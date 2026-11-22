"""Headless companion (systemd user service). Keeps the node moving when the
window is closed:

  * announces progress as desktop notifications: sync milestones, Fulcrum's
    index, the explorer becoming ready, a service that stopped;
  * records sync progress once a minute, so the remaining-time estimate is
    meaningful the moment the window opens;
  * when the initial sync finishes, switches to the full-service profile and
    launches Tor, Fulcrum and Mempool;
  * finishes a change to the services that was cut short — the app was closed or
    the computer switched off in the middle of it, or a service would not stop;
  * keeps the computer from going to sleep while the node is meant to run (a
    sleeping computer does not sync);
  * in "Tor via VPN" mode, follows the VPN interface: Tor is stopped while the
    VPN is down and re-bound when its address changes;
  * checks for updates (node software and Fedora itself) once a day and sends
    a desktop notification.
"""
import time
from pathlib import Path

from . import (__version__, eta, hardening, installer, net, node, rpc, selfupdate, services,
               settings, system)

TICK = 20
DAY = 86400
AWAKE_WHY = "The Bitcoin node is running"
AWAKE_RETRY = 120       # seconds between attempts while the lock is refused (nobody logged in)
FINISH_RETRY = 300      # seconds between attempts to finish a change that keeps failing


def sync_complete(s) -> bool:
    try:
        info = rpc.BitcoinRPC(Path(s["data_dir"]) / "bitcoin").call("getblockchaininfo")
    except (rpc.RPCError, OSError, ValueError):
        return False
    if info["initialblockdownload"]:
        eta.record_sample(info["verificationprogress"])    # history for the time estimate
    return (not info["initialblockdownload"]) and info["blocks"] >= info["headers"] - 1 \
        and info["headers"] > 0


def announce(s):
    """Desktop notifications for what changed since the last look (node.status_events).

    An event counts as announced only once the desktop has taken it: while nobody is
    logged in there is no notification service, and the next tick simply tries again.
    The very first look — a new install, or the first run of a version that has this —
    only takes stock: what was already true then is not news."""
    events, seen = node.status_events(node.snapshot(), s["notified"])
    if not s["notified"]:
        events = []
    if all(system.notify(title, body) for title, body in events) and seen != s["notified"]:
        settings.update(notified=seen)


def keep_awake(s, state):
    """Hold a lock against sleep while the node is meant to run (system.hold_awake).

    The lock lives exactly as long as a helper process of this agent, so it cannot
    outlast the agent; it is given up when everything is stopped or the setting is
    switched off. logind refuses it while the user is not logged in — then this
    simply tries again every AWAKE_RETRY seconds."""
    helper = state.get("awake")
    if helper is not None and helper.poll() is not None:        # refused, or ended by someone
        state["awake"] = helper = None
        if state.get("awake_ok", True):
            print("agent: sleep is not blocked (the lock was refused or released); trying again", flush=True)
        state["awake_ok"] = False
    elif helper is not None and not state.get("awake_ok"):
        print("agent: the computer is kept awake while the node runs", flush=True)
        state["awake_ok"] = True
    wanted = bool(s["installed"] and not s["all_stopped"] and s["keep_awake"])
    if not wanted:
        if helper is not None:
            system.release_awake(helper)
            print("agent: sleep is no longer blocked", flush=True)
        for key in ("awake", "awake_ok", "awake_next"):
            state.pop(key, None)
    elif helper is None and time.monotonic() >= state.get("awake_next", 0):
        state["awake"] = system.hold_awake(AWAKE_WHY)
        state["awake_next"] = time.monotonic() + AWAKE_RETRY


def finish_unfinished(state, announce_failure=True):
    """Carry out a change to the services that began and did not complete
    (services.unfinished()): apply() goes on from where things stand. While it keeps
    failing it is tried again every FINISH_RETRY seconds, and each new reason is
    announced once."""
    if not services.unfinished():
        state.pop("finish_next", None)
        state.pop("finish_error", None)
        return
    if time.monotonic() < state.get("finish_next", 0):
        return
    state["finish_next"] = time.monotonic() + FINISH_RETRY
    print("agent: finishing a change that was not completed", flush=True)
    try:
        services.apply()
    except Exception as e:          # it stays unfinished; the rest of the tick must still happen
        print(f"agent: not finished: {type(e).__name__}: {e}", flush=True)
        if str(e) != state.get("finish_error"):
            state["finish_error"] = str(e)
            if announce_failure:
                system.notify("A change to your node is not complete", str(e)[:300])
    else:
        print("agent: the change is complete", flush=True)
        state.pop("finish_next", None)
        state.pop("finish_error", None)


def tick(state: dict):
    s = settings.load()
    try:
        keep_awake(s, state)
    except OSError as e:            # must never cost the rest of the tick
        print(f"agent: keep awake: {e}", flush=True)
    if not s["installed"]:
        return
    finish_unfinished(state, s["status_notifications"])     # also when everything is meant to be stopped
    if s["all_stopped"]:
        return
    if s["phase"] == "ibd" and s["bitcoind_enabled"] and sync_complete(s):
        node.finalize_sync()
        if s["status_notifications"]:
            system.notify("Blockchain synced",
                          "Your node is fully validated. Starting Tor, Fulcrum and Mempool.")
        return

    # Follow the VPN: any change in its addresses changes torrc / whether Tor may run.
    # First, and before anything that can be slow or fail: it is the one duty here that
    # must not wait.
    if s["tor_route"] == "vpn" and s["tor_enabled"]:
        addrs = system.vpn_addresses(s["vpn_iface"])
        if state.get("vpn") != addrs:
            if "vpn" in state:
                system.notify("Tor routing",
                              f"VPN {s['vpn_iface']} is back — Tor reconnecting through it." if any(addrs)
                              else f"VPN {s['vpn_iface']} is down — Tor stopped (no clearnet fallback).")
            state["vpn"] = addrs
            services.apply()

    if s["status_notifications"]:
        try:
            announce(s)
        except Exception as e:      # a nicety: it must never cost the update check below
            print(f"agent: status: {type(e).__name__}: {e}", flush=True)

    if s["auto_check_updates"] and time.time() - s["last_update_check"] > DAY:
        installer.check_updates()
        try:
            os_info = hardening.check_os_updates()
            if os_info["security"] and os_info["security"] != state.get("os_security"):
                state["os_security"] = os_info["security"]
                system.notify("Fedora security updates",
                              f"{os_info['security']} security update(s) are waiting to be installed.")
        except RuntimeError:
            pass
        fresh = settings.load()
        pending = installer.pending_updates(fresh)
        own = fresh["available"].get("bitfedot", "")
        if net.is_newer(own, __version__):
            pending = {**pending, "bitfedot": own}
            if fresh["auto_self_update"] and selfupdate.status(fresh)["can_install"]:
                try:                      # same checks as the Update button: signature, tests, no downgrade
                    done = selfupdate.update()
                    system.notify("BitFedot updated", f"Version {done['version']} was verified and installed. "
                                                      "Restart BitFedot to use it.")
                    pending.pop("bitfedot")
                except Exception as e:
                    print(f"agent: self-update refused: {e}", flush=True)
        if pending and pending != state.get("notified"):
            state["notified"] = pending
            system.notify("Updates available", ", ".join(
                f"{installer.TITLES[n]} {v}" for n, v in pending.items()))


def main():
    state = {}
    while True:
        try:
            tick(state)
        except Exception as e:      # the agent must survive transient failures
            print(f"agent: {type(e).__name__}: {e}", flush=True)
        time.sleep(TICK)


if __name__ == "__main__":
    main()
