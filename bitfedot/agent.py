"""Headless companion (systemd user service). Keeps the node moving when the
window is closed:

  * records sync progress once a minute, so the remaining-time estimate is
    meaningful the moment the window opens;
  * when the initial sync finishes, switches to the full-service profile and
    launches Tor, Fulcrum and Mempool;
  * in "Tor via VPN" mode, follows the VPN interface: Tor is stopped while the
    VPN is down and re-bound when its address changes;
  * checks for updates (node software and Fedora itself) once a day and sends
    a desktop notification.
"""
import time
from pathlib import Path

from . import __version__, eta, hardening, installer, net, node, rpc, services, settings, system

TICK = 20
DAY = 86400


def sync_complete(s) -> bool:
    try:
        info = rpc.BitcoinRPC(Path(s["data_dir"]) / "bitcoin").call("getblockchaininfo")
    except (rpc.RPCError, OSError, ValueError):
        return False
    if info["initialblockdownload"]:
        eta.record_sample(info["verificationprogress"])    # history for the time estimate
    return (not info["initialblockdownload"]) and info["blocks"] >= info["headers"] - 1 \
        and info["headers"] > 0


def tick(state: dict):
    s = settings.load()
    if not s["installed"]:
        return
    if s["all_stopped"]:
        return
    if s["phase"] == "ibd" and s["bitcoind_enabled"] and sync_complete(s):
        node.finalize_sync()
        system.notify("Blockchain synced",
                      "Your node is fully validated. Starting Tor, Fulcrum and Mempool.")
        return

    # Follow the VPN: any change in its addresses changes torrc / whether Tor may run.
    if s["tor_route"] == "vpn" and s["tor_enabled"]:
        addrs = system.vpn_addresses(s["vpn_iface"])
        if state.get("vpn") != addrs:
            if "vpn" in state:
                system.notify("Tor routing",
                              f"VPN {s['vpn_iface']} is back — Tor reconnecting through it." if any(addrs)
                              else f"VPN {s['vpn_iface']} is down — Tor stopped (no clearnet fallback).")
            state["vpn"] = addrs
            services.apply(s)

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
