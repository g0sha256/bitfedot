"""Live status of the node (one snapshot dict consumed by the UI and tray)
and the user-facing actions."""
import collections
import re
import shutil
import time
from pathlib import Path

from . import eta, installer, paths, rpc, services, settings, system
from .paths import U_BITCOIND, U_FULCRUM, U_MEMPOOL, U_TOR

_fresh = collections.deque(maxlen=60)   # this process's own (time, progress) samples


def _sync_eta(s, progress):
    """Remaining seconds of the initial sync; see eta.py for the model."""
    now = time.time()
    if not _fresh or now - _fresh[-1][0] >= 20:
        _fresh.append((now, progress))
    return eta.estimate(progress, system.dbcache_ibd() if services.in_ibd(s) else system.dbcache_ready(),
                        system.is_rotational(s["data_dir"]), extra_samples=tuple(_fresh))


def _bitcoin(s, state):
    b = {"state": "stopped", "message": "Stopped", "version": s["versions"].get("bitcoin", "")}
    if state in ("inactive", "failed", "deactivating"):
        b["state"] = {"failed": "error", "deactivating": "stopping"}.get(state, "stopped")
        b["message"] = {"failed": "Failed — see Logs", "deactivating": "Shutting down, flushing to disk…"
                        }.get(state, "Stopped")
        return b
    client = rpc.BitcoinRPC(Path(s["data_dir"]) / "bitcoin")
    try:
        chain = client.call("getblockchaininfo")
        netinfo = client.call("getnetworkinfo")
        header = client.call("getblockheader", chain["bestblockhash"])
        indexes = client.call("getindexinfo")
    except rpc.RPCError as e:
        b.update(state="starting", message=str(e) if e.code == -28 else f"RPC: {e}")
        return b
    except (OSError, ValueError, KeyError):
        b.update(state="starting", message="Starting…")
        return b
    ibd = chain["initialblockdownload"] or chain["blocks"] < chain["headers"] - 1
    b.update(
        state="syncing" if ibd else "synced",
        message="Syncing" if ibd else "Synced",
        blocks=chain["blocks"], headers=chain["headers"],
        progress=1.0 if not ibd else min(chain["verificationprogress"], 0.9999),
        ibd=chain["initialblockdownload"],
        best_hash=chain["bestblockhash"], best_time=header["time"], best_txs=header.get("nTx"),
        size_on_disk=chain.get("size_on_disk", 0),
        peers_in=netinfo.get("connections_in", 0), peers_out=netinfo.get("connections_out", 0),
        subversion=netinfo.get("subversion", ""),
        networks={n["name"]: n["reachable"] for n in netinfo.get("networks", [])},
        onion=next((f"{a['address']}:{a['port']}" for a in netinfo.get("localaddresses", [])
                    if a["address"].endswith(".onion")), ""),
        txindex=indexes.get("txindex"),
    )
    b["eta"] = None
    if ibd:
        b["eta"] = _sync_eta(s, chain["verificationprogress"])
        try:        # how many transactions that is: the honest measure of work done
            done = client.call("getchaintxstats")["txcount"]
            b["txs_done"] = done
            b["txs_total"] = int(done / chain["verificationprogress"]) if chain["verificationprogress"] > 0 else None
        except (rpc.RPCError, OSError, ValueError, KeyError):
            pass
    return b


def _tor(s, state):
    t = {"state": "stopped", "message": "Stopped" if s["all_stopped"] else "Down", "bootstrap": 0,
         "version": s["versions"].get("tor", ""), "route": s["tor_route"], "vpn_iface": s["vpn_iface"]}
    if s["tor_route"] == "vpn":
        v4, v6 = system.vpn_addresses(s["vpn_iface"])
        src = v4 or v6
        t["vpn_up"] = bool(src)
        # Does the kernel really send traffic from the VPN address out of the VPN?
        t["vpn_routed"] = bool(src) and system.route_device(
            src, "1.1.1.1" if v4 else "2606:4700:4700::1111") == s["vpn_iface"]
        if s["tor_enabled"] and not src and s["phase"] == "ready" and not s["all_stopped"]:
            t["message"] = f"Waiting for VPN ({s['vpn_iface']})"
            t["state"] = "blocked"
            return t
    if state == "failed":
        t.update(state="error", message="Failed — see Logs")
        return t
    if state not in ("active", "activating"):
        if services.in_ibd(s) and s["ibd_clearnet"]:
            t["message"] = "Starts when sync completes"
        return t
    try:
        info = rpc.TorControl().getinfo("status/bootstrap-phase", "traffic/read", "traffic/written")
    except OSError:
        t.update(state="starting", message="Starting…")
        return t
    phase = info.get("status/bootstrap-phase", "")
    pct = int(phase.split("PROGRESS=")[1].split()[0]) if "PROGRESS=" in phase else 0
    summary = phase.split('SUMMARY="')[1].rstrip('"') if 'SUMMARY="' in phase else ""
    t.update(bootstrap=pct, read=int(info.get("traffic/read", 0)), written=int(info.get("traffic/written", 0)),
             state="running" if pct >= 100 else "starting",
             message="Connected" if pct >= 100 else f"Bootstrapping {pct}% — {summary}")
    return t


def fulcrum_progress(log_line: str):
    """Fulcrum reports its initial indexing as '… Processed height: 412000, 43.2%, …'.
    -> (height, fraction) or None. Fulcrum rounds to one decimal, so its last lines read
    '100.0%' while it is still working: the fraction stays below 1 until it serves."""
    m = re.search(r"Processed height:\s*(\d+),\s*(\d+(?:\.\d+)?)%", log_line or "", re.ASCII)
    return (int(m.group(1)), min(float(m.group(2)) / 100, 0.999)) if m else None


def _fulcrum(s, state, bitcoin):
    f = {"state": "stopped", "message": "Stopped", "version": s["versions"].get("fulcrum", ""),
         "onion": services.onion_hostname("fulcrum") if s["onion_fulcrum"] else ""}
    if s["phase"] != "ready":
        f["message"] = "Starts after initial sync"
        return f
    if state == "failed":
        f.update(state="error", message="Failed — see Logs")
    elif state in ("active", "activating"):
        h = rpc.electrum_height()
        if h is not None:
            f.update(state="running", height=h, message=f"Serving wallets · height {h:,}")
        else:
            last = system.journal_last(U_FULCRUM)
            prog = fulcrum_progress(last)
            if prog:
                tip = bitcoin.get("blocks")
                f.update(state="syncing", progress=prog[1], pill=f"Indexing {int(prog[1] * 100)}%",
                         message=f"Building the wallet index: {prog[1] * 100:.1f}% · block {prog[0]:,}"
                                 + (f" of {tip:,}" if tip else ""))
            else:
                txi = bitcoin.get("txindex") or {}
                if bitcoin.get("state") == "synced" and txi and not txi.get("synced", True):
                    msg = "Waiting for Bitcoin Core to finish its transaction index"
                else:
                    last = last.split("> ", 1)[-1] if "> " in last else last
                    msg = last[:90] or "Starting the index…"
                f.update(state="syncing", pill="Indexing", message=msg)
    return f


def _mempool(s, state, bitcoin=None, fulcrum=None):
    m = {"state": "stopped", "message": "Stopped", "version": s["versions"].get("mempool", ""),
         "onion": services.onion_hostname("mempool") if s["onion_mempool"] else ""}
    if s["phase"] != "ready":
        m["message"] = "Starts after initial sync"
    elif state == "failed":
        m.update(state="error", message="Failed — see Logs")
    elif state in ("active", "activating"):
        tip = (rpc.http_text(paths.MEMPOOL_PORT, "/api/blocks/tip/height") or "").strip()
        node_tip = (bitcoin or {}).get("blocks")
        if tip.isascii() and tip.isdigit():
            height = int(tip)
            if node_tip and height < node_tip - 1:
                m.update(state="syncing", pill="Catching up", height=height,
                         message=f"Explorer catching up: block {height:,} of {node_tip:,}")
            elif (fulcrum or {}).get("state") != "running":
                # Mempool follows Bitcoin Core by itself; only its address lookups go through
                # Fulcrum. So it is up long before it is complete — say which part is missing.
                m.update(state="running", pill="Partly ready", height=height,
                         message=f"Blocks and transactions ready · block {height:,} — "
                                 "address lookups wait for Fulcrum")
            else:
                m.update(state="running", height=height, message=f"Explorer ready · block {height:,}")
        elif rpc.http_ok(paths.MEMPOOL_PORT, "/api/v1/backend-info"):
            m.update(state="starting", pill="Loading", message="Explorer is loading blocks and the mempool…")
        else:
            m.update(state="starting", message="Starting…")
    return m


def _restarting(service: dict, unit: dict) -> dict:
    """Add what systemd knows about crashes: how often it restarted the unit by itself and,
    while the unit waits for the next attempt, that this is no ordinary start (systemd
    reports a unit in auto-restart as 'activating', never as 'failed')."""
    service["restarts"] = unit.get("restarts", 0)
    if unit.get("sub") == "auto-restart":
        service.update(state="starting", pill="Restarting",
                       message="Stopped unexpectedly — restarting. See Logs.")
    return service


def explorer_available(snap) -> bool:
    """Can the explorer be opened? It also answers while it is still catching up."""
    m = snap.get("mempool") or {}
    return m.get("state") == "running" or (m.get("state") == "syncing" and "height" in m)


def snapshot() -> dict:
    s = settings.load()
    # A node whose move from the pre-release name is not finished (migrate.py) is not an
    # installed one yet: it has no units, and the wizard is where the move is completed.
    installed = bool(s["installed"]) and not s["adopting"]
    snap = {"t": time.time(), "settings": s, "installed": installed, "phase": s["phase"]}
    if not installed:
        return snap
    info = system.unit_info([U_BITCOIND, U_TOR, U_FULCRUM, U_MEMPOOL])
    units = {unit: i["state"] for unit, i in info.items()}
    snap["units"] = units
    unfinished = paths.APPLY_PENDING.exists()       # looked at first: see services.unfinished()
    snap["activity"] = services.activity()
    snap["pending"] = services.UNFINISHED_NOTE if unfinished and not snap["activity"] else ""
    snap["bitcoin"] = _restarting(_bitcoin(s, units[U_BITCOIND]), info[U_BITCOIND])
    snap["tor"] = _restarting(_tor(s, units[U_TOR]), info[U_TOR])
    snap["fulcrum"] = _restarting(_fulcrum(s, units[U_FULCRUM], snap["bitcoin"]), info[U_FULCRUM])
    snap["mempool"] = _restarting(_mempool(s, units[U_MEMPOOL], snap["bitcoin"], snap["fulcrum"]),
                                  info[U_MEMPOOL])
    try:
        snap["disk_free_gb"] = shutil.disk_usage(s["data_dir"]).free / 1e9
    except OSError:
        snap["disk_free_gb"] = None
    snap["updates"] = installer.pending_updates(s)
    snap["awake"] = bool(s["keep_awake"]) and system.held_awake()
    return snap


def demo_snapshot(synced=False) -> dict:
    """Canned data so the interface can be previewed without a node (--demo)."""
    s = dict(settings.DEFAULTS, installed=True, phase="ready" if synced else "ibd",
             versions={"bitcoin": "32.1", "fulcrum": "2.1.4", "mempool": "3.3.2", "tor": "0.4.9.15"},
             onion_fulcrum=synced)
    tip = 975_312
    blocks = tip if synced else 612_480
    h = "00000000000000000001a7c3f09d1e9b5a4f2c6d8e0b7a3915c4e2f6d8b0a1c3"
    return {
        "t": time.time(), "settings": s, "installed": True, "phase": s["phase"], "demo": True,
        "bitcoin": {"state": "synced" if synced else "syncing", "message": "Synced" if synced else "Syncing",
                    "version": "32.1", "blocks": blocks, "headers": tip,
                    "progress": 1.0 if synced else 0.4721, "best_hash": h,
                    "best_time": time.time() - (410 if synced else 6.1 * 365 * 86400), "best_txs": 3811,
                    "size_on_disk": 742e9 if synced else 301e9, "peers_in": 14 if synced else 0,
                    "peers_out": 10, "eta": None if synced else 11 * 3600 + 1400,
                    "txs_done": 698_000_000, "txs_total": 1_481_000_000,
                    "networks": {"ipv4": True, "ipv6": True, "onion": synced},
                    "onion": "bitfedotexampleonionaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion:8333" if synced else "",
                    "txindex": {"synced": True}},
        "tor": {"state": "running" if synced else "stopped", "bootstrap": 100 if synced else 0,
                "message": "Connected" if synced else "Starts when sync completes", "version": "0.4.9.15", "route": "direct",
                "vpn_iface": "", "read": 48_300_000, "written": 12_900_000},
        "fulcrum": {"state": "running" if synced else "stopped", "version": "2.1.4", "height": tip,
                    "message": f"Serving wallets · height {tip:,}" if synced else "Starts after initial sync",
                    "onion": "fulcrumexampleonionaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion" if synced else ""},
        "mempool": {"state": "running" if synced else "stopped", "version": "3.3.2", "onion": "",
                    **({"height": tip} if synced else {}),
                    "message": f"Explorer ready · block {tip:,}" if synced else "Starts after initial sync"},
        "units": {}, "activity": "", "disk_free_gb": 1890.0, "updates": {"fulcrum": "2.1.5"} if synced else {},
        "awake": True,
    }


# ------------------------------------------------------------------- sleep --
AWAKE_INFO = ("A sleeping computer does not sync. While services run, BitFedot keeps this one from going "
              "to sleep, by itself or on request. The screen still switches off and locks, and closing a "
              "laptop's lid still puts it to sleep.")


def awake_status(snap) -> str:
    """Subtitle of the keep-awake switch: what it does, and whether it is in effect now."""
    s = snap["settings"]
    if not snap.get("installed") or not s["keep_awake"]:
        return AWAKE_INFO
    if s["all_stopped"]:
        return AWAKE_INFO + " Not needed right now: everything is stopped."
    if snap.get("awake"):
        return AWAKE_INFO + " In effect now."
    return (AWAKE_INFO + " Not in effect right now: it is set up within two minutes of logging in, and "
            "cannot be while nobody is logged in — the switch below covers that.")


# ----------------------------------------------------------------- summary --
NAMES = (("bitcoin", "Bitcoin Core"), ("tor", "Tor"), ("fulcrum", "Fulcrum"), ("mempool", "Mempool"))
READY = {"tor": "connected", "fulcrum": "serving wallets", "mempool": "explorer ready"}
CRASH_NOTICE_EVERY = 3600       # seconds: a service that keeps crashing is announced once an hour at most


def sync_percent(progress: float) -> str:
    """Progress of a sync that is not finished: never shown as 100 %."""
    return f"{min(progress * 100, 99.9):.1f}%"


def summary(snap) -> list:
    """One short status line per service, for the tray menu."""
    if not snap.get("installed"):
        return ["Not installed"]
    b = snap["bitcoin"]
    if "blocks" in b:
        first = (f"Bitcoin Core: synced · block {b['blocks']:,}" if b["state"] == "synced" else
                 f"Bitcoin Core: syncing {sync_percent(b['progress'])} · block {b['blocks']:,}")
    else:
        first = f"Bitcoin Core: {b['message']}"
    lines = [first]
    for key, name in NAMES[1:]:
        info = snap[key]
        # Mempool answers before Fulcrum does; until then its own message says what is missing.
        complete = info["state"] == "running" and not (key == "mempool" and snap["fulcrum"]["state"] != "running")
        text = READY[key] if complete else info["message"]
        lines.append(f"{name}: {text[:1].lower() + text[1:] if text else info['state']}")
    return lines


def status_events(snap, seen: dict):
    """Things worth a desktop notification since the last look.
    `seen` is what was already announced; -> ([(title, body)], new_seen).
    Pure: the agent keeps `seen` in the settings file so nothing is announced twice."""
    events, seen = [], dict(seen or {})
    if not snap.get("installed") or snap["settings"].get("all_stopped"):
        return events, seen
    b, f, m = snap["bitcoin"], snap["fulcrum"], snap["mempool"]

    # Sync milestones belong to the initial sync only: a synced node that is a few blocks
    # behind after a restart is "syncing" at 99.99 % too, and that is not news.
    if snap.get("phase") == "ibd":
        for key in ("fulcrum_index", "fulcrum_ready", "mempool_ready"):
            seen.pop(key, None)                                   # they start over after this sync
        if b["state"] == "syncing" and "progress" in b:
            step = int(b["progress"] * 10) * 10                   # 10, 20, … 90
            if step + 10 < seen.get("sync", 0):
                seen["sync"] = step                               # a new sync from far below: start over
            elif step >= 10 and step > seen.get("sync", 0):
                seen["sync"] = step
                eta_s = b.get("eta")
                left = f" · about {eta_s / 3600:.0f} h left" if eta_s and eta_s > 5400 else ""
                events.append((f"Blockchain sync {step}%", f"Block {b['blocks']:,} of {b['headers']:,}{left}"))

    if f["state"] == "syncing" and f.get("progress") is not None:
        step = min(int(f["progress"] * 4) * 25, 75)                # 25, 50, 75
        if f["progress"] < 0.9 and seen.get("fulcrum_ready"):
            seen.pop("fulcrum_ready")                              # the index is being built again
            seen.pop("mempool_ready", None)
        if step + 25 < seen.get("fulcrum_index", 0):
            seen["fulcrum_index"] = step
        elif step >= 25 and step > seen.get("fulcrum_index", 0):
            seen["fulcrum_index"] = step
            events.append((f"Fulcrum index {step}%", "Wallets can connect when it reaches 100%."))
    if f["state"] == "running" and not seen.get("fulcrum_ready"):
        seen["fulcrum_ready"] = True
        events.append(("Fulcrum is ready", f"Your wallets can connect to 127.0.0.1:{paths.FULCRUM_PORT}."))
    # The explorer is complete only once Fulcrum serves its address lookups.
    if m["state"] == "running" and f["state"] == "running" and not seen.get("mempool_ready"):
        seen["mempool_ready"] = True
        events.append(("Mempool explorer is ready", "Open the Explorer page in BitFedot."))

    # "Stopped unexpectedly" has two faces. A unit systemd gave up on rests in 'failed'
    # (state "error"). One that crashes and is restarted — the usual case with
    # Restart=on-failure — never does: its restart counter is what tells. The counter
    # outlives a deliberate stop (systemd clears it at the next start), so it only counts
    # for a service that is meant to be running now.
    failed = sorted(name for key, name in NAMES if snap[key]["state"] == "error")
    stopped = [name for name in failed if name not in (seen.get("failed") or [])]
    crashes, now = dict(seen.get("crashes") or {}), snap.get("t") or 0
    for key, name in NAMES:
        count = snap[key].get("restarts") or 0
        last_count, last_notice = crashes.get(name, (0, 0))
        wanted = snap[key]["state"] not in ("stopped", "blocked")
        if (count > last_count and wanted and name not in stopped
                and now - last_notice >= CRASH_NOTICE_EVERY):
            stopped.append(name)
        if name in stopped:
            last_notice = now
        if count or last_notice:
            crashes[name] = [count, last_notice]
        else:
            crashes.pop(name, None)
    if stopped:
        events.append(("A service stopped unexpectedly", ", ".join(sorted(stopped)) + " — see Logs in BitFedot."))
    seen["failed"] = failed
    if crashes or "crashes" in seen:
        seen["crashes"] = crashes
    return events, seen


# ----------------------------------------------------------------- actions --
def apply_settings(report=None, **changes):
    """Persist `changes` and converge services onto what is stored: whatever needs a
    restart is stopped safely and started again, in dependency order.

    apply() reads the settings itself once it holds the lock, so of several changes
    saved close together none is lost to an older one that happens to be applied later.
    Without `changes` this finishes a change that was cut short (services.unfinished())."""
    if changes:
        settings.update(**changes)
    return services.apply(report=report)


def stop_all(report=None):
    """Stop every service in a safe order and keep them stopped (also after a reboot)."""
    return apply_settings(report, all_stopped=True)


def start_all(report=None):
    return apply_settings(report, all_stopped=False, resume_on_launch=False)


def shut_down(report=None):
    """Quit-time shutdown: stop everything safely now, start again with the app."""
    return apply_settings(report, all_stopped=True, resume_on_launch=True)


def safe_reboot(report=None):
    """Shut every service down cleanly, then restart the computer. Services
    return by themselves after boot — and right away if the computer does not
    restart after all."""
    services.stop_everything(report)
    try:
        system.run(["systemctl", "reboot"], timeout=60, check=True)
    except RuntimeError:
        services.apply(report=report)
        raise


def on_launch(report=None) -> bool:
    """What opening the app owes the node: start it again after "Shut down the node",
    or finish a change that was cut short (the app was closed or the computer switched
    off in the middle of it). -> whether there was anything to do."""
    s = settings.load()
    if s["resume_on_launch"]:
        start_all(report)
    elif s["installed"] and not s["adopting"] and services.unfinished():
        services.apply(report=report)
    else:
        return False
    return True


def tor_set(up: bool):
    apply_settings(tor_enabled=up)


def tor_reconnect():
    services.restart_unit(U_TOR, wait=True)


def tor_new_identity():
    rpc.TorControl().signal("NEWNYM")


def restart(unit):
    services.restart_unit(unit)


def finalize_sync():
    """Initial block download is complete: switch Bitcoin Core from the sync
    profile to the full-service profile and bring up Tor, Fulcrum and Mempool."""
    s = settings.update(phase="ready")
    services.apply()
    return s
