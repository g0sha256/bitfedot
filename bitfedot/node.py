"""Live status of the node (one snapshot dict consumed by the UI and tray)
and the user-facing actions."""
import collections
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
            last = last.split("> ", 1)[-1] if "> " in last else last
            f.update(state="syncing", message=(last[:90] or "Indexing…"))
    return f


def _mempool(s, state):
    m = {"state": "stopped", "message": "Stopped", "version": s["versions"].get("mempool", ""),
         "onion": services.onion_hostname("mempool") if s["onion_mempool"] else ""}
    if s["phase"] != "ready":
        m["message"] = "Starts after initial sync"
    elif state == "failed":
        m.update(state="error", message="Failed — see Logs")
    elif state in ("active", "activating"):
        if rpc.http_ok(paths.MEMPOOL_PORT, "/api/v1/backend-info"):
            m.update(state="running", message=f"http://127.0.0.1:{paths.MEMPOOL_PORT}")
        else:
            m.update(state="starting", message="Starting (waits for Fulcrum)…")
    return m


def snapshot() -> dict:
    s = settings.load()
    snap = {"t": time.time(), "settings": s, "installed": s["installed"], "phase": s["phase"]}
    if not s["installed"]:
        return snap
    units = system.unit_states([U_BITCOIND, U_TOR, U_FULCRUM, U_MEMPOOL])
    snap["units"] = units
    snap["activity"] = services.activity()
    snap["bitcoin"] = _bitcoin(s, units[U_BITCOIND])
    snap["tor"] = _tor(s, units[U_TOR])
    snap["fulcrum"] = _fulcrum(s, units[U_FULCRUM], snap["bitcoin"])
    snap["mempool"] = _mempool(s, units[U_MEMPOOL])
    try:
        snap["disk_free_gb"] = shutil.disk_usage(s["data_dir"]).free / 1e9
    except OSError:
        snap["disk_free_gb"] = None
    snap["updates"] = installer.pending_updates(s)
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
                    "message": f"http://127.0.0.1:{paths.MEMPOOL_PORT}" if synced else "Starts after initial sync"},
        "units": {}, "activity": "", "disk_free_gb": 1890.0, "updates": {"fulcrum": "2.1.5"} if synced else {},
    }


# ----------------------------------------------------------------- actions --
def apply_settings(report=None, **changes):
    """Persist `changes` and converge services onto them: whatever needs a
    restart is stopped safely and started again, in dependency order."""
    return services.apply(settings.update(**changes), report=report)


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
    return by themselves after boot."""
    services.stop_everything(report)
    system.run(["systemctl", "reboot"], timeout=60, check=True)


def tor_set(up: bool):
    apply_settings(tor_enabled=up)


def tor_reconnect():
    system.systemctl("restart", U_TOR, check=True)


def tor_new_identity():
    rpc.TorControl().signal("NEWNYM")


def restart(unit):
    system.systemctl("--no-block", "restart", unit, check=True)


def finalize_sync():
    """Initial block download is complete: switch Bitcoin Core from the sync
    profile to the full-service profile and bring up Tor, Fulcrum and Mempool."""
    s = settings.update(phase="ready")
    services.apply(s)
    return s
