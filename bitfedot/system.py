"""Thin wrappers around the host: subprocesses, systemd --user, hardware, VPNs."""
import json
import os
import platform
import re
import shutil
import signal
import subprocess

from . import paths

DRY_RUN = bool(os.environ.get("BITFEDOT_ROOT"))  # tests never touch systemd


def run(cmd, timeout=60, check=False, env=None, input=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env, input=input)
    except FileNotFoundError:
        p = subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        p = subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]}: timed out")
    if check and p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip() or f"{cmd[0]} failed ({p.returncode})")
    return p


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


# ---------------------------------------------------------------- systemd --
def systemctl(*args, check=False, timeout=120):
    if DRY_RUN:
        return subprocess.CompletedProcess(args, 0, "", "")
    return run(["systemctl", "--user", *args], timeout=timeout, check=check)


def unit_states(units) -> dict:
    """unit -> 'active' | 'activating' | 'deactivating' | 'failed' | 'inactive'"""
    units = list(units)
    if DRY_RUN:
        return {u: "inactive" for u in units}
    out = run(["systemctl", "--user", "is-active", *units], timeout=15).stdout.split("\n")
    return {u: (out[i].strip() if i < len(out) and out[i].strip() else "inactive")
            for i, u in enumerate(units)}


def _parse_units(text: str, units) -> dict:
    """Output of `systemctl show -p Id -p ActiveState -p SubState -p NRestarts u1 u2 …`
    (one block per unit, separated by an empty line) -> what unit_info() returns."""
    blocks = [dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
              for block in text.strip().split("\n\n") if block.strip()]
    by_id = {b.get("Id"): b for b in blocks}
    info = {}
    for i, unit in enumerate(units):
        b = by_id.get(unit) or (blocks[i] if len(blocks) == len(units) else {})
        restarts = b.get("NRestarts", "")
        info[unit] = {"state": b.get("ActiveState") or "inactive", "sub": b.get("SubState", ""),
                      "restarts": int(restarts) if restarts.isascii() and restarts.isdigit() else 0}
    return info


def unit_info(units) -> dict:
    """unit -> {'state': as in unit_states(), 'sub': systemd's finer state, 'restarts': how
    often systemd restarted it by itself since it was last started — i.e. how often it
    crashed}. A unit that crashed and waits for its automatic restart is 'activating' with
    sub-state 'auto-restart': with Restart=on-failure it never rests in 'failed'."""
    units = list(units)
    if DRY_RUN:
        return {u: {"state": "inactive", "sub": "dead", "restarts": 0} for u in units}
    out = run(["systemctl", "--user", "show", "-p", "Id", "-p", "ActiveState", "-p", "SubState",
               "-p", "NRestarts", *units], timeout=15).stdout
    return _parse_units(out, units)


def journal(unit: str, lines=200) -> str:
    return run(["journalctl", "--user", "-u", unit, "-n", str(lines), "-o", "short-iso",
                "--no-pager", "--no-hostname"], timeout=15).stdout


def journal_last(unit: str) -> str:
    out = run(["journalctl", "--user", "-u", unit, "-n", "1", "-o", "cat", "--no-pager"],
              timeout=10).stdout.strip()
    return out.splitlines()[-1] if out else ""


def linger_enabled() -> bool:
    out = run(["loginctl", "show-user", os.environ.get("USER", ""), "-p", "Linger"]).stdout
    return "yes" in out


def set_linger(on: bool):
    if DRY_RUN:
        return
    run(["loginctl", "enable-linger" if on else "disable-linger"], check=True)


# ------------------------------------------------------------------- sleep --
def hold_awake(why: str):
    """Start a helper that keeps the computer from going to sleep for as long as it
    runs: a systemd "sleep" block lock, listed by `systemd-inhibit --list`. It stops
    automatic suspend and a suspend on request alike; it does not touch the screen
    (blanking, locking) and a laptop lid still puts the computer to sleep.
    -> the helper process, or None where there is nothing to start.

    logind grants the lock to a logged-in user only. Refused, the helper ends at
    once — `poll()` on the result tells. It never asks for a password."""
    if DRY_RUN or not have("systemd-inhibit"):
        return None
    return subprocess.Popen(
        ["systemd-inhibit", "--what=sleep", f"--who={paths.APP_NAME}", f"--why={why}", "--mode=block",
         "--no-ask-password", "sleep", "infinity"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)           # its own process group: released as one


def release_awake(helper):
    """End a helper started by hold_awake(), and with it the lock."""
    if helper is None or helper.poll() is not None:
        return
    try:
        os.killpg(helper.pid, signal.SIGTERM)
    except OSError:
        helper.terminate()
    try:
        helper.wait(5)
    except subprocess.TimeoutExpired:
        helper.kill()


def _sleep_blockers(listing: str) -> list:
    """Output of `systemd-inhibit --list --json=short` -> who holds a lock that blocks sleep."""
    try:
        entries = json.loads(listing or "[]")
    except ValueError:
        return []
    return [str(e.get("who", "")) for e in entries if isinstance(e, dict)
            and e.get("mode") == "block" and "sleep" in str(e.get("what", "")).split(":")]


def held_awake() -> bool:
    """Is BitFedot's sleep lock in place right now?"""
    if DRY_RUN:
        return False
    return paths.APP_NAME in _sleep_blockers(run(["systemd-inhibit", "--list", "--json=short"], timeout=10).stdout)


# ---------------------------------------------------------------- hardware --
def ram_mb() -> int:
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)


def cpu_count() -> int:
    return os.cpu_count() or 1


def arch() -> str:
    return platform.machine()


def existing_parent(path) -> str:
    p = os.path.abspath(os.path.expanduser(str(path)))
    while not os.path.exists(p):
        p = os.path.dirname(p)
    return p


def disk_free_gb(path) -> float:
    return shutil.disk_usage(existing_parent(path)).free / 1e9


def is_rotational(path) -> bool:
    """True if `path` sits on a spinning disk (sync will be much slower)."""
    try:
        dev = os.stat(existing_parent(path)).st_dev
        base = f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}"
        for cand in (base, os.path.join(base, "..")):
            f = os.path.join(cand, "queue/rotational")
            if os.path.exists(f):
                return open(f).read().strip() == "1"
    except OSError:
        pass
    return False


def on_encrypted_volume(path) -> bool:
    """Does `path` (or the nearest folder that exists) sit on an encrypted (LUKS) volume?"""
    src = run(["findmnt", "-no", "SOURCE", "-T", existing_parent(path)], timeout=10).stdout.strip()
    src = src.split("[")[0]           # btrfs subvolume suffix
    if not src:
        return False
    return "crypt" in run(["lsblk", "-sno", "TYPE", src], timeout=10).stdout.split()


MIN_FEDORA = 45      # the release BitFedot is developed and tested on


def fedora_release(os_release="/etc/os-release"):
    """Fedora's release number, or None on anything else."""
    try:
        with open(os_release) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    info = dict(line.strip().split("=", 1) for line in lines if "=" in line)
    if info.get("ID", "").strip('"') != "fedora":
        return None
    try:
        return int(info.get("VERSION_ID", "").strip('"'))
    except ValueError:
        return None


# Rough mainnet footprint (GB): blocks + chainstate, txindex, Fulcrum, Mempool DB.
REQUIRED_GB = 1300


def dbcache_ibd() -> int:
    """UTXO cache during initial sync: half the RAM, leaving room for the OS."""
    return max(450, min(ram_mb() // 2, 24000))


def dbcache_ready() -> int:
    return max(450, min(ram_mb() // 8, 4096))


def fulcrum_db_mem() -> int:
    return max(1024, min(ram_mb() // 8, 8192))


# -------------------------------------------------------------------- VPNs --
_VPN_KINDS = {"wireguard", "tun", "ppp", "ipip", "gre", "vti", "xfrm", "ovpn"}
_VPN_NAMES = re.compile(r"^(wg|tun|ppp|proton|mullvad|nordlynx|tailscale|vpn|ipsec)", re.I)
_NOT_VPN = re.compile(r"^(lo|docker|podman|virbr|veth|br-|cni|vnet|tap)")


def vpn_interfaces() -> list:
    """Tunnel interfaces that are up and carry a routable address.
    -> [{'name': 'wg0', 'kind': 'wireguard', 'v4': [...], 'v6': [...]}]"""
    try:
        links = json.loads(run(["ip", "-d", "-j", "addr", "show", "up"], timeout=10).stdout or "[]")
    except ValueError:
        return []
    found = []
    for link in links:
        name = link.get("ifname", "")
        kind = (link.get("linkinfo") or {}).get("info_kind", "")
        if _NOT_VPN.match(name):
            continue
        if not (kind in _VPN_KINDS or _VPN_NAMES.match(name) or "POINTOPOINT" in link.get("flags", [])):
            continue
        v4, v6 = [], []
        for a in link.get("addr_info", []):
            if a.get("scope") != "global":
                continue
            (v4 if a.get("family") == "inet" else v6).append(a["local"])
        if v4 or v6:
            found.append({"name": name, "kind": kind or "tunnel", "v4": v4, "v6": v6})
    return found


def vpn_addresses(iface: str):
    """(v4, v6) currently assigned to `iface`; (None, None) if it is down."""
    for v in vpn_interfaces():
        if v["name"] == iface:
            return (v["v4"][0] if v["v4"] else None, v["v6"][0] if v["v6"] else None)
    return None, None


def route_device(src: str, dst="1.1.1.1") -> str:
    """Which interface the kernel would use for traffic from `src` to `dst`."""
    try:
        r = json.loads(run(["ip", "-j", "route", "get", dst, "from", src], timeout=10).stdout or "[]")
        return r[0].get("dev", "") if r else ""
    except (ValueError, IndexError):
        return ""


def notify(title: str, body: str = "") -> bool:
    """Show a desktop notification. -> whether the desktop took it: with nobody logged in
    (the node keeps running then) there is no notification service to take it."""
    if DRY_RUN:
        return True
    if not have("notify-send"):
        return False
    return run(["notify-send", "-a", paths.APP_NAME, "-i", paths.APP_ID, title, body],
               timeout=10).returncode == 0


def default_route_device() -> str:
    """Interface carrying ordinary internet traffic right now."""
    try:
        r = json.loads(run(["ip", "-j", "route", "get", "1.1.1.1"], timeout=10).stdout or "[]")
        return r[0].get("dev", "") if r else ""
    except (ValueError, IndexError):
        return ""
