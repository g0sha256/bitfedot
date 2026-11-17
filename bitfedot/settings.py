"""Persistent settings/state shared by the GUI and the background agent.

A single JSON file guarded by an flock; every mutation is read-modify-write so
the two processes never clobber each other."""
import copy
import fcntl
import json
import os
import secrets as _secrets
from contextlib import contextmanager

from . import paths

DEFAULTS = {
    "installed": False,
    # new -> ibd (initial block download) -> ready
    "phase": "new",
    "data_dir": str(paths.DEFAULT_CHAIN_DIR),

    # --- connectivity -----------------------------------------------------
    "ibd_clearnet": True,        # initial sync over clearnet, Tor comes up afterwards
    "net_mode": "dual",          # clearnet | dual | tor_only | tor_proxy
    "listen_onion": True,        # accept inbound peers on an onion service
    "listen_clearnet": False,    # accept inbound peers on your public IP
    "natpmp": False,             # ask the router to forward the P2P port
    "tor_enabled": True,         # Tor up / down
    "tor_route": "direct",       # direct | vpn
    "vpn_iface": "",
    "onion_fulcrum": False,      # publish Fulcrum as an onion service
    "onion_mempool": False,      # publish Mempool as an onion service

    # --- services ---------------------------------------------------------
    "all_stopped": False,        # "Stop all": overrides the per-service switches below
    "resume_on_launch": False,   # set by "shut down and quit": start everything on next launch
    "bitcoind_enabled": True,
    "fulcrum_enabled": True,
    "mempool_enabled": True,

    # --- security & privacy -----------------------------------------------
    "sandbox": True,             # systemd sandboxing for every service
    "core_min_signers": 3,       # Bitcoin Core: independent builder signatures required
    "pinned_images_only": True,  # run only container images whose digest BitFedot vouches for
    "private_broadcast": False,  # relay own transactions over one-shot Tor connections
    "fw_strict": False,          # firewalld: dedicated zone, everything inbound closed
    "fw_prev_zone": "",          # zone to restore when strict mode is switched off
    "fw_allow_ssh": False,
    "killswitch": False,         # system-wide: block all traffic that bypasses the VPN
    "ks_iface": "",
    "ks_allow_lan": True,
    "ks_endpoints": "",          # extra VPN server addresses allowed outside the tunnel
    "os_updates": {},            # last Fedora update check: count, security, reboot, checked
    "hwkeys": {},                # hardware-key setup progress, see hardware_keys.state()
    "auto_self_update": False,   # install signed BitFedot releases without asking

    # --- app behaviour ----------------------------------------------------
    "linger": True,              # keep the node running while logged out
    "keep_awake": True,          # while services run, keep the computer from going to sleep
    "autostart": True,           # start the tray app at login
    "background": True,          # closing the window keeps the app running
    "theme": "system",           # system | light | dark
    "updates_via_tor": True,
    "status_notifications": True,   # desktop notifications for sync milestones and services
    "notified": {},                 # what was already announced, see node.status_events()
    "auto_check_updates": True,
    "last_update_check": 0,
    "available": {},             # component -> latest upstream version seen

    "versions": {},              # component -> installed version
    "digests": {},               # container image -> digest
    "secrets": {},
}

NET_MODES = ("clearnet", "dual", "tor_only", "tor_proxy")
REPLACED = ("os_updates", "notified")      # dict-valued keys that update() replaces instead of merging


@contextmanager
def _lock():
    paths.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(paths.CONFIG_DIR / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read() -> dict:
    data = copy.deepcopy(DEFAULTS)
    try:
        with open(paths.SETTINGS_FILE) as f:
            stored = json.load(f)
        if isinstance(stored, dict):
            data.update(stored)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        # A corrupt file must not be silently replaced by defaults: that would
        # make an installed node look uninstalled.
        raise RuntimeError(f"Cannot read {paths.SETTINGS_FILE}; fix or remove it.")
    return data


def _write(data: dict):
    tmp = paths.SETTINGS_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, paths.SETTINGS_FILE)


def load() -> dict:
    with _lock():
        return _read()


def update(**changes) -> dict:
    """Atomically merge `changes` into the stored settings and return the result.
    Dict values (versions, digests, secrets, available) are merged key-wise;
    a value of None removes that key (e.g. versions={"sparrow": None}).
    Two dict-valued keys are records rather than maps and are replaced whole (REPLACED):
    `os_updates`, the result of one check, and `notified`, see node.status_events()."""
    with _lock():
        data = _read()
        for k, v in changes.items():
            if isinstance(v, dict) and isinstance(data.get(k), dict) and k not in REPLACED:
                data[k] = {k2: v2 for k2, v2 in {**data[k], **v}.items() if v2 is not None}
            else:
                data[k] = v
        _write(data)
        return data


def ensure_secrets() -> dict:
    """Generate the local service passwords once."""
    with _lock():
        data = _read()
        s = data["secrets"]
        for key in ("mempool_rpc_password", "db_password", "db_root_password"):
            s.setdefault(key, _secrets.token_hex(24))
        s.setdefault("rpc_salt", _secrets.token_hex(16))
        _write(data)
        return data
