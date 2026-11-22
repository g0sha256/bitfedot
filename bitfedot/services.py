"""Renders every config file and systemd unit from the settings, and converges
the running system onto them.

`apply()` is the single place that decides what runs. It is idempotent and
*ordered*: anything that has to go down is stopped dependents-first and waited
for (Mempool → Fulcrum → Bitcoin Core → Tor), then everything that should run
is started in the opposite order. It is called by the installer, the GUI and
the background agent; a file lock keeps those from reconfiguring concurrently.

Three rules keep what runs from drifting away from what is stored:

  * apply() reads the settings itself, under the lock. Whoever holds the lock
    applies the latest ones; a snapshot taken earlier can never be applied later.
  * A file is replaced only once everything that reads it has been stopped. However
    an apply() ends — a service that will not stop, the app closed, the power gone —
    whatever runs still matches its files, and the next apply() sees from the files
    what is left to do. (A restart the files cannot show, after a new binary, is
    written down first: paths.APPLY_PENDING.)
  * Nothing systemd refuses passes silently. A stop that fails ends the apply()
    before anything is replaced; anything else is tried in full and then reported.
    An apply() that did not complete stays `unfinished()`, and the background agent
    and the app finish it.
"""
import fcntl
import hashlib
import hmac
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from . import paths, pins, settings, system
from .paths import U_AGENT, U_BITCOIND, U_FULCRUM, U_MEMPOOL, U_TOR

HEADER = "# Managed by BitFedot — edits are overwritten. Change settings in the app.\n"
MARIADB_IMAGE = "docker.io/library/mariadb:10.5.21"   # version pinned by upstream Mempool
POD_HOST_IP = "169.254.1.3"                           # host loopback as seen from the pod

LABELS = {U_BITCOIND: "Bitcoin Core", U_TOR: "Tor", U_FULCRUM: "Fulcrum",
          U_MEMPOOL: "Mempool", U_AGENT: "background agent"}
# Shutdown order: consumers before the things they consume. Start-up is the reverse.
STOP_ORDER = (U_MEMPOOL, U_FULCRUM, U_BITCOIND, U_TOR)
# When the key restarts, these are taken down first and brought back afterwards.
DEPENDENTS = {U_BITCOIND: (U_FULCRUM, U_MEMPOOL), U_FULCRUM: (U_MEMPOOL,)}
# Seconds to wait for a clean stop; matches TimeoutStopSec of each unit plus a margin.
STOP_TIMEOUT = {U_BITCOIND: 1900, U_FULCRUM: 700, U_MEMPOOL: 240, U_TOR: 90}


def mempool_images(version: str) -> dict:
    """part -> image name by release tag (what upstream calls it)."""
    return {"web": f"docker.io/mempool/frontend:v{version}",
            "api": f"docker.io/mempool/backend:v{version}",
            "db": MARIADB_IMAGE}


def image_ref(image: str) -> str:
    """What is actually pulled and run: the pinned digest when BitFedot vouches
    for the image (see pins.py), otherwise the tag."""
    return pins.pinned_ref(image) or image



# ------------------------------------------------------------ predicates --
def in_ibd(s) -> bool:
    return s["phase"] != "ready"


def bitcoin_uses_tor(s) -> bool:
    if in_ibd(s) and s["ibd_clearnet"]:
        return False
    return s["net_mode"] != "clearnet"


def tor_wanted(s) -> bool:
    if not s["installed"] or s["all_stopped"] or not s["tor_enabled"]:
        return False
    if in_ibd(s) and s["ibd_clearnet"]:
        return False           # sync first, Tor afterwards
    if s["tor_route"] == "vpn":
        return any(system.vpn_addresses(s["vpn_iface"]))   # kill switch: no VPN, no Tor
    return True


def desired_units(s) -> dict:
    """unit -> should it be running?"""
    up = s["installed"] and not s["all_stopped"]
    core = up and s["bitcoind_enabled"]
    ready = core and s["phase"] == "ready"
    return {
        U_BITCOIND: core,
        U_TOR: tor_wanted(s),
        U_FULCRUM: ready and s["fulcrum_enabled"],
        U_MEMPOOL: ready and s["mempool_enabled"] and s["fulcrum_enabled"],
        U_AGENT: s["installed"],
    }


# ------------------------------------------------------------ bitcoin.conf --
def rpcauth(user, password, salt) -> str:
    """An rpcauth= line as produced by Bitcoin Core's share/rpcauth/rpcauth.py."""
    digest = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    return f"rpcauth={user}:{salt}${digest}"


def bitcoin_conf(s) -> str:
    sec = s["secrets"]
    socks = f"127.0.0.1:{paths.TOR_SOCKS}"
    L = [HEADER,
         "server=1",
         "rpcbind=127.0.0.1",
         "rpcallowip=127.0.0.1",
         f"rpcport={paths.RPC_PORT}",
         rpcauth("mempool", sec["mempool_rpc_password"], sec["rpc_salt"]),
         "printtoconsole=1",      # logs go to the journal
         "debuglogfile=0",
         "disablewallet=1",       # keys live in your wallet app, never in the node
         ""]
    if in_ibd(s):
        L += ["# --- initial block download: tuned for speed ---",
              f"dbcache={system.dbcache_ibd()}",   # big UTXO cache = far fewer disk flushes
              "blocksonly=1",                       # skip loose transactions while catching up
              "persistmempool=0",
              "txindex=0",                          # built in the background after sync
              "listen=0",
              ""]
    else:
        L += ["# --- synced: full service profile ---",
              f"dbcache={system.dbcache_ready()}",
              "txindex=1",                          # required by Fulcrum and Mempool
              f"zmqpubhashblock=tcp://127.0.0.1:{paths.ZMQ_PORT}",
              ""]

    mode = s["net_mode"] if bitcoin_uses_tor(s) else "clearnet"
    L.append(f"# --- network: {mode} ---")
    if mode == "dual":
        L += [f"onion={socks}"]
    elif mode == "tor_only":
        L += [f"proxy={socks}", "onlynet=onion", "dnsseed=0", "dns=0"]
    elif mode == "tor_proxy":
        L += [f"proxy={socks}", "dns=0"]

    if not in_ibd(s):
        if mode != "clearnet" and s["private_broadcast"]:
            L.append("privatebroadcast=1")   # own transactions leave via one-shot Tor connections
        binds = []
        if mode != "clearnet" and s["listen_onion"]:
            binds.append(f"bind=127.0.0.1:{paths.ONION_P2P_PORT}=onion")
            L += ["listenonion=1", f"torcontrol=127.0.0.1:{paths.TOR_CONTROL}"]
        else:
            L.append("listenonion=0")
        if clearnet_inbound(s):
            binds.append(f"bind=0.0.0.0:{paths.P2P_PORT}")
            if os.path.exists("/proc/net/if_inet6"):
                binds.append(f"bind=[::]:{paths.P2P_PORT}")
            L.append(f"natpmp={1 if s['natpmp'] else 0}")
        else:
            L.append("discover=0")       # never learn or advertise our own IP
        L.append(f"listen={1 if binds else 0}")
        L += binds
    return "\n".join(L) + "\n"


def clearnet_inbound(s) -> bool:
    """Is the P2P port meant to be reachable on the public IP? (Also drives the firewall.)"""
    return (not in_ibd(s) and s["listen_clearnet"]
            and (s["net_mode"] if bitcoin_uses_tor(s) else "clearnet") in ("clearnet", "dual"))


# ------------------------------------------------------------------ torrc --
def hidden_service_dir(name) -> Path:
    return paths.TOR_DIR / f"hs_{name}"


def onion_hostname(name) -> str:
    try:
        return (hidden_service_dir(name) / "hostname").read_text().strip()
    except OSError:
        return ""


def torrc(s) -> str:
    L = [HEADER,
         f"DataDirectory {paths.TOR_DIR / 'data'}",
         f"SocksPort 127.0.0.1:{paths.TOR_SOCKS}",
         f"ControlPort 127.0.0.1:{paths.TOR_CONTROL}",
         "CookieAuthentication 1",
         f"CookieAuthFile {paths.TOR_DIR / 'control_auth_cookie'}",
         "ClientOnly 1",
         "AvoidDiskWrites 1",
         "Log notice stdout"]
    if s["tor_route"] == "vpn":
        v4, v6 = system.vpn_addresses(s["vpn_iface"])
        L.append(f"# Tor leaves through VPN interface {s['vpn_iface']}; if it goes away Tor cannot connect.")
        if v4:
            L.append(f"OutboundBindAddress {v4}")
        if v6:
            L.append(f"OutboundBindAddress [{v6}]")
        if not v6:
            L.append("ClientUseIPv6 0")
        if not v4:
            L.append("ClientUseIPv4 0")
    for name, on, virt, target in (("fulcrum", s["onion_fulcrum"], 50001, paths.FULCRUM_PORT),
                                   ("mempool", s["onion_mempool"], 80, paths.MEMPOOL_PORT)):
        if on:
            L += [f"HiddenServiceDir {hidden_service_dir(name)}",
                  f"HiddenServicePort {virt} 127.0.0.1:{target}"]
    return "\n".join(L) + "\n"


# ------------------------------------------------------------ fulcrum.conf --
def fulcrum_conf(s) -> str:
    return "\n".join([
        HEADER,
        f"datadir = {Path(s['data_dir']) / 'fulcrum'}",
        f"bitcoind = 127.0.0.1:{paths.RPC_PORT}",
        f"rpccookie = {Path(s['data_dir']) / 'bitcoin' / '.cookie'}",
        f"tcp = 127.0.0.1:{paths.FULCRUM_PORT}",
        f"stats = 127.0.0.1:{paths.FULCRUM_STATS}",
        "peering = false",
        "announce = false",
        f"db_mem = {system.fulcrum_db_mem()}",
        "anon_logs = true",
    ]) + "\n"


# ------------------------------------------------------------------ units --
def _arg(text) -> str:
    """Quote one ExecStart argument for systemd (paths may contain spaces)."""
    text = str(text).replace("%", "%%").replace("$", "$$")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"' if " " in text else text


def sandbox(s, writable=()) -> str:
    """systemd sandboxing for a service that only needs the network and the
    directories in `writable`. Everything here works in an unprivileged user
    manager on Fedora (systemd ≥ 254 sets up the user namespace itself)."""
    if not s["sandbox"]:
        return ""
    L = ["NoNewPrivileges=yes",
         "ProtectSystem=strict",          # whole filesystem read-only …
         "ProtectHome=read-only",
         *(f"ReadWritePaths={_arg(p)}" for p in writable),   # … except its own data
         "PrivateDevices=yes",
         "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
         "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
         "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
         "RestrictNamespaces=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes",
         "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
         "SystemCallArchitectures=native", "SystemCallFilter=@system-service",
         "UMask=0077", "LimitCORE=0"]
    managed = [str(p) for p in (*writable, paths.APPS_DIR, paths.CONFIG_DIR)]
    if not any(p.startswith(("/tmp/", "/var/tmp/")) for p in managed):
        L.append("PrivateTmp=yes")        # a private /tmp would hide data kept under /tmp
    return "\n".join(L) + "\n"


def _unit(desc, exec_start, extra="", after="network-online.target"):
    return f"""{HEADER}[Unit]
Description={desc}
After={after}

[Service]
Type=exec
ExecStart={exec_start}
Restart=on-failure
RestartSec=30
{extra}
[Install]
WantedBy=default.target
"""


def bitcoind_unit(s) -> str:
    exe = paths.app_current("bitcoin") / "bin" / "bitcoind"
    datadir = Path(s["data_dir"]) / "bitcoin"
    return _unit("BitFedot — Bitcoin Core",
                 " ".join(_arg(a) for a in (exe, f"-conf={paths.BITCOIN_CONF}", f"-datadir={datadir}")),
                 # flushing a large UTXO cache on shutdown can take minutes
                 "TimeoutStartSec=infinity\nTimeoutStopSec=1800\n" + sandbox(s, [datadir]))


def tor_unit(s) -> str:
    return _unit("BitFedot — Tor", f"/usr/bin/tor -f {_arg(paths.TORRC)}",
                 "ExecReload=/bin/kill -HUP $MAINPID\nTimeoutStopSec=60\n" + sandbox(s, [paths.TOR_DIR]))


# Upstream's Fulcrum binary is linked on Debian, where bzip2's library is called
# libbz2.so.1.0; Fedora ships the very same library as libbz2.so.1.
COMPAT_LIBS = {"libbz2.so.1.0": ("/usr/lib64/libbz2.so.1", "/lib64/libbz2.so.1", "/usr/lib/libbz2.so.1")}


def ensure_compat_libs():
    """Give prebuilt upstream binaries the library names they were linked against,
    as symlinks to the system's own libraries in a private directory."""
    for soname, candidates in COMPAT_LIBS.items():
        if any((Path(d) / soname).exists() for d in ("/usr/lib64", "/lib64", "/usr/lib")):
            continue                                  # the system provides it under that name
        target = next((c for c in candidates if os.path.exists(c)), None)
        link = paths.COMPAT_LIB_DIR / soname
        if target and os.path.realpath(link) != os.path.realpath(target):
            paths.COMPAT_LIB_DIR.mkdir(parents=True, exist_ok=True)
            link.unlink(missing_ok=True)
            os.symlink(target, link)


def fulcrum_unit(s) -> str:
    exe = paths.app_current("fulcrum") / "Fulcrum"
    return _unit("BitFedot — Fulcrum", f"{_arg(exe)} {_arg(paths.FULCRUM_CONF)}",
                 # Fulcrum must exit cleanly or its database needs a full rebuild
                 f"Environment=LD_LIBRARY_PATH={_arg(paths.COMPAT_LIB_DIR)}\n"
                 "TimeoutStopSec=600\nLimitNOFILE=65536\n"
                 + sandbox(s, [Path(s["data_dir"]) / "fulcrum"]), after=U_BITCOIND)


def agent_unit(s) -> str:
    return _unit("BitFedot — background agent", f"{sys.executable} -m bitfedot.agent",
                 f"Environment=PYTHONPATH={_arg(paths.PKG_DIR.parent)}\nEnvironment=BITFEDOT_AGENT=1\n")


def autostart_entry() -> str:
    return f"""[Desktop Entry]
Type=Application
Name={paths.APP_NAME}
Icon={paths.APP_ID}
Exec=env PYTHONPATH={paths.PKG_DIR.parent} {sys.executable} -m bitfedot --background
X-GNOME-Autostart-enabled=true
"""


def mempool_quadlets(s) -> dict:
    sec = s["secrets"]
    img = {part: image_ref(image) for part, image in
           mempool_images(s["versions"].get("mempool", "0")).items()}
    md = paths.MEMPOOL_DIR
    # Containers are rootless already; additionally drop every capability.
    harden = "NoNewPrivileges=true\nDropCapability=all\n" if s["sandbox"] else ""

    def container(name, image, env, extra):
        envs = "".join(f"Environment={k}={v}\n" for k, v in env.items())
        return f"""{HEADER}[Unit]
Description=BitFedot — Mempool {name}

[Container]
ContainerName=bitfedot-mempool-{name}
Image={image}
Pod=bitfedot-mempool.pod
User=1000:1000
{harden}{envs}{extra}
[Service]
Restart=on-failure
RestartSec=20
TimeoutStartSec=900
"""
    return {
        "bitfedot-mempool.pod": f"""{HEADER}[Unit]
Description=BitFedot — Mempool

[Pod]
PodName=bitfedot-mempool
# Rootless network namespace; the node's loopback is reachable as "nodehost".
Network=pasta:--map-host-loopback={POD_HOST_IP}
AddHost=nodehost:{POD_HOST_IP}
PublishPort=127.0.0.1:{paths.MEMPOOL_PORT}:8080
UserNS=keep-id:uid=1000,gid=1000

[Install]
WantedBy=default.target
""",
        "bitfedot-mempool-db.container": container("db", img["db"], {
            "MYSQL_DATABASE": "mempool", "MYSQL_USER": "mempool",
            "MYSQL_PASSWORD": sec["db_password"], "MYSQL_ROOT_PASSWORD": sec["db_root_password"],
            "MARIADB_AUTO_UPGRADE": "1",
        }, f"Volume={md / 'mysql'}:/var/lib/mysql:Z\n"),
        "bitfedot-mempool-api.container": container("api", img["api"], {
            "MEMPOOL_BACKEND": "electrum",
            "CORE_RPC_HOST": "nodehost", "CORE_RPC_PORT": paths.RPC_PORT,
            "CORE_RPC_USERNAME": "mempool", "CORE_RPC_PASSWORD": sec["mempool_rpc_password"],
            "ELECTRUM_HOST": "nodehost", "ELECTRUM_PORT": paths.FULCRUM_PORT,
            "ELECTRUM_TLS_ENABLED": "false",
            "DATABASE_ENABLED": "true", "DATABASE_HOST": "127.0.0.1",
            "DATABASE_DATABASE": "mempool", "DATABASE_USERNAME": "mempool",
            "DATABASE_PASSWORD": sec["db_password"],
            "STATISTICS_ENABLED": "true",
        }, f"Volume={md / 'cache'}:/backend/cache:Z\n"
           "Exec=./wait-for-it.sh 127.0.0.1:3306 --timeout=720 --strict -- ./start.sh\n"),
        "bitfedot-mempool-web.container": container("web", img["web"], {
            "FRONTEND_HTTP_PORT": "8080", "BACKEND_MAINNET_HTTP_HOST": "127.0.0.1",
        }, "Exec=./wait-for 127.0.0.1:3306 --timeout=720 -- nginx -g 'daemon off;'\n"),
    }


# ----------------------------------------------------------- write files --
def sync_dir(directory: Path):
    """Make a rename or removal inside `directory` survive a power cut."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:                     # a filesystem that cannot do this for folders
        pass
    finally:
        os.close(fd)


def _differs(path: Path, text: str) -> bool:
    try:
        return path.read_text() != text
    except (OSError, ValueError):       # missing, unreadable, or not text at all
        return True


def write_file(path: Path, text: str, mode=0o600) -> bool:
    """Atomically and durably write `text`; -> True if the file changed."""
    if not _differs(path, text):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    sync_dir(path.parent)
    return True


def config_files(s, desired=None) -> list:
    """Every generated file as (path, text, unit), where `unit` is what has to restart
    when that file changes. Renders only: nothing is written here. Writing is apply()'s
    job, and it does it only once the unit concerned is down."""
    desired = desired_units(s) if desired is None else desired
    files = [
        (paths.BITCOIN_CONF, bitcoin_conf(s), U_BITCOIND),
        (paths.UNIT_DIR / U_BITCOIND, bitcoind_unit(s), U_BITCOIND),
        (paths.TORRC, torrc(s), U_TOR),
        (paths.UNIT_DIR / U_TOR, tor_unit(s), U_TOR),
        (paths.FULCRUM_CONF, fulcrum_conf(s), U_FULCRUM),
        (paths.UNIT_DIR / U_FULCRUM, fulcrum_unit(s), U_FULCRUM),
        (paths.UNIT_DIR / U_AGENT, agent_unit(s), U_AGENT),
    ]
    if desired[U_MEMPOOL]:
        files += [(paths.QUADLET_DIR / name, text, U_MEMPOOL)
                  for name, text in mempool_quadlets(s).items()]
    return files


def _prepare_dirs(s):
    """The folders the services expect, and the library names upstream binaries look for."""
    paths.ensure_dirs()
    data = Path(s["data_dir"])
    for d in (data / "bitcoin", data / "fulcrum", paths.TOR_DIR / "data",
              paths.MEMPOOL_DIR / "mysql", paths.MEMPOOL_DIR / "cache"):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.TOR_DIR / "data", 0o700)
    ensure_compat_libs()


def write_autostart(s):
    """The tray app's login autostart entry, per the `autostart` setting. Touches nothing
    else — in particular no file a service reads."""
    for old_id in paths.OLD_APP_IDS:                     # entries from before a rename
        (paths.AUTOSTART_DIR / f"{old_id}.desktop").unlink(missing_ok=True)
    auto = paths.AUTOSTART_DIR / f"{paths.APP_ID}.desktop"
    if s["autostart"]:
        write_file(auto, autostart_entry(), 0o644)
    elif auto.exists():
        auto.unlink()


# ----------------------------------------------------------------- apply --
class Busy(RuntimeError):
    """A reconfiguration is under way and holds the lock."""


@contextmanager
def _apply_lock(wait=True):
    """The lock every reconfiguration holds. With `wait` false: raise Busy instead of
    queueing behind one that is running (a second or so of patience covers the status
    poll, which takes the lock for an instant to see whether it is free)."""
    paths.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(paths.APPLY_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if wait:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            for _ in range(20):
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.05)
            else:
                raise Busy("BitFedot is changing the services right now — try again when it has finished.")
        try:
            yield
        finally:
            paths.ACTIVITY_FILE.unlink(missing_ok=True)
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _note(text, report=None):
    """Publish what a reconfiguration is doing, for this and other processes."""
    paths.ACTIVITY_FILE.write_text(text)
    if report:
        report(text)


def activity() -> str:
    """What a running apply() — in the GUI or the agent — is doing; '' if idle."""
    try:
        fd = os.open(paths.APPLY_LOCK, os.O_RDWR)
    except OSError:
        return ""
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:                      # lock is held: an apply is in progress
        try:
            return paths.ACTIVITY_FILE.read_text().strip() or "Applying changes…"
        except OSError:
            return "Applying changes…"
    finally:
        os.close(fd)
    return ""


UNFINISHED_NOTE = "A change to your node was not completed"


def _owed() -> set:
    """Units an unfinished apply() still owes a restart that the files do not show."""
    try:
        return set(paths.APPLY_PENDING.read_text().split()) & set(LABELS)
    except (OSError, ValueError):
        return set()


def _mark_unfinished(owed=()):
    """Record, durably, that a reconfiguration is under way and which restarts it owes.
    The record goes when an apply() completes; until then `unfinished()` tells."""
    write_file(paths.APPLY_PENDING, "".join(f"{unit}\n" for unit in sorted(owed)))


def _finished():
    paths.APPLY_PENDING.unlink(missing_ok=True)
    sync_dir(paths.CONFIG_DIR)


def unfinished() -> bool:
    """Did a reconfiguration begin and not complete — the app was closed or the computer
    switched off in the middle of it, or a service would not stop? Running apply() once
    more finishes it. False while one is running."""
    return paths.APPLY_PENDING.exists() and not activity()


def _systemctl(*args, timeout=120) -> str:
    """Run one systemctl call. -> '' if systemd did it, otherwise why not.
    One unit per call: a call that names several does nothing for any of them when
    systemd does not have one."""
    p = system.systemctl(*args, timeout=timeout)
    if p.returncode == 0:
        return ""
    said = (p.stderr or p.stdout or "").strip().splitlines()
    if p.returncode == 124 and (not said or "timed out" in said[-1]):      # system.run's own limit
        return f"no answer after {timeout} seconds"
    return said[-1].strip() if said else f"systemctl exit status {p.returncode}"


def _up(states: dict) -> set:
    """Units that are running in any sense: also starting, stopping or waiting to restart."""
    return {unit for unit, state in states.items() if state not in ("inactive", "failed")}


def _stop_in_order(units, report=None):
    """Stop `units`, consumers first, waiting for each. Raises at the first one that does
    not stop: nothing it depends on may be taken down under it."""
    for unit in STOP_ORDER:
        if unit in units:
            _note(f"Stopping {LABELS[unit]} safely…" + (
                " (flushing to disk, this can take a few minutes)" if unit == U_BITCOIND else ""), report)
            why = _systemctl("stop", unit, timeout=STOP_TIMEOUT[unit])
            if why:
                raise RuntimeError(f"{LABELS[unit]} could not be stopped ({why}).")


def _remove_mempool_quadlets() -> bool:
    files = list(paths.QUADLET_DIR.glob("bitfedot-mempool*"))
    for f in files:
        f.unlink()
    return bool(files)


def apply(*, restart=(), report=None) -> set:
    """Converge files and units onto the stored settings.

    Units whose configuration changed (or that are listed in `restart`, e.g.
    after a binary upgrade) are restarted together with everything depending
    on them, in a safe order. Blocks until every stop has completed.

    Raises RuntimeError when systemd refuses something. A service that does not
    stop ends it there, before any file is replaced; whatever else fails is
    reported once everything has been tried. Either way the apply stays
    `unfinished()`: run again — by hand, by the agent, at the next launch — it
    carries on from where things stand.
    -> set of units whose configuration changed."""
    with _apply_lock():
        s = settings.load()                 # the latest, whoever saved them and whenever
        _note("Applying changes…", report)
        owed = _owed() | (set(restart) & set(LABELS))
        _mark_unfinished(owed)
        desired = desired_units(s)
        files = config_files(s, desired)
        stale = {unit for path, text, unit in files if _differs(path, text)} | owed
        states = system.unit_states(desired)         # raises if systemd does not answer
        running = _up(states)

        # 1. What has to go down: unwanted units, changed units, and their dependents.
        cycle = {u for u in running if desired[u] and u in stale}
        for base in (U_BITCOIND, U_FULCRUM):
            if base in cycle or (base in running and not desired[base]):
                cycle |= {d for d in DEPENDENTS[base] if d in running and desired[d]}
        going_down = {u for u in running if not desired[u]} | cycle
        try:
            _stop_in_order(going_down, report)
        except RuntimeError as e:
            raise RuntimeError(f"{e} No file was changed; the change stays pending.") from None
        if going_down:      # stopping takes minutes: is everything that must be down still down?
            must_be_down = {u for u in STOP_ORDER if u in stale or not desired[u]}
            back = sorted(LABELS[u] for u in _up(system.unit_states(desired)) & must_be_down)
            if back:
                raise RuntimeError(f"{' and '.join(back)} started again while the change was being "
                                   "applied — not by BitFedot. No file was changed; the change stays pending.")

        # 2. Nothing that reads them is running now: replace the files. (The agent is the
        #    exception. It keeps running, so the restart it is owed is written down first;
        #    while applying it never restarts itself, its new unit serves from its next start.)
        me = bool(os.environ.get("BITFEDOT_AGENT"))
        agent_stale = U_AGENT in stale and U_AGENT in running and desired[U_AGENT]
        owed = {U_AGENT} if agent_stale and not me else set()
        _mark_unfinished(owed)
        _prepare_dirs(s)
        for path, text, _unit in files:
            write_file(path, text)
        write_autostart(s)
        if not desired[U_MEMPOOL]:
            _remove_mempool_quadlets()
        why = _systemctl("daemon-reload")
        if why:
            raise RuntimeError(f"The new configuration is written, but systemd did not load it ({why}). "
                               "The change stays pending.")

        # 3. Bring everything that should run back up, providers first. What fails here is
        #    collected, so that one refusal does not keep the rest of the node down.
        problems = []

        def attempt(what, *args) -> bool:
            why = _systemctl(*args)
            if why:
                problems.append(f"{what} ({why}).")
            return not why

        for unit in reversed(STOP_ORDER):
            generated = unit == U_MEMPOOL        # Quadlet units cannot be enabled/disabled
            if desired[unit]:
                if not generated:
                    attempt(f"{LABELS[unit]} could not be enabled", "enable", unit)
                if unit not in running or unit in going_down:
                    _note(f"Starting {LABELS[unit]}…", report)
                    attempt(f"{LABELS[unit]} could not be started", "--no-block", "start", unit)
            elif not generated and (paths.UNIT_DIR / unit).exists():
                if states.get(unit) == "failed":
                    system.systemctl("reset-failed", unit)
                attempt(f"{LABELS[unit]} could not be disabled", "disable", unit)

        # 4. The agent follows the install state.
        if desired[U_AGENT]:
            attempt("The background agent could not be enabled", "enable", U_AGENT)
            if not me:
                attempt("The background agent could not be started",
                        "--no-block", "restart" if agent_stale else "start", U_AGENT)
        else:
            system.systemctl("disable", "--now", U_AGENT)

        if problems:
            raise RuntimeError(" ".join(problems) + " The change stays pending.")
        _finished()
    return stale


def restart_unit(unit, wait=False):
    """Restart one service as it is configured now — the user's "Restart" and "Reconnect".
    Refused (Busy) while a reconfiguration is under way: started in the middle of one, a
    service could come up with files that are about to be replaced."""
    with _apply_lock(wait=False):
        _note(f"Restarting {LABELS[unit]}…")
        why = _systemctl(*(() if wait else ("--no-block",)), "restart", unit)
        if why:
            raise RuntimeError(f"{LABELS[unit]} could not be restarted ({why}).")


def _stop_all(report=None):
    """Stop the background agent — or it would start things again — and then every
    service, consumers first, waiting for each.

    Only what is up is asked to stop. systemd answers with an error for a unit it does
    not have, and Mempool has none while it is switched off or the first sync is still
    running: that is not "could not be stopped". Raises when systemd does not answer,
    and at the first unit that does not stop."""
    up = _up(system.unit_states((U_AGENT, *STOP_ORDER)))
    if U_AGENT in up:
        why = _systemctl("stop", U_AGENT)
        if why:
            raise RuntimeError(f"The {LABELS[U_AGENT]} could not be stopped ({why}).")
    _stop_in_order(up, report)


def stop_everything(report=None):
    """Ordered, blocking stop of every service without changing what is enabled
    (used before a reboot: everything comes back by itself afterwards).

    An apply() is owed from the first moment: it is a no-op after the reboot, and it is
    what brings the node back if this is cut short or the reboot never happens. If a
    service does not stop, this raises and the agent is started again to do just that."""
    with _apply_lock():
        _mark_unfinished(_owed())
        try:
            _stop_all(report)
        except BaseException:
            system.systemctl("--no-block", "start", U_AGENT)
            raise
        _mark_unfinished()      # a restart that was owed is paid: everything is down, and will start afresh


def remove_all(report=None):
    """Stop and remove every unit, then mark the node as not installed. Blockchain data
    and settings are kept.

    If a service does not stop, nothing is removed: this raises, the node stays installed
    and the agent is started again, which brings back what had already been stopped."""
    with _apply_lock():
        _mark_unfinished(_owed())
        try:
            _stop_all(report)
            back = sorted(LABELS[u] for u in _up(system.unit_states(STOP_ORDER)))
            if back:    # stopping takes minutes
                raise RuntimeError(f"{' and '.join(back)} started again while the services were being "
                                   "stopped — not by BitFedot.")
        except BaseException as e:
            system.systemctl("--no-block", "start", U_AGENT)
            if isinstance(e, RuntimeError):
                raise RuntimeError(f"{str(e).rstrip('.')}. Nothing was removed.") from None
            raise
        for unit in (*STOP_ORDER, U_AGENT):
            if unit != U_MEMPOOL:
                system.systemctl("disable", unit)
                (paths.UNIT_DIR / unit).unlink(missing_ok=True)
        _remove_mempool_quadlets()
        (paths.AUTOSTART_DIR / f"{paths.APP_ID}.desktop").unlink(missing_ok=True)
        system.systemctl("daemon-reload")
        # Still under the lock: an apply() queued behind this one must find nothing to run.
        settings.update(installed=False)
        _finished()
