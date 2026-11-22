#!/usr/bin/env python3
"""Rehearse services.apply() against the REAL systemd user manager — with stand-ins.

The unit tests drive apply() against a fake `systemctl`. This runs the same code against
the real one. Five throw-away units that only sleep stand in for Tor, Bitcoin Core,
Fulcrum, Mempool and the agent, under names no installation uses; settings and every
generated file live in a temporary folder.

    python3 -P tools/apply-rehearsal.py          (from a checkout, logged in; about a minute)

Never touched: any `bitfedot-*` unit, any port, any real configuration or data — it is
safe on a computer whose node is running. A guard refuses every systemctl call that
names a unit other than the stand-ins. They are stopped and removed at the end, and a
timer set at the start removes them even if this is killed half-way.

What it goes through: starting in order · an apply that changes nothing · a changed file
restarting what reads it, dependents included, and replaced only once they are down · a
service that will not stop (reported, nothing replaced, finished later) · the applying
process killed in the middle (finished later) · a restart refused meanwhile · systemd
not answering · stopping everything · the same while one service has no unit, as Mempool
has none while it is switched off · removal.
"""
import contextlib
import io
import os
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = Path(os.environ.get("BF_REHEARSAL_ROOT") or tempfile.mkdtemp(prefix="bitfedot-rehearsal-"))
PREFIX = os.environ.get("BF_REHEARSAL_PREFIX") or f"bfrehearsal{secrets.token_hex(3)}"
os.environ.update(BITFEDOT_ROOT=str(ROOT), BF_REHEARSAL_ROOT=str(ROOT), BF_REHEARSAL_PREFIX=PREFIX)
os.environ.pop("BITFEDOT_AGENT", None)

sys.path.insert(0, str(HERE.parent.parent))
from bitfedot import paths  # noqa: E402

# Before anything else of the package is imported: the stand-ins' names, and the one real
# folder — where systemd looks for units. Everything else stays under ROOT.
for _name in ("U_BITCOIND", "U_TOR", "U_FULCRUM", "U_MEMPOOL", "U_AGENT"):
    setattr(paths, _name, getattr(paths, _name).replace("bitfedot-", PREFIX + "-"))
paths.UNIT_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd/user"

from bitfedot import agent, node, services, settings, system  # noqa: E402
from bitfedot.paths import U_AGENT, U_BITCOIND, U_FULCRUM, U_MEMPOOL, U_TOR  # noqa: E402

NODE = (U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL)
ALL = (*NODE, U_AGENT)
LOG, HOLD = ROOT / "order.log", ROOT / "hold"
_real_systemctl = system.systemctl


def guarded(*args, **kw):
    """The only door to systemd here: stand-ins only."""
    for arg in args:
        if arg.endswith((".service", ".target", ".timer")) and not arg.startswith(PREFIX + "-"):
            raise AssertionError(f"the rehearsal must not touch {arg}")
    return _real_systemctl(*args, **kw)


def stand_in(unit) -> str:
    """A unit that only sleeps. It notes when it starts and when it is asked to stop — and
    whether bitcoin.conf said "Tor only" at that moment — and it refuses to stop for as
    long as a file HOLD/<unit> exists."""
    note = f"$$(grep -c onlynet=onion {paths.BITCOIN_CONF})"
    return f"""{services.HEADER}[Unit]
Description=BitFedot rehearsal stand-in for {services.LABELS[unit]} — safe to remove

[Service]
Type=exec
ExecStartPre=/bin/sh -c 'echo "start {unit} {note}" >> {LOG}'
ExecStart=/usr/bin/sleep infinity
ExecStop=/bin/sh -c 'echo "stop {unit} {note}" >> {LOG}; while [ -e {HOLD}/{unit} ]; do sleep 0.2; done'
TimeoutStopSec=90
RuntimeMaxSec=1800

[Install]
WantedBy=default.target
"""


def install_stand_ins():
    system.DRY_RUN = False                      # this is the point: the real systemctl
    system.systemctl = guarded
    services.bitcoind_unit = lambda s: stand_in(U_BITCOIND)
    services.tor_unit = lambda s: stand_in(U_TOR)
    services.fulcrum_unit = lambda s: stand_in(U_FULCRUM)
    services.agent_unit = lambda s: stand_in(U_AGENT)
    # Mempool's unit is made by Quadlet from files apply() writes; those go to ROOT, where
    # Quadlet does not look, and this takes the place of what it would have generated.
    paths.UNIT_DIR.mkdir(parents=True, exist_ok=True)
    (paths.UNIT_DIR / U_MEMPOOL).write_text(stand_in(U_MEMPOOL))
    HOLD.mkdir(parents=True, exist_ok=True)


def child(argv) -> int:
    """`--apply key=value`: apply one changed setting, as the app would — to be killed."""
    install_stand_ins()
    key, value = argv[0].split("=", 1)
    node.apply_settings(**{key: value})
    return 0


def pids() -> dict:
    out = subprocess.run(["systemctl", "--user", "show", "-p", "MainPID", "--value", *ALL],
                         capture_output=True, text=True).stdout.split()
    return dict(zip(ALL, out))


def running() -> set:
    return {u for u, state in system.unit_states(ALL).items() if state == "active"}


def wait_for(condition, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.2)
    return False


def order(verb) -> list:
    """What the stand-ins noted since the log was last cleared: [(unit, conf said Tor only)]."""
    lines = [line.split() for line in LOG.read_text().splitlines()] if LOG.exists() else []
    return [(line[1], line[2] == "1") for line in lines if len(line) == 3 and line[0] == verb]


def remove_stand_ins():
    shutil.rmtree(HOLD, ignore_errors=True)     # nothing holds a stop back any more
    for unit in ALL:        # one call for each: a call that names a unit systemd does not have stops none
        _real_systemctl("stop", unit, timeout=120)
        _real_systemctl("disable", unit)
        (paths.UNIT_DIR / unit).unlink(missing_ok=True)
    _real_systemctl("daemon-reload")
    for unit in ALL:
        _real_systemctl("reset-failed", unit)


def main() -> int:
    if system.run(["systemctl", "--user", "is-system-running"]).returncode == 127:
        print("systemctl is not available here.")
        return 1
    results = []

    def check(what, ok):
        results.append(bool(ok))
        print(f"  {'ok  ' if ok else 'FAIL'}  {what}")

    def quiet():
        return contextlib.redirect_stdout(io.StringIO())

    conf = paths.BITCOIN_CONF
    # If this is killed half-way, the stand-ins still go: a timer of systemd's own.
    sweep = "".join(f"systemctl --user stop {u}; systemctl --user disable {u}; "
                    f"rm -f {shlex.quote(str(paths.UNIT_DIR / u))}; " for u in ALL) + "systemctl --user daemon-reload"
    subprocess.run(["systemd-run", "--user", "--quiet", "--collect", f"--unit={PREFIX}-sweep",
                    "--on-active=20min", "/bin/sh", "-c", sweep], check=False)
    print(f"Stand-in units: {PREFIX}-*.service · files under {ROOT}")
    try:
        install_stand_ins()
        settings.ensure_secrets()
        settings.update(installed=True, phase="ready", net_mode="dual", tor_route="direct", autostart=False,
                        versions={"mempool": "3.3.2"})

        print("\n1. Starting, and an apply that changes nothing")
        services.apply()
        check("the first apply starts all four services and the agent", wait_for(lambda: running() == set(ALL)))
        check("it is complete", not services.unfinished())
        before = pids()
        check("a second apply reports no change", services.apply() == set())
        check("and restarts nothing", pids() == before)

        print("\n2. A changed file: Bitcoin Core's network mode")
        LOG.unlink(missing_ok=True)
        changed = node.apply_settings(net_mode="tor_only")
        wait_for(lambda: running() == set(ALL))
        after = pids()
        check("apply reports Bitcoin Core as changed", changed == {U_BITCOIND})
        check("stopped, in this order: Mempool, Fulcrum, Bitcoin Core",
              [u for u, _ in order("stop")] == [U_MEMPOOL, U_FULCRUM, U_BITCOIND])
        check("the old file was still in place at each stop", not any(tor_only for _, tor_only in order("stop")))
        wait_for(lambda: len(order("start")) == 3)
        check("the new file was in place at each start",
              len(order("start")) == 3 and all(tor_only for _, tor_only in order("start")))
        check("Tor, which does not read it, kept running", after[U_TOR] == before[U_TOR])
        check("the other three are new processes",
              all(after[u] != before[u] and after[u] != "0" for u in (U_BITCOIND, U_FULCRUM, U_MEMPOOL)))

        print("\n3. A service that will not stop")
        (HOLD / U_FULCRUM).touch()
        services.STOP_TIMEOUT[U_FULCRUM] = 3
        before = pids()
        try:
            node.apply_settings(net_mode="dual")
            said = ""
        except RuntimeError as e:
            said = str(e)
        check(f"it is reported: {said[:74]}…", "Fulcrum could not be stopped (no answer after 3 seconds)" in said)
        check("no file was replaced", "onlynet=onion" in conf.read_text())
        check("Bitcoin Core was not taken down under it", pids()[U_BITCOIND] == before[U_BITCOIND])
        check("the change counts as unfinished", services.unfinished())
        (HOLD / U_FULCRUM).unlink()
        services.STOP_TIMEOUT[U_FULCRUM] = 700
        with quiet():
            agent.finish_unfinished({}, announce_failure=False)
        check("the agent finishes it: everything runs again", wait_for(lambda: running() == set(ALL)))
        check("with the new file", "onlynet=onion" not in conf.read_text())
        check("and nothing is left unfinished", not services.unfinished())

        print("\n4. The process applying a change is killed in the middle")
        (HOLD / U_BITCOIND).touch()
        before = pids()
        applying = subprocess.Popen([sys.executable, "-P", str(HERE), "--apply", "net_mode=tor_only"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check("it gets as far as stopping Bitcoin Core",
              wait_for(lambda: "Stopping Bitcoin Core" in services.activity()))
        check("meanwhile it does not count as unfinished", not services.unfinished())
        try:
            node.restart(U_TOR)
            refused = False
        except services.Busy:
            refused = True
        check("a restart asked for meanwhile is refused", refused and pids()[U_TOR] == before[U_TOR])
        applying.send_signal(signal.SIGKILL)
        applying.wait()
        check("after the kill the change counts as unfinished", wait_for(services.unfinished, 5))
        check("no file was replaced", "onlynet=onion" not in conf.read_text())
        (HOLD / U_BITCOIND).unlink()
        check("opening the app finishes it", node.on_launch() and wait_for(lambda: running() == set(ALL)))
        check("with the new file", "onlynet=onion" in conf.read_text())
        check("and nothing is left unfinished", not services.unfinished())

        print("\n5. systemd not answering")
        env = dict(os.environ)
        os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        os.environ["XDG_RUNTIME_DIR"] = "/nonexistent"
        try:
            node.apply_settings(net_mode="dual")
            said = ""
        except RuntimeError as e:
            said = str(e)
        finally:
            os.environ.clear()
            os.environ.update(env)
        check(f"is an error, not “nothing is running”: {said[:60]}…", "systemd did not say what is running" in said)
        check("no file was replaced", "onlynet=onion" in conf.read_text())
        services.apply()
        check("the next apply carries the change out", "onlynet=onion" not in conf.read_text()
              and wait_for(lambda: running() == set(ALL)) and not services.unfinished())

        print("\n6. Stopping everything (as before a restart of the computer)")
        LOG.unlink(missing_ok=True)
        services.stop_everything()
        check("everything is down, the agent included", running() == set())
        check("in this order: Mempool, Fulcrum, Bitcoin Core, Tor",
              [u for u, _ in order("stop") if u != U_AGENT] == [U_MEMPOOL, U_FULCRUM, U_BITCOIND, U_TOR])
        check("an apply is owed", services.unfinished())
        services.apply()
        check("which brings everything back", wait_for(lambda: running() == set(ALL)) and not services.unfinished())

        print("\n7. The same while Mempool is switched off and has no unit")
        rest = set(ALL) - {U_MEMPOOL}
        node.apply_settings(mempool_enabled=False)
        check("switching Mempool off stops it and nothing else", wait_for(lambda: running() == rest))
        (paths.UNIT_DIR / U_MEMPOOL).unlink()       # what Quadlet does once apply() has removed its files
        guarded("daemon-reload")
        answer = guarded("stop", U_MEMPOOL)
        check(f"asked to stop it, systemd answers with an error: …{(answer.stderr or '').strip()[-11:]}",
              answer.returncode == 5)
        LOG.unlink(missing_ok=True)
        try:
            services.stop_everything()
            said = ""
        except RuntimeError as e:
            said = str(e)
        check("stopping everything does not take that for a service that will not stop" + (f": {said}" if said else ""),
              not said)
        check("the rest went down in order: Fulcrum, Bitcoin Core, Tor",
              [u for u, _ in order("stop") if u != U_AGENT] == [U_FULCRUM, U_BITCOIND, U_TOR] and running() == set())
        services.apply()
        check("and comes back", wait_for(lambda: running() == rest) and not services.unfinished())

        print("\n8. Removal, with Mempool's unit still missing")
        services.remove_all()
        check("nothing runs", running() == set())
        check("the units are gone", not any((paths.UNIT_DIR / u).exists() for u in ALL if u != U_MEMPOOL))
        check("the node counts as not installed", not settings.load()["installed"])
    finally:
        remove_stand_ins()
        subprocess.run(["systemctl", "--user", "stop", f"{PREFIX}-sweep.timer"], capture_output=True)
        shutil.rmtree(ROOT, ignore_errors=True)
    left = subprocess.run(["systemctl", "--user", "list-units", "--all", "--no-legend", f"{PREFIX}-*"],
                          capture_output=True, text=True).stdout.strip()
    print(f"\n{sum(results)} of {len(results)} checks passed." + (f"\nStill known to systemd:\n{left}" if left else ""))
    return 0 if all(results) and not left else 1


if __name__ == "__main__":
    sys.exit(child(sys.argv[2:]) if sys.argv[1:2] == ["--apply"] else main())
