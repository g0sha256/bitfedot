"""Offline tests: config rendering, service orchestration, hardening rules,
verification, explorer helpers and migration. No network, no systemd, no root.

    python3 -m unittest discover tests
"""
import base64
import contextlib
import errno
import http.client
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

os.environ["BITFEDOT_ROOT"] = tempfile.mkdtemp(prefix="bitfedot-test-")

from bitfedot import (about, agent, apps, eta, explorer, hardening, installer, migrate, net, node,  # noqa: E402
                      paths, pins, rpc, selfupdate, services, settings, system, verify)
from bitfedot import hardware_keys as hk  # noqa: E402
from bitfedot import keyring_unlock, ykpins  # noqa: E402
from bitfedot.catalog import CATALOG, CATEGORIES  # noqa: E402
from bitfedot.paths import U_BITCOIND, U_FULCRUM, U_MEMPOOL, U_TOR  # noqa: E402


def cfg(**kw):
    """Settings of an installed node with every switch at its default, plus `kw`. Not stored,
    and — but for the generated passwords — not taken from what other tests stored."""
    secrets = settings.ensure_secrets()["secrets"]
    return {**settings.DEFAULTS, "secrets": secrets, "installed": True, "versions": {"mempool": "3.3.2"}, **kw}


def store(**kw):
    """Make the stored settings those of an installed node with every switch at its default,
    plus `kw` — apply() reads what is stored, never what a caller holds."""
    settings.ensure_secrets()
    plain = {k: v for k, v in settings.DEFAULTS.items() if not isinstance(v, dict)}
    return settings.update(**{**plain, "installed": True, "versions": {"mempool": "3.3.2"}, **kw})


class Systemd:
    """Stands in for `systemctl --user`: remembers what runs and records every call as
    (verb, unit). `refuse` makes a call fail the way systemd says so, `die_at` ends the
    process in the middle of one (the app closed, the power gone), `on` runs something
    at that moment. A unit it does not have — neither running nor with a file — gets the
    error the real one gives (noted from systemd 262, with a unit name nothing uses)."""

    class Killed(BaseException):
        pass

    NOT_THERE = {"stop": (5, "Failed to stop {0}: Unit {0} not loaded."),
                 "start": (5, "Failed to start {0}: Unit {0} not found."),
                 "restart": (5, "Failed to restart {0}: Unit {0} not found."),
                 "enable": (1, "Failed to enable unit: Unit {0} does not exist"),
                 "disable": (1, "Failed to disable unit: Unit {0} does not exist"),
                 "reset-failed": (1, "Failed to reset failed state of unit {0}: Unit {0} not loaded.")}

    def __init__(self, running=()):
        self.running, self.calls = set(running), []
        self.refuse, self.die_at, self.on = {}, None, {}

    def has(self, unit) -> bool:
        """Mempool's unit is generated from its Quadlet files and goes when they go."""
        if unit in self.running or (paths.UNIT_DIR / unit).exists():
            return True
        return unit == U_MEMPOOL and any(paths.QUADLET_DIR.glob("bitfedot-mempool*"))

    def systemctl(self, *args, **_kw):
        words = [a for a in args if not a.startswith("--")]
        call = (words[0], words[1] if len(words) > 1 else "")
        self.calls.append(call)
        if call == self.die_at:
            raise self.Killed(call)
        self.on.get(call, lambda: None)()
        if call in self.refuse:
            code, said = self.refuse[call] if isinstance(self.refuse[call], tuple) else (1, self.refuse[call])
            return subprocess.CompletedProcess(args, code, "", said)
        if call[0] in self.NOT_THERE and not self.has(call[1]):
            code, said = self.NOT_THERE[call[0]]
            return subprocess.CompletedProcess(args, code, "", said.format(call[1]))
        if call[0] == "stop" or (call[0] == "disable" and "--now" in args):
            self.running.discard(call[1])
        elif call[0] in ("start", "restart"):
            self.running.add(call[1])
        return subprocess.CompletedProcess(args, 0, "", "")

    def unit_states(self, units):
        return {u: "active" if u in self.running else "inactive" for u in units}

    def did(self, verb):
        """The node's services `verb` was asked for, in order."""
        return [unit for v, unit in self.calls if v == verb and unit in services.STOP_ORDER]

    def __enter__(self):
        self._patch = mock.patch.multiple(system, systemctl=self.systemctl, unit_states=self.unit_states)
        self._patch.start()
        return self

    def __exit__(self, *_exc):
        self._patch.stop()


class BitcoinConf(unittest.TestCase):
    def test_ibd_is_clearnet_and_fast(self):
        c = services.bitcoin_conf(cfg(phase="ibd", net_mode="tor_only"))
        self.assertIn("blocksonly=1", c)
        self.assertIn("listen=0", c)
        self.assertNotIn("proxy=", c)
        self.assertNotIn("txindex=1", c)

    def test_ibd_over_tor_when_requested(self):
        c = services.bitcoin_conf(cfg(phase="ibd", ibd_clearnet=False, net_mode="tor_only"))
        self.assertIn("onlynet=onion", c)
        self.assertIn("blocksonly=1", c)

    def test_tor_only_never_touches_clearnet(self):
        c = services.bitcoin_conf(cfg(phase="ready", net_mode="tor_only", listen_clearnet=True))
        for line in ("onlynet=onion", "dnsseed=0", "dns=0", "discover=0", "txindex=1"):
            self.assertIn(line, c)
        self.assertNotIn("bind=0.0.0.0", c)

    def test_dual_with_clearnet_inbound(self):
        c = services.bitcoin_conf(cfg(phase="ready", net_mode="dual", listen_clearnet=True))
        self.assertIn(f"onion=127.0.0.1:{paths.TOR_SOCKS}", c)
        self.assertIn("bind=0.0.0.0:8333", c)
        self.assertIn("bind=127.0.0.1:8334=onion", c)
        self.assertNotIn("\nproxy=", c)

    def test_clearnet_ignores_tor(self):
        c = services.bitcoin_conf(cfg(phase="ready", net_mode="clearnet", private_broadcast=True))
        self.assertIn("listenonion=0", c)
        self.assertNotIn("\nonion=", c)
        self.assertNotIn("privatebroadcast", c)      # needs Tor; would stop bitcoind from starting

    def test_private_broadcast_with_tor(self):
        c = services.bitcoin_conf(cfg(phase="ready", net_mode="dual", private_broadcast=True))
        self.assertIn("privatebroadcast=1", c)

    def test_node_never_holds_keys(self):
        for phase in ("ibd", "ready"):
            self.assertIn("disablewallet=1", services.bitcoin_conf(cfg(phase=phase)))

    def test_rpcauth_matches_bitcoin_core_scheme(self):
        self.assertEqual(
            services.rpcauth("u", "p", "abcd"),
            "rpcauth=u:abcd$" + __import__("hmac").new(b"abcd", b"p", "sha256").hexdigest())


class Units(unittest.TestCase):
    def test_nothing_but_bitcoind_during_clearnet_sync(self):
        d = services.desired_units(cfg(phase="ibd"))
        self.assertTrue(d[U_BITCOIND])
        self.assertFalse(d[U_TOR] or d[U_FULCRUM] or d[U_MEMPOOL])

    def test_everything_when_ready(self):
        self.assertTrue(all(services.desired_units(cfg(phase="ready")).values()))

    def test_stop_all_overrides_everything_but_the_agent(self):
        d = services.desired_units(cfg(phase="ready", all_stopped=True))
        self.assertEqual([u for u, v in d.items() if v], [paths.U_AGENT])

    def test_vpn_kill_switch_for_tor(self):
        d = services.desired_units(cfg(phase="ready", tor_route="vpn", vpn_iface="does-not-exist0"))
        self.assertFalse(d[U_TOR])

    def test_apply_is_idempotent(self):
        store(phase="ready")
        services.apply()
        self.assertEqual(services.apply(), set())
        self.assertTrue((paths.QUADLET_DIR / "bitfedot-mempool.pod").exists())
        settings.update(mempool_enabled=False)
        services.apply()
        self.assertFalse((paths.QUADLET_DIR / "bitfedot-mempool.pod").exists())
        self.assertEqual(services.activity(), "")
        self.assertFalse(services.unfinished())

    def test_apply_takes_no_settings(self):
        """It reads them itself, under its lock. A caller's copy may be older than what is stored."""
        with self.assertRaises(TypeError):
            services.apply(cfg(phase="ready"))

    def test_torrc_onion_services(self):
        t = services.torrc(cfg(phase="ready", onion_fulcrum=True))
        self.assertIn("HiddenServicePort 50001 127.0.0.1:50001", t)
        self.assertNotIn("hs_mempool", t)

    def test_sandbox_toggle(self):
        on = services.bitcoind_unit(cfg(phase="ready"))
        self.assertIn("ProtectSystem=strict", on)
        self.assertIn("ReadWritePaths=", on)
        self.assertNotIn("ProtectSystem", services.bitcoind_unit(cfg(phase="ready", sandbox=False)))
        self.assertIn("DropCapability=all", services.mempool_quadlets(cfg())["bitfedot-mempool-db.container"])

    def test_exec_arguments_with_spaces_are_quoted(self):
        unit = services.bitcoind_unit(cfg(data_dir="/run/media/me/My Disk/node"))
        self.assertIn('"-datadir=/run/media/me/My Disk/node/bitcoin"', unit)


class SafeOrdering(unittest.TestCase):
    """apply() must stop consumers before providers, wait, then start in reverse."""

    def run_apply(self, running, restart=(), **changes):
        with Systemd(running) as sd:
            if changes:
                settings.update(**changes)
            services.apply(restart=restart)
        return sd.did("stop"), sd.did("start")

    def setUp(self):
        store(phase="ready")
        services.apply()                             # files on disk match: no change pending
        self.all = {U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL}

    def test_no_change_touches_nothing(self):
        self.assertEqual(self.run_apply(self.all), ([], []))

    def test_bitcoind_restart_cycles_dependents_in_order(self):
        stops, starts = self.run_apply(self.all, restart=[U_BITCOIND])
        self.assertEqual(stops, [U_MEMPOOL, U_FULCRUM, U_BITCOIND])
        self.assertEqual(starts, [U_BITCOIND, U_FULCRUM, U_MEMPOOL])

    def test_tor_restart_leaves_the_rest_alone(self):
        stops, starts = self.run_apply(self.all, restart=[U_TOR])
        self.assertEqual((stops, starts), ([U_TOR], [U_TOR]))

    def test_stop_all_then_start_all(self):
        stops, starts = self.run_apply(self.all, all_stopped=True)
        self.assertEqual(stops, [U_MEMPOOL, U_FULCRUM, U_BITCOIND, U_TOR])
        self.assertEqual(starts, [])
        stops, starts = self.run_apply(set(), all_stopped=False)
        self.assertEqual(stops, [])
        self.assertEqual(starts, [U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL])

    def test_stopping_bitcoind_takes_dependents_down_first(self):
        stops, _ = self.run_apply(self.all, bitcoind_enabled=False)
        self.assertEqual(stops, [U_MEMPOOL, U_FULCRUM, U_BITCOIND])

    def test_a_file_is_replaced_only_once_its_reader_is_down(self):
        """However an apply ends, what runs must match what is on disk."""
        seen = {}
        with Systemd(self.all) as sd:
            sd.on[("stop", U_BITCOIND)] = lambda: seen.update(at_stop=paths.BITCOIN_CONF.read_text())
            sd.on[("start", U_BITCOIND)] = lambda: seen.update(at_start=paths.BITCOIN_CONF.read_text())
            node.apply_settings(net_mode="tor_only")
        self.assertNotIn("onlynet=onion", seen["at_stop"])
        self.assertIn("onlynet=onion", seen["at_start"])


class CutShort(unittest.TestCase):
    """A change that is interrupted — the app closed, the power gone — must leave nothing
    running on other configuration than the files hold, and must still be carried out."""

    def setUp(self):
        self.all = {U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL}
        store(phase="ready", net_mode="dual")
        services.apply()
        self.addCleanup(paths.APPLY_PENDING.unlink, missing_ok=True)

    def test_while_services_were_being_stopped(self):
        before = paths.BITCOIN_CONF.read_text()
        with Systemd(self.all) as sd:
            sd.die_at = ("stop", U_FULCRUM)
            with self.assertRaises(Systemd.Killed):
                node.apply_settings(net_mode="tor_only")
            self.assertEqual(paths.BITCOIN_CONF.read_text(), before)    # Bitcoin Core still runs — on this file
            self.assertIn(U_BITCOIND, sd.running)
            self.assertTrue(services.unfinished())
            sd.die_at, sd.calls = None, []
            services.apply()                                            # whoever comes next: the agent, the app
            self.assertEqual(sd.did("stop"), [U_FULCRUM, U_BITCOIND])
            self.assertEqual(sd.did("start"), [U_BITCOIND, U_FULCRUM, U_MEMPOOL])
        self.assertIn("onlynet=onion", paths.BITCOIN_CONF.read_text())
        self.assertFalse(services.unfinished())

    def test_after_the_files_were_written(self):
        with Systemd(self.all) as sd:
            sd.die_at = ("daemon-reload", "")
            with self.assertRaises(Systemd.Killed):
                node.apply_settings(net_mode="tor_only")
            self.assertIn("onlynet=onion", paths.BITCOIN_CONF.read_text())     # written …
            self.assertEqual(sd.running, {U_TOR})                               # … with everything that reads it down
            self.assertTrue(services.unfinished())
            sd.die_at, sd.calls = None, []
            self.assertEqual(services.apply(), set())                   # the files match: nothing looks changed,
            self.assertEqual(sd.did("stop"), [])
            self.assertEqual(sd.did("start"), [U_BITCOIND, U_FULCRUM, U_MEMPOOL])   # and still it all comes back
        self.assertFalse(services.unfinished())

    def test_a_restart_owed_after_an_update_is_not_forgotten(self):
        with Systemd(self.all) as sd:
            sd.die_at = ("stop", U_MEMPOOL)
            with self.assertRaises(Systemd.Killed):
                services.apply(restart=[U_BITCOIND])                    # a new Bitcoin Core was just installed
            sd.die_at, sd.calls = None, []
            self.assertEqual(services.apply(), {U_BITCOIND})            # an apply that was told of no restart
            self.assertEqual(sd.did("stop"), [U_MEMPOOL, U_FULCRUM, U_BITCOIND])
            sd.calls = []
            self.assertEqual(services.apply(), set())                   # owed once, not for ever
            self.assertEqual(sd.did("stop"), [])

    def test_the_agent_finishes_it_and_keeps_trying(self):
        with Systemd(self.all) as sd, mock.patch.object(system, "notify", return_value=True) as notify, \
                contextlib.redirect_stdout(io.StringIO()) as log:
            sd.die_at = ("stop", U_BITCOIND)
            with self.assertRaises(Systemd.Killed):
                node.apply_settings(net_mode="tor_only")                # Mempool and Fulcrum are down by now
            sd.die_at, sd.calls = None, []
            sd.refuse[("stop", U_BITCOIND)] = "Job for bitfedot-bitcoind.service canceled."
            state = {}
            agent.finish_unfinished(state)                              # Bitcoin Core will not stop
            agent.finish_unfinished(state)                              # too soon to try again
            self.assertEqual(sd.did("stop"), [U_BITCOIND])
            notify.assert_called_once()
            self.assertIn("Bitcoin Core could not be stopped", notify.call_args.args[1])
            state["finish_next"] = 0
            agent.finish_unfinished(state)                              # the same reason is not announced twice
            notify.assert_called_once()
            agent.finish_unfinished({"finish_next": 0}, announce_failure=False)   # notifications switched off
            notify.assert_called_once()
            sd.refuse.clear()
            state["finish_next"] = 0
            agent.finish_unfinished(state)
            self.assertTrue(self.all <= sd.running)
            self.assertNotIn("finish_error", state)
        self.assertIn("onlynet=onion", paths.BITCOIN_CONF.read_text())
        self.assertFalse(services.unfinished())
        self.assertIn("agent: the change is complete", log.getvalue())

    def test_the_agent_does_it_on_its_round(self):
        with Systemd(self.all) as sd, contextlib.redirect_stdout(io.StringIO()):
            sd.die_at = ("stop", U_FULCRUM)
            with self.assertRaises(Systemd.Killed):
                node.apply_settings(all_stopped=True)                   # "Stop all", cut short
            sd.die_at = None
            agent.tick({})                                              # everything is meant to be stopped: also then
            self.assertEqual(sd.running & self.all, set())
        self.assertFalse(services.unfinished())

    def test_opening_the_app_finishes_it_too(self):
        with Systemd(self.all) as sd:
            self.assertFalse(node.on_launch())                          # nothing was cut short
            sd.die_at = ("stop", U_FULCRUM)
            with self.assertRaises(Systemd.Killed):
                node.apply_settings(net_mode="tor_only")
            sd.die_at = None
            self.assertEqual(node.snapshot()["pending"], services.UNFINISHED_NOTE)     # the banner, with its button
            self.assertTrue(node.on_launch())
            self.assertTrue(self.all <= sd.running)
        self.assertEqual(node.snapshot()["pending"], "")

    def test_opening_the_app_still_starts_a_node_that_was_shut_down(self):
        settings.update(all_stopped=True, resume_on_launch=True)        # "Shut down the node", then quit
        with Systemd() as sd:
            self.assertTrue(node.on_launch())
            self.assertTrue(self.all <= sd.running)
        s = settings.load()
        self.assertFalse(s["all_stopped"] or s["resume_on_launch"])

    def test_an_apply_that_is_still_running_is_not_an_unfinished_one(self):
        with Systemd(self.all) as sd:
            seen = []
            sd.on[("stop", U_BITCOIND)] = lambda: seen.append((services.unfinished(), services.activity()))
            node.apply_settings(net_mode="tor_only")
        self.assertEqual(seen, [(False, "Stopping Bitcoin Core safely… (flushing to disk, this can take a few minutes)")])


class Refused(unittest.TestCase):
    """What systemd refuses must not pass silently, and must not leave a change half applied."""

    def setUp(self):
        self.all = {U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL}
        store(phase="ready", net_mode="dual")
        services.apply()
        self.addCleanup(paths.APPLY_PENDING.unlink, missing_ok=True)

    def test_a_service_that_does_not_stop_ends_the_change_before_any_file_is_replaced(self):
        before = paths.BITCOIN_CONF.read_text()
        with Systemd(self.all) as sd:
            sd.refuse[("stop", U_FULCRUM)] = "Job for bitfedot-fulcrum.service canceled."
            with self.assertRaises(RuntimeError) as failure:
                node.apply_settings(net_mode="tor_only")
            self.assertIn("Fulcrum could not be stopped (Job for bitfedot-fulcrum.service canceled.)",
                          str(failure.exception))
            self.assertEqual(sd.did("stop"), [U_MEMPOOL, U_FULCRUM])    # Bitcoin Core is not taken down under it
            self.assertEqual(sd.did("start"), [])
            self.assertEqual(paths.BITCOIN_CONF.read_text(), before)
            self.assertTrue(services.unfinished())
            sd.refuse.clear()
            sd.calls = []
            services.apply()
            self.assertEqual(sd.did("stop"), [U_FULCRUM, U_BITCOIND])
            self.assertEqual(sd.did("start"), [U_BITCOIND, U_FULCRUM, U_MEMPOOL])
        self.assertIn("onlynet=onion", paths.BITCOIN_CONF.read_text())
        self.assertFalse(services.unfinished())

    def test_a_stop_that_gets_no_answer_in_time_is_a_failure_too(self):
        with Systemd(self.all) as sd:
            sd.refuse[("stop", U_BITCOIND)] = (124, "systemctl: timed out")     # what system.run reports
            with self.assertRaises(RuntimeError) as failure:
                services.apply(restart=[U_BITCOIND])
            self.assertIn(f"Bitcoin Core could not be stopped (no answer after {services.STOP_TIMEOUT[U_BITCOIND]} "
                          "seconds)", str(failure.exception))
            self.assertEqual(sd.did("start"), [])                       # not started on top of a stop still under way

    def test_systemd_not_answering_changes_nothing(self):
        before = paths.BITCOIN_CONF.read_text()
        silent = RuntimeError("systemd did not say what is running (Failed to connect to bus)")
        with Systemd(self.all) as sd, mock.patch.object(system, "unit_states", side_effect=silent):
            with self.assertRaises(RuntimeError):
                node.apply_settings(net_mode="tor_only")
            self.assertEqual(sd.calls, [])
        self.assertEqual(paths.BITCOIN_CONF.read_text(), before)
        self.assertTrue(services.unfinished())

    def test_no_answer_is_never_read_as_nothing_is_running(self):
        def answer(stdout, stderr=""):
            return mock.patch.object(system, "run", return_value=subprocess.CompletedProcess([], 3, stdout, stderr))
        with mock.patch.object(system, "DRY_RUN", False):
            with answer("active\ninactive\n"):
                self.assertEqual(system.unit_states([U_TOR, U_FULCRUM]), {U_TOR: "active", U_FULCRUM: "inactive"})
            with answer("", "Failed to connect to user scope bus via local transport: No such file or directory"):
                with self.assertRaises(RuntimeError) as failure:
                    system.unit_states([U_TOR, U_FULCRUM])
        self.assertIn("Failed to connect to user scope bus", str(failure.exception))

    def test_a_service_that_was_started_behind_its_back_ends_the_change(self):
        before = (paths.UNIT_DIR / U_BITCOIND).read_text()
        with Systemd(self.all) as sd:
            sd.on[("stop", U_TOR)] = lambda: sd.running.add(U_BITCOIND)     # say, a `systemctl start` by hand
            with self.assertRaises(RuntimeError) as failure:
                node.apply_settings(sandbox=False)                      # changes every unit
            self.assertIn("Bitcoin Core started again", str(failure.exception))
            self.assertEqual(sd.did("start"), [])
        self.assertEqual((paths.UNIT_DIR / U_BITCOIND).read_text(), before)
        self.assertTrue(services.unfinished())

    def test_a_refused_start_is_reported_once_the_rest_was_started(self):
        with Systemd() as sd:
            sd.refuse[("start", U_FULCRUM)] = "Failed to start bitfedot-fulcrum.service: Unit is masked."
            with self.assertRaises(RuntimeError) as failure:
                services.apply()
            self.assertIn("Fulcrum could not be started (Failed to start bitfedot-fulcrum.service: Unit is masked.)",
                          str(failure.exception))
            self.assertEqual(sd.did("start"), [U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL])    # Mempool all the same
            self.assertIn(paths.U_AGENT, sd.running)
            self.assertTrue(services.unfinished())
            sd.refuse.clear()
            services.apply()
            self.assertIn(U_FULCRUM, sd.running)
        self.assertFalse(services.unfinished())

    def test_a_reload_that_systemd_refuses_is_reported(self):
        with Systemd(self.all) as sd:
            sd.refuse[("daemon-reload", "")] = "Failed to reload daemon: Access denied"
            with self.assertRaises(RuntimeError) as failure:
                node.apply_settings(net_mode="tor_only")
            self.assertIn("systemd did not load it (Failed to reload daemon: Access denied)", str(failure.exception))
            self.assertEqual(sd.did("start"), [])
        self.assertTrue(services.unfinished())

    def test_a_reboot_is_called_off_when_a_service_does_not_stop(self):
        with Systemd(self.all | {paths.U_AGENT}) as sd, mock.patch.object(system, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()):
            sd.refuse[("stop", U_BITCOIND)] = "Job for bitfedot-bitcoind.service canceled."
            with self.assertRaises(RuntimeError):
                node.safe_reboot()
            run.assert_not_called()                                     # no `systemctl reboot`
            self.assertIn(paths.U_AGENT, sd.running)                    # the agent is back, and it has work to do:
            self.assertTrue(services.unfinished())
            sd.refuse.clear()
            agent.finish_unfinished({})
            self.assertTrue(self.all <= sd.running)
        self.assertFalse(services.unfinished())

    def test_the_node_comes_back_if_the_computer_does_not_restart_after_all(self):
        with Systemd(self.all | {paths.U_AGENT}) as sd, \
                mock.patch.object(system, "run", side_effect=RuntimeError("Access denied")):
            with self.assertRaises(RuntimeError):
                node.safe_reboot()
            self.assertTrue(self.all | {paths.U_AGENT} <= sd.running)
        self.assertFalse(services.unfinished())

    def test_after_the_reboot_the_apply_that_is_owed_changes_nothing(self):
        with Systemd(self.all | {paths.U_AGENT}) as sd, mock.patch.object(system, "run"), \
                contextlib.redirect_stdout(io.StringIO()):
            node.safe_reboot()
            self.assertEqual(sd.running, set())
            sd.running, sd.calls = self.all | {paths.U_AGENT}, []      # back up: systemd has started everything
            agent.finish_unfinished({})
            self.assertEqual((sd.did("stop"), sd.did("start")), ([], []))
        self.assertFalse(services.unfinished())

    def test_a_service_that_has_no_unit_is_not_one_that_does_not_stop(self):
        """Mempool has no unit while it is switched off; asked to stop it, systemd answers with an
        error. Stopping everything stops the rest and does not take that for a refusal."""
        with Systemd(self.all | {paths.U_AGENT}) as sd:
            node.apply_settings(mempool_enabled=False)                  # stops it, and its Quadlet files go
            self.assertEqual(sd.systemctl("stop", U_MEMPOOL).returncode, 5)
            sd.calls.clear()
            with mock.patch.object(system, "run") as run:
                node.safe_reboot()
            self.assertEqual(sd.did("stop"), [U_FULCRUM, U_BITCOIND, U_TOR])
            self.assertEqual(sd.running, set())
            run.assert_called_once()                                    # `systemctl reboot`

    def test_a_node_that_is_still_syncing_can_be_removed(self):
        """During the first sync Fulcrum has a unit but does not run, and Mempool has none."""
        store(phase="ibd")
        with Systemd() as sd:
            services.apply()
            self.assertEqual(sd.running, {U_BITCOIND, paths.U_AGENT})
            self.assertFalse(sd.has(U_MEMPOOL))
            sd.calls.clear()
            services.remove_all()
            self.assertEqual(sd.did("stop"), [U_BITCOIND])
            self.assertEqual(sd.running, set())
        self.assertFalse(settings.load()["installed"])
        self.assertFalse((paths.UNIT_DIR / U_BITCOIND).exists())
        self.assertFalse(services.unfinished())

    def test_nothing_is_stopped_if_the_agent_cannot_be(self):
        """Left running, it would start the services again behind the back of whoever stops them."""
        with Systemd(self.all | {paths.U_AGENT}) as sd, mock.patch.object(system, "run") as run:
            sd.refuse[("stop", paths.U_AGENT)] = ("Failed to stop bitfedot-agent.service: "
                                                  "Transport endpoint is not connected")
            with self.assertRaises(RuntimeError) as failure:
                node.safe_reboot()
            self.assertIn("background agent could not be stopped", str(failure.exception))
            self.assertEqual(sd.did("stop"), [])
            self.assertTrue(self.all | {paths.U_AGENT} <= sd.running)
            run.assert_not_called()

    def test_stopping_everything_pays_a_restart_that_was_owed(self):
        """A restart left over from an update is not carried out a second time after the reboot."""
        with Systemd(self.all | {paths.U_AGENT}) as sd, mock.patch.object(system, "run"), \
                contextlib.redirect_stdout(io.StringIO()):
            services._mark_unfinished({U_BITCOIND})
            node.safe_reboot()
            self.assertTrue(services.unfinished())                      # the node still has to come back
            sd.running, sd.calls = self.all | {paths.U_AGENT}, []      # back up: systemd has started everything
            agent.finish_unfinished({})
            self.assertEqual((sd.did("stop"), sd.did("start")), ([], []))
        self.assertFalse(services.unfinished())

    def test_a_service_that_was_started_behind_its_back_ends_the_removal(self):
        with Systemd(self.all | {paths.U_AGENT}) as sd:
            sd.on[("stop", U_TOR)] = lambda: sd.running.add(U_FULCRUM)      # say, a `systemctl start` by hand
            with self.assertRaises(RuntimeError) as failure:
                services.remove_all()
            self.assertIn("Fulcrum started again", str(failure.exception))
            self.assertIn("Nothing was removed.", str(failure.exception))
            self.assertTrue(settings.load()["installed"])
            self.assertTrue((paths.UNIT_DIR / U_FULCRUM).exists())
            self.assertIn(paths.U_AGENT, sd.running)
        self.assertTrue(services.unfinished())

    def test_a_node_that_does_not_stop_is_not_removed(self):
        with Systemd(self.all | {paths.U_AGENT}) as sd:
            sd.refuse[("stop", U_FULCRUM)] = "Job for bitfedot-fulcrum.service canceled."
            with self.assertRaises(RuntimeError) as failure:
                services.remove_all()
            self.assertIn("Fulcrum could not be stopped (Job for bitfedot-fulcrum.service canceled.). "
                          "Nothing was removed.", str(failure.exception))
            self.assertTrue(settings.load()["installed"])
            self.assertTrue((paths.UNIT_DIR / U_BITCOIND).exists())
            self.assertIn(paths.U_AGENT, sd.running)                    # it brings Mempool back
            self.assertTrue(services.unfinished())
            sd.refuse.clear()
            services.remove_all()
            self.assertEqual(sd.running, set())
        self.assertFalse(settings.load()["installed"])
        self.assertFalse((paths.UNIT_DIR / U_BITCOIND).exists())
        self.assertFalse(services.unfinished())

    def test_a_restart_is_refused_while_a_change_is_being_applied(self):
        with Systemd(self.all) as sd:
            with services._apply_lock(), mock.patch.object(services.time, "sleep"):
                with self.assertRaises(services.Busy):
                    node.restart(U_BITCOIND)                            # it could come up on files about to change
            self.assertEqual(sd.calls, [])
            node.restart(U_BITCOIND)
            self.assertEqual(sd.calls, [("restart", U_BITCOIND)])
            sd.refuse[("restart", U_TOR)] = "Failed to restart bitfedot-tor.service: Unit not found."
            with self.assertRaises(RuntimeError):
                node.tor_reconnect()


class LatestSettings(unittest.TestCase):
    """Whoever gets to apply, applies what is stored at that moment — never an older copy."""

    def setUp(self):
        self.addCleanup(paths.APPLY_PENDING.unlink, missing_ok=True)

    def test_what_the_agent_read_earlier_does_not_undo_a_change_made_since(self):
        store(phase="ready", tor_route="vpn", vpn_iface="wg0", status_notifications=False, auto_check_updates=False)
        vpn = [("10.2.0.2", None)]

        def the_user_switches_tor_to_direct(*_announcement):
            node.apply_settings(tor_route="direct")                     # saved and applied before the agent's turn
            return True
        with Systemd({U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL}) as sd, \
                mock.patch.object(system, "vpn_addresses", side_effect=lambda _iface: vpn[0]), \
                mock.patch.object(system, "notify", side_effect=the_user_switches_tor_to_direct):
            services.apply()
            self.assertIn("OutboundBindAddress 10.2.0.2", paths.TORRC.read_text())
            vpn[0] = (None, None)                                       # the VPN drops; the agent has read the settings …
            agent.tick({"vpn": ("10.2.0.2", None)})                     # … and applies after the user did
            self.assertIn(U_TOR, sd.running)                            # with the old copy Tor would be stopped: no VPN
        self.assertEqual(paths.TORRC.read_text(), services.torrc(settings.load()))
        self.assertNotIn("OutboundBindAddress", paths.TORRC.read_text())

    def test_changes_saved_one_after_the_other_are_all_applied_whoever_goes_first(self):
        store(phase="ready", net_mode="dual")
        services.apply()
        settings.update(net_mode="tor_only")                            # saved by one caller,
        settings.update(private_broadcast=True)                         # then by another, whose apply() runs first
        services.apply()
        services.apply()
        conf = paths.BITCOIN_CONF.read_text()
        self.assertIn("onlynet=onion", conf)
        self.assertIn("privatebroadcast=1", conf)

    def test_switching_autostart_writes_nothing_a_service_reads(self):
        store(phase="ready", net_mode="dual")
        services.apply()
        before = paths.BITCOIN_CONF.read_text()
        s = settings.update(net_mode="tor_only", autostart=False)       # saved; not applied yet
        services.write_autostart(s)
        self.assertFalse((paths.AUTOSTART_DIR / f"{paths.APP_ID}.desktop").exists())
        self.assertEqual(paths.BITCOIN_CONF.read_text(), before)
        with Systemd({U_BITCOIND}) as sd:
            services.apply()
            self.assertEqual(sd.did("stop"), [U_BITCOIND])              # so the change is still seen, and carried out


class Hardening(unittest.TestCase):
    def test_killswitch_rules(self):
        rules = hardening.killswitch_rules("wg0", allow_lan=False, endpoints="198.51.100.7 2001:db8::/32")
        self.assertIn('oifname "wg0" accept', rules)
        self.assertIn("198.51.100.7/32", rules)
        self.assertIn("2001:db8::/32", rules)
        self.assertNotIn("192.168.0.0/16", rules)
        self.assertTrue(rules.rstrip().endswith("}"))
        self.assertIn("192.168.0.0/16", hardening.killswitch_rules("wg0", allow_lan=True))

    def test_killswitch_rejects_hostile_input(self):
        for iface in ("", "wg0; reboot", 'x" accept', "a" * 16):
            with self.assertRaises(ValueError):
                hardening.killswitch_rules(iface)
        with self.assertRaises(ValueError):
            hardening.killswitch_rules("wg0", endpoints="1.2.3.4; nft flush ruleset")

    def test_firewall_script_follows_inbound_setting(self):
        closed = hardening.firewall_script(cfg(phase="ready"), True, "FedoraWorkstation")
        self.assertIn("firewall-cmd --permanent --zone=bitfedot --remove-port=8333/tcp", closed)
        opened = hardening.firewall_script(cfg(phase="ready", listen_clearnet=True, fw_allow_ssh=True),
                                           True, "FedoraWorkstation")
        self.assertIn("firewall-cmd --permanent --zone=bitfedot --add-port=8333/tcp", opened)
        self.assertIn("firewall-cmd --permanent --zone=bitfedot --add-service=ssh", opened)
        back = hardening.firewall_script(cfg(fw_prev_zone="public; rm -rf /"), False, "bitfedot")
        self.assertIn("--set-default-zone=FedoraWorkstation", back[0])   # hostile zone name ignored

    def test_dnf_output_parsing(self):
        out = "kernel.x86_64    7.3.4-300.fc45    updates\nfirefox.x86_64   150.0-1.fc45      updates\n"
        self.assertEqual(hardening._count_packages(out), 2)
        self.assertEqual(hardening._count_packages(""), 0)


class Explorer(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(explorer.classify(" 840000 "), ("height", 840000))
        self.assertEqual(explorer.classify("A" * 64), ("hash", "a" * 64))
        self.assertEqual(explorer.classify("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")[0], "address")
        self.assertEqual(explorer.classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")[0], "address")
        self.assertEqual(explorer.classify("../../etc/passwd"), (None, None))

    def test_pool_logos_come_from_this_nodes_own_mempool_and_nowhere_else(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><circle cx="4" cy="4" r="3"/></svg>'
        asked = []

        class Reply:
            def __init__(self, kind, body):
                self.headers, self.body = {"Content-Type": kind}, body

            def read(self, amount=None):
                return self.body[:amount]

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        def urlopen(request, timeout=None):
            asked.append(request.full_url)
            name = request.full_url.rsplit("/", 1)[1]
            if name in ("foundryusa.svg", "default.svg"):
                return Reply("image/svg+xml", svg + b"<!-- " + name.encode() + b" -->")
            return Reply("text/html", b"<!doctype html><html></html>")     # Mempool's answer to an unknown name

        with mock.patch.object(explorer, "_logos", {}), \
                mock.patch.object(explorer.urllib.request, "urlopen", side_effect=urlopen):
            logo = explorer.pool_logo({"id": 111, "name": "Foundry USA", "slug": "foundryusa"})
            self.assertTrue(logo.startswith(b"<svg") and b"foundryusa.svg" in logo)
            explorer.pool_logo({"slug": "foundryusa"})
            self.assertEqual(asked, [explorer.BASE + "/resources/mining-pools/foundryusa.svg"])   # remembered
            self.assertIn(b"default.svg", explorer.pool_logo({"slug": "trustpool"}))    # no logo: the generic one
            count = len(asked)
            # A name that could leave the folder, or is no name at all, never reaches a URL.
            for odd in ({"slug": "../../api/v1/blocks"}, {"slug": "Foundry USA"}, {"slug": "a/b"},
                        {"slug": ""}, {"slug": None}, {"slug": 7}, {}, None):
                self.assertIn(b"default.svg", explorer.pool_logo(odd), odd)
            self.assertEqual(len(asked), count)
            self.assertTrue(all(url.startswith(explorer.BASE + "/resources/mining-pools/") for url in asked))

        with mock.patch.object(explorer, "_logos", {}), \
                mock.patch.object(explorer.urllib.request, "urlopen", side_effect=OSError("refused")) as down:
            self.assertIsNone(explorer.pool_logo({"slug": "antpool"}))                  # Mempool is not up yet
            self.assertIsNone(explorer.pool_logo({"slug": "antpool"}))
            self.assertEqual(down.call_count, 2)                                        # … so it is asked again
        huge = Reply("image/svg+xml", b"<svg>" + b" " * explorer.LOGO_MAX + b"</svg>")
        with mock.patch.object(explorer, "_logos", {}), \
                mock.patch.object(explorer.urllib.request, "urlopen", return_value=huge):
            self.assertIsNone(explorer.pool_logo({"slug": "antpool"}))                  # absurdly large: not a logo
        for block in explorer.demo_overview()["blocks"]:                                # the sample data has the shape
            self.assertRegex(block["extras"]["pool"]["slug"], explorer._SLUG)
            self.assertTrue(block["extras"]["pool"]["name"])

    def test_a_logo_is_drawn_sharp_and_a_broken_one_is_no_crash(self):
        try:
            from bitfedot.ui import widgets
        except (ImportError, ValueError):
            self.skipTest("PyGObject is not available")
        tall = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 76"><circle cx="16" cy="38" r="12"/></svg>'
        self.assertIsNone(widgets.svg_texture(b"<!doctype html><html></html>", 22))
        self.assertIsNone(widgets.svg_texture(b"", 22))
        texture = widgets.svg_texture(tall, 22)
        if texture is None:
            self.skipTest("no SVG loader on this system")
        self.assertEqual(texture.get_height(), 44)                 # twice the shown size, for dense screens
        self.assertLess(texture.get_width(), 44)                   # … and never stretched

    def test_tx_math(self):
        t = {"weight": 400, "fee": 500, "vin": [{"prevout": {"scriptpubkey_address": "A", "value": 1500}}],
             "vout": [{"scriptpubkey_address": "B", "value": 700}, {"scriptpubkey_address": "A", "value": 300}]}
        self.assertEqual(explorer.tx_summary(t), {"vsize": 100.0, "out": 1000, "fee": 500,
                                                  "coinbase": False, "rate": 5.0})
        self.assertEqual(explorer.address_delta(t, "A"), -1200)
        self.assertEqual(explorer.address_delta(t, "B"), 700)

    def test_demo_data_has_the_live_shape(self):
        d = explorer.demo_overview()
        self.assertEqual(set(d), {"fees", "mempool", "next", "blocks", "difficulty"})
        self.assertIn("medianFee", d["blocks"][0]["extras"])


class Apps(unittest.TestCase):
    def test_catalog_is_consistent(self):
        ids = [a.id for a in CATALOG]
        self.assertEqual(len(ids), len(set(ids)))
        for a in CATALOG:
            self.assertIn(a.category, CATEGORIES, a.id)
            self.assertIn(a.kind, ("archive", "apt", "flatpak", "dnf"), a.id)
            self.assertTrue(a.fingerprints and all(len(f) == 40 for f in a.fingerprints), a.id)
            self.assertTrue(list((paths.KEYS_DIR / a.key_dir).iterdir()), f"{a.id}: no pinned key shipped")
            self.assertTrue(a.homepage.startswith("https://") and a.license and a.signer, a.id)

    def test_pinned_fingerprints_match_the_shipped_keys(self):
        """Each catalog fingerprint must be a primary key in that app's key files."""
        for a in CATALOG:
            shipped = set(verify.primary_fingerprints((paths.KEYS_DIR / a.key_dir).iterdir()))
            self.assertEqual(shipped & set(a.fingerprints), set(a.fingerprints), a.id)

    def test_sparrow_config_is_merged_not_replaced(self):
        apps.SPARROW_HOME.mkdir(parents=True, exist_ok=True)
        (apps.SPARROW_HOME / "config").write_text(json.dumps({"theme": "DARK", "useProxy": True}))
        apps.configure_sparrow()
        c = json.loads((apps.SPARROW_HOME / "config").read_text())
        self.assertEqual(c["theme"], "DARK")                        # user's own setting survives
        self.assertEqual(c["electrumServer"], "tcp://127.0.0.1:50001|BitFedot node")
        self.assertFalse(c["useProxy"])
        self.assertTrue((apps.SPARROW_HOME / "config.before-bitfedot").exists())

    def test_dnf_repository_pins_the_key(self):
        text = apps.dnf_repo_text(apps.get("librewolf"))
        self.assertIn("gpgcheck=1", text)
        self.assertIn("repo_gpgcheck=1", text)
        self.assertIn("gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bitfedot-librewolf", text)
        script = "\n".join(apps.dnf_install_script(apps.get("mullvad"), upgrade=False))
        self.assertIn("BEGIN PGP PUBLIC KEY BLOCK", script)         # key comes from our pinned copy
        self.assertIn("dnf install -y --refresh mullvad-vpn", script)
        self.assertEqual(apps.dnf_install_script(apps.get("mullvad"), upgrade=True),
                         ["dnf upgrade -y --refresh mullvad-vpn"])

    def test_debian_release_and_package_parsing(self):
        release = "Origin: x\nMD5Sum:\n aa 10 main/binary-amd64/Packages.gz\nSHA256:\n" \
                  " BEEF 10 main/binary-amd64/Packages.gz\n cafe 9 main/binary-arm64/Packages.gz\n"
        self.assertEqual(apps._release_sha256(release, "main/binary-amd64/Packages.gz"), "beef")
        with self.assertRaises(verify.VerificationError):
            apps._release_sha256(release, "main/binary-riscv64/Packages.gz")
        paths.ensure_dirs()
        deb = paths.DATA_DIR / "t.deb"

        def member(name, data):
            return f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode() + data \
                + (b"\n" if len(data) % 2 else b"")
        deb.write_bytes(b"!<arch>\n" + member("debian-binary", b"2.0\n") + member("control.tar.xz", b"abc")
                        + member("data.tar.xz", b"PAYLOAD"))
        offset, size, name = apps.deb_data_member(deb)
        self.assertEqual((size, name, deb.read_bytes()[offset:offset + size]), (7, "data.tar.xz", b"PAYLOAD"))

    def test_status_reflects_what_the_app_needs(self):
        s = cfg(phase="ibd", versions={"sparrow": "2.5.6", "element": "1.0"})
        self.assertFalse(apps.status("sparrow", s)["ready"])        # needs Fulcrum, i.e. a synced node
        self.assertTrue(apps.status("element", s)["ready"])
        self.assertTrue(apps.status("sparrow", {**s, "phase": "ready"})["ready"])
        # Synced, Fulcrum switched on — but it opens its port only once its index is complete.
        # Sparrow can be opened, and the page says why it will not connect yet.
        ready = {**s, "phase": "ready"}
        building = apps.status("sparrow", ready, {"state": "syncing", "progress": 0.804})
        self.assertTrue(building["ready"])
        self.assertIn("cannot connect to your node yet", building["note"])
        self.assertIn("building its index (80%)", building["note"])
        self.assertEqual(apps.status("sparrow", ready, {"state": "running", "height": 976_315})["note"], "")
        self.assertIn("Fulcrum has failed", apps.status("sparrow", ready, {"state": "error"})["note"])
        self.assertIn("Fulcrum is starting", apps.status("sparrow", ready, {"state": "starting"})["note"])
        self.assertEqual(apps.status("element", ready, {"state": "syncing", "progress": 0.1})["note"], "")
        self.assertEqual(apps.status("mullvad", s)["installed"], "")


class SyncEstimate(unittest.TestCase):
    def test_later_transactions_cost_more(self):
        naive = (1 - 0.06) / 2e-5
        self.assertGreater(eta.remaining_seconds(0.06, 2e-5, dbcache_mb=24000), naive)
        small = eta.remaining_seconds(0.06, 2e-5, dbcache_mb=4000)
        self.assertGreater(small, eta.remaining_seconds(0.06, 2e-5, dbcache_mb=24000))
        self.assertGreater(eta.remaining_seconds(0.06, 2e-5, dbcache_mb=4000, rotational=True), small)

    def test_speed_measured_in_the_slow_phase_is_not_penalised_twice(self):
        # 1 % left, all of it signature-checked at the measured speed: plain division.
        self.assertAlmostEqual(eta.remaining_seconds(0.99, 1e-5, dbcache_mb=10**9), 0.01 / 1e-5, places=3)

    def test_rate_needs_continuous_history(self):
        steady = [(1000 + i * 60, 0.10 + i * 0.0012) for i in range(20)]
        self.assertAlmostEqual(eta.measured_rate(steady, now=steady[-1][0]), 2e-5)
        self.assertIsNone(eta.measured_rate(steady[:2], now=steady[1][0]))         # too short
        restarted = steady[:10] + [(9000, 0.2), (9060, 0.2006), (9200, 0.202)]
        self.assertAlmostEqual(eta.measured_rate(restarted, now=9200), 0.002 / 200)  # only since restart
        self.assertIsNone(eta.remaining_seconds(0.5, None, 4000))

    def test_cache_overflow_point(self):
        self.assertLess(eta.cache_overflow_progress(450), eta.cache_overflow_progress(8000))
        self.assertEqual(eta.cache_overflow_progress(10**9), 1.0)

    def test_samples_are_rate_limited_and_bounded(self):
        eta.SAMPLE_FILE.unlink(missing_ok=True)
        eta.record_sample(0.1, now=1000)
        eta.record_sample(0.2, now=1010)                 # too soon: ignored
        self.assertEqual(eta.record_sample(0.3, now=1100), [(1000, 0.1), (1100, 0.3)])


class SupplyChain(unittest.TestCase):
    def test_pinned_images_run_by_digest(self):
        self.assertIn("3.3.2", pins.pinned_mempool_versions())
        quadlets = services.mempool_quadlets(cfg(versions={"mempool": "3.3.2"}))
        for name in ("api", "web", "db"):
            self.assertRegex(quadlets[f"bitfedot-mempool-{name}.container"], r"Image=\S+@sha256:[0-9a-f]{64}")
        unpinned = services.mempool_quadlets(cfg(versions={"mempool": "99.0.0"}))
        self.assertIn("Image=docker.io/mempool/backend:v99.0.0", unpinned["bitfedot-mempool-api.container"])

    def test_strict_mode_refuses_unvouched_images(self):
        settings.update(pinned_images_only=True)
        with self.assertRaises(verify.VerificationError):
            installer.install_mempool("99.0.0")

    def test_signature_threshold_cannot_be_lowered(self):
        paths.ensure_dirs()
        f = paths.DATA_DIR / "none.txt"
        f.write_text("x")
        with self.assertRaisesRegex(verify.VerificationError, "3 are required"):
            verify.verify_bitcoin(f, f, f, min_signers=1)
        with self.assertRaisesRegex(verify.VerificationError, "6 are required"):
            verify.verify_bitcoin(f, f, f, min_signers=6)


class SelfUpdate(unittest.TestCase):
    """A release is installed only when signed by a key shipped with the running app."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="bf-selfupdate-"))
        cls.gpg = ["gpg", "--homedir", str(cls.tmp / "gnupg"), "--batch", "--no-tty", "--pinentry-mode",
                   "loopback", "--passphrase", ""]
        (cls.tmp / "gnupg").mkdir(mode=0o700)
        made = system.run(cls.gpg + ["--quick-generate-key", "BitFedot test release", "ed25519", "sign", "1d"])
        cls.keys = cls.tmp / "keys"
        cls.keys.mkdir()
        pub = system.run(cls.gpg + ["--armor", "--export"]).stdout
        if made.returncode != 0 or "BEGIN PGP" not in pub:
            raise unittest.SkipTest("cannot create a throw-away signing key here")
        (cls.keys / "release.asc").write_text(pub)

    @classmethod
    def tearDownClass(cls):
        system.run(["gpgconf", "--homedir", str(cls.tmp / "gnupg"), "--kill", "all"])
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.live = self.tmp / "lib" / "bitfedot"
        shutil.rmtree(self.tmp / "lib", ignore_errors=True)
        (self.live / "bitfedot").mkdir(parents=True)
        (self.live / "bitfedot" / "__init__.py").write_text('__version__ = "0.0.1"\n')
        self.patches = [mock.patch.object(selfupdate, "RELEASE_KEY_DIR", self.keys),
                        mock.patch.object(selfupdate, "live_dir", lambda: self.live),
                        mock.patch.object(selfupdate, "install_kind", lambda: "user"),
                        mock.patch.object(selfupdate, "_preflight", lambda tree: None)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def release(self, version, sign=True, inner_version=None):
        folder = self.tmp / f"rel-{version}-{sign}-{inner_version}"
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir()
        body = f'__version__ = "{inner_version or version}"\n'.encode()
        with tarfile.open(folder / f"bitfedot-{version}.tar.gz", "w:gz") as tar:
            info = tarfile.TarInfo(f"bitfedot-{version}/bitfedot/__init__.py")
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
        digest = verify.sha256_file(folder / f"bitfedot-{version}.tar.gz")
        (folder / "SHA256SUMS").write_text(f"{digest}  bitfedot-{version}.tar.gz\n")
        if sign:
            system.run(self.gpg + ["--armor", "--detach-sign", "-o", str(folder / "SHA256SUMS.asc"),
                                   str(folder / "SHA256SUMS")], check=True)
        else:
            (folder / "SHA256SUMS.asc").write_text("no signature")
        return folder

    def test_signed_release_is_installed_and_can_be_rolled_back(self):
        result = selfupdate.install_release(self.release("9.9.9"), "9.9.9")
        self.assertEqual(result["version"], "9.9.9")
        self.assertEqual(selfupdate._tree_version(self.live), "9.9.9")
        self.assertEqual(selfupdate._tree_version(selfupdate.previous_dir()), "0.0.1")
        self.assertEqual(selfupdate.rollback(), "0.0.1")
        self.assertEqual(selfupdate._tree_version(self.live), "0.0.1")

    def test_unsigned_tampered_or_mislabelled_releases_are_refused(self):
        with self.assertRaises(verify.VerificationError):
            selfupdate.install_release(self.release("9.9.9", sign=False), "9.9.9")
        tampered = self.release("9.9.8")
        with open(tampered / "bitfedot-9.9.8.tar.gz", "ab") as f:
            f.write(b"extra")
        with self.assertRaises(verify.VerificationError):
            selfupdate.install_release(tampered, "9.9.8")
        with self.assertRaises(verify.VerificationError):          # signed, but lies about its version
            selfupdate.install_release(self.release("9.9.7", inner_version="0.0.0"), "9.9.7")
        self.assertEqual(selfupdate._tree_version(self.live), "0.0.1")   # nothing was replaced

    def test_no_downgrade_and_no_install_without_a_shipped_key(self):
        with self.assertRaisesRegex(RuntimeError, "not newer"):
            selfupdate.install_release(self.release("0.0.1"), "0.0.1")
        with mock.patch.object(selfupdate, "RELEASE_KEY_DIR", self.tmp / "empty"):
            with self.assertRaises(verify.VerificationError):
                selfupdate.install_release(self.release("9.9.9"), "9.9.9")
            self.assertFalse(selfupdate.status(cfg())["can_install"])

    def test_a_release_that_fails_its_self_test_is_not_installed(self):
        def broken(tree):
            raise RuntimeError("self-test failed")
        with mock.patch.object(selfupdate, "_preflight", broken):
            with self.assertRaisesRegex(RuntimeError, "self-test"):
                selfupdate.install_release(self.release("9.9.9"), "9.9.9")
        self.assertEqual(selfupdate._tree_version(self.live), "0.0.1")
        self.assertFalse(selfupdate._stage_dir().exists())


class HardwareKeys(unittest.TestCase):
    U1, U2 = "11111111-2222-4333-8444-555555555555", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    DEVS = [{"device": "/dev/nvme0n1p3", "uuid": U1, "mapper": "luks-" + U1},
            {"device": "/dev/sda1", "uuid": U2, "mapper": "luks-" + U2}]

    def scripts(self):
        return {
            "prepare": hk.prepare_script(),
            "key": hk.key_script("main", reset=True),
            "key-noreset": hk.key_script("backup", reset=False),
            "pgp-clone": hk.pgp_script("clone", "BitFedot release", "me@example.org", "/home/me/keys"),
            "pgp-separate": hk.pgp_script("separate", "BitFedot release", "me@example.org", "/home/me/keys"),
            "disk": hk.disk_script(self.DEVS),
            "disk-plain": hk.disk_script(self.DEVS, plain_boot=True),
            "boot": hk.boot_script(self.DEVS),
            "login": hk.login_script("fedora"),
            "keyring": hk.keyring_script(),
            "keyring-unencrypted": hk.keyring_script(encrypted=False),
            "finalize": hk.finalize_script(self.DEVS, "fedora", recovery_key=True),
            "revert": hk.revert_script(self.DEVS, "fedora"),
        }

    def test_every_script_is_valid_shell(self):
        everything = {**self.scripts(), "finalize-bare": hk.finalize_script(self.DEVS, "fedora", False)}
        for name, text in everything.items():
            self.assertNotIn("{{", text, name)                     # an unexpanded template brace
            self.assertNotIn("}}", text, name)
        for name, text in self.scripts().items():
            p = system.run(["bash", "-n"], input=text)
            self.assertEqual(p.returncode, 0, f"{name}: {p.stderr}")
            self.assertIn("set -euo pipefail", text, name)

    def test_only_the_final_script_removes_anything(self):
        s = self.scripts()
        for name, text in s.items():
            destructive = "--wipe-slot=password" in text or "passwd -l" in text
            self.assertEqual(destructive, name == "finalize", name)
        self.assertIn(hk.CONFIRM_PHRASE, s["finalize"])
        self.assertIn("--recovery-key", s["finalize"])
        bare = hk.finalize_script(self.DEVS, "fedora", recovery_key=False)
        self.assertNotIn("--recovery-key", bare)
        self.assertIn("LOST FOREVER", bare)                         # said in red, and must be typed away
        self.assertIn("ONLY MY KEYS", bare)
        self.assertLess(bare.index("ONLY MY KEYS"), bare.index("--wipe-slot"))
        self.assertIn('--kver "$(uname -r)"', s["disk"])           # older kernels stay as a fallback
        self.assertEqual(s["disk"].count("systemd-cryptenroll --fido2-device=auto"), 2)   # one per volume
        self.assertIn("/dev/shm", s["pgp-clone"])                  # the cloned key never touches the disk
        for mode in ("pgp-clone", "pgp-separate"):                 # gpgconf lists it even when it is missing
            self.assertIn('[ -x "$(gpgconf --list-dirs libexecdir)/scdaemon" ] || missing+=(gnupg2-scdaemon)', s[mode])
        for name, text in s.items():                               # every step installs its own tools
            self.assertEqual("\nneed_tools\n" in text, name.split("-")[0] not in ("revert", "keyring"), name)

    def test_password_removal_is_gated_on_both_keys(self):
        hw = {"main": "111111", "backup": "222222", "disk": True, "keyring": True,
              "boot_ok": ["111111"], "login_ok": ["111111"]}
        ok, missing = hk.ready_to_finalize(hw)
        self.assertFalse(ok)
        self.assertEqual(len(missing), 2)                          # backup: boot and sudo unproven
        self.assertFalse(hk.ready_to_finalize({**hw, "boot_ok": ["111111", "222222"],
                                               "login_ok": ["111111", "222222"], "keyring": False})[0])
        hw.update(boot_ok=["111111", "222222"], login_ok=["111111", "222222"])
        self.assertEqual(hk.ready_to_finalize(hw), (True, []))
        self.assertFalse(hk.ready_to_finalize({**hw, "backup": "111111"})[0])     # same key twice
        self.assertFalse(hk.ready_to_finalize({**hw, "disk": False})[0])
        # A desktop whose keyring cannot open from a credential must not be stuck for good …
        self.assertEqual(hk.ready_to_finalize({**hw, "keyring": False}, keyring_supported=False), (True, []))
        # … but that waives the keyring step only, never the proofs that prevent a lock-out.
        self.assertFalse(hk.ready_to_finalize({**hw, "login_ok": ["111111"]}, keyring_supported=False)[0])

    def test_keyring_step_is_done_only_while_the_credential_exists(self):
        """`keyring_unlock.py undo` removes the credential: the page and the gate must follow."""
        marker = paths.CONFIG_DIR / "hwkey-keyring.done"
        credential = paths.CREDSTORE_DIR / keyring_unlock.CREDENTIAL
        self.assertIn(os.environ["BITFEDOT_ROOT"], str(credential))             # never the real one
        for f in (marker, credential):
            f.parent.mkdir(parents=True, exist_ok=True)
            f.touch()
            self.addCleanup(f.unlink, missing_ok=True)
        self.addCleanup(settings.update, hwkeys={"keyring": None})
        self.assertTrue(hk.adopt_serials()["keyring"])
        with mock.patch.object(settings, "update", wraps=settings.update) as write:
            self.assertTrue(hk.adopt_serials()["keyring"])
            write.assert_not_called()                              # polled every few seconds: no rewrite
        credential.unlink()                                        # what `undo` does
        hw = hk.adopt_serials()
        self.assertFalse(hw["keyring"])
        full = {**hw, "main": "111111", "backup": "222222", "disk": True,
                "boot_ok": ["111111", "222222"], "login_ok": ["111111", "222222"]}
        self.assertFalse(hk.ready_to_finalize(full)[0])
        credential.touch()
        marker.unlink()                                            # the script never reached its end
        self.assertFalse(hk.adopt_serials()["keyring"])

    def test_keyring_step_says_what_it_costs_and_what_this_desktop_can_do(self):
        s = self.scripts()
        for name in ("keyring", "keyring-unencrypted"):
            self.assertIn("TPM chip", s[name], name)                            # bound to it where there is one
            self.assertIn("TYPE your password no longer opens the keyring", s[name], name)
            self.assertLess(s[name].index(" undo"), s[name].index(" setup\n"), name)
            marker = '"$STATE/hwkey-keyring.done"'                 # "done" is this run's, not an earlier one's
            self.assertLess(s[name].index("rm -f " + marker), s[name].index(" setup\n"), name)
            self.assertLess(s[name].index(" setup\n"), s[name].index("touch " + marker), name)
        self.assertIn("only your keys unlock", s["keyring"])
        self.assertNotIn("NOT ENCRYPTED", s["keyring"])
        plain = s["keyring-unencrypted"]                           # no disk encryption: say so, have it typed
        self.assertNotIn("only your keys unlock", plain)
        self.assertLess(plain.index('[ "$accept" = "NOT ENCRYPTED" ]'), plain.index(" setup\n"))
        # going back to passwords also gives the keyring a typed password again
        self.assertIn("keyring_unlock.py undo", s["revert"])
        self.assertIn("credstore.encrypted/" + keyring_unlock.CREDENTIAL, s["revert"])

        hint, runs = hk.keyring_stage({}, {})
        self.assertEqual((hint, runs), (hk.KEYRING_HINT, True))
        text, runs = hk.keyring_stage({"keyring": True}, {"keyring_supported": True, "keyring_encrypted": True})
        self.assertTrue(text.startswith("Done") and runs)
        text, runs = hk.keyring_stage({}, {"keyring_supported": True, "keyring_encrypted": False})
        self.assertTrue("not encrypted" in text and runs)
        text, runs = hk.keyring_stage({}, {"keyring_supported": False, "keyring_reason": "Needs oo7."})
        self.assertTrue(text.startswith("Needs oo7.") and "still ask for your old login password" in text)
        self.assertFalse(runs)

    def test_boot_confirmation_needs_evidence_and_exactly_one_known_key(self):
        hw = {"main": "111111", "backup": "222222"}
        self.assertIsNone(hk.confirm_boot(hw, {"plugged": ["111111"], "fido2_boot": False})[0])
        self.assertIsNone(hk.confirm_boot(hw, {"plugged": ["111111", "222222"], "fido2_boot": True})[0])
        self.assertIsNone(hk.confirm_boot(hw, {"plugged": ["999999"], "fido2_boot": True})[0])
        self.assertEqual(hk.confirm_boot(hw, {"plugged": ["222222"], "fido2_boot": True})[0], "222222")
        self.assertEqual(hk.confirm_boot(hw, {"plugged": ["111111"], "fido2_boot": False}, user_vouches=True)[0],
                         "111111")

    def test_steps_count_as_done_only_when_their_script_finished(self):
        s = self.scripts()
        self.assertLess(s["disk"].index("sudo dracut --force"), s["disk"].index('touch "$STATE/hwkey-disk.done"'))
        self.assertLess(s["finalize"].index("passwd -l"), s["finalize"].index('touch "$STATE/hwkey-final.done"'))
        paths.ensure_dirs()
        marker = paths.CONFIG_DIR / "hwkey-disk.done"
        marker.unlink(missing_ok=True)
        settings.update(hwkeys={})
        self.assertFalse(hk.adopt_serials().get("disk"))
        marker.touch()
        self.assertTrue(hk.adopt_serials().get("disk"))
        marker.unlink()

    def test_polled_facts_never_talk_to_the_key(self):
        """Opening the key from a poll resets it under a running script (a real bug once)."""
        with mock.patch.object(hk, "plugged_serials", side_effect=AssertionError("polled the key")), \
                mock.patch.object(system, "have", lambda b: True):
            f = hk.facts()
            hk.health(f, {"main": "111111"})
        self.assertIn("present", f)
        self.assertNotIn("plugged", f)

    def test_hostile_input_is_rejected(self):
        bad_dev = [{"device": "/dev/sda1; rm -rf /", "uuid": "", "mapper": "luks-" + self.U1}]
        bad_map = [{"device": "/dev/sda1", "uuid": "", "mapper": "luks-x; reboot"}]
        with self.assertRaises(ValueError):
            hk.boot_script(bad_map)
        for call in (lambda: hk.disk_script(bad_dev, False), lambda: hk.finalize_script(bad_dev, "fedora", True),
                     lambda: hk.login_script("root; reboot"), lambda: hk.key_script("third", False),
                     lambda: hk.pgp_script("clone", "x`id`", "me@example.org", "/tmp"),
                     lambda: hk.pgp_script("clone", "Name", "not-an-address", "/tmp")):
            with self.assertRaises(ValueError):
                call()

    def test_setup_survives_updates(self):
        s = self.scripts()
        for needle in (hk.PROTECTED, hk.KERNEL_HOOK, "/etc/kernel/cmdline", "/etc/default/grub",
                       "dnf mark user"):
            self.assertIn(needle, s["disk"], needle)
        for needle in (hk.GUARD, hk.GUARD_UNITS[0], hk.GUARD_UNITS[1], hk.SAVED, hk.PROTECTED):
            self.assertIn(needle, s["login"], needle)
        for needle in (hk.GUARD, hk.KERNEL_HOOK, hk.PROTECTED, hk.SAVED):     # Undo removes every guard
            self.assertIn(needle, s["revert"], needle)
        for text in (hk.KERNEL_HOOK_TEXT, hk.GUARD_TEXT):
            self.assertEqual(system.run(["bash", "-n"], input=text).returncode, 0)
        self.assertTrue(hk.KERNEL_HOOK_TEXT.rstrip().endswith("exit 0"))       # never blocks a kernel update

    def test_boot_argument_edits(self):
        """The sed programs that drop 'rhgb' for future kernels, on sample files."""
        paths.ensure_dirs()
        cmdline, grub = paths.DATA_DIR / "cmdline", paths.DATA_DIR / "grub"
        cmdline.write_text("root=UUID=x ro rd.luks.uuid=luks-a rhgb quiet video=DP-2:1920x1080@60\n")
        grub.write_text('GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="rd.luks.uuid=luks-a rhgb quiet"\n')
        script = hk.disk_script(self.DEVS, plain_boot=True)
        for target, f in (("/etc/kernel/cmdline", cmdline), ("/etc/default/grub", grub)):
            line = next(ln for ln in script.splitlines() if ln.startswith(f"[ -f {target} ] && sudo sed"))
            command = line.split("&& sudo ", 1)[1].replace(target, str(f))
            system.run(["bash", "-c", command], check=True)
        self.assertEqual(cmdline.read_text(), "root=UUID=x ro rd.luks.uuid=luks-a quiet video=DP-2:1920x1080@60\n")
        self.assertNotIn("rhgb", grub.read_text())
        self.assertIn("GRUB_TIMEOUT=5", grub.read_text())

    def test_health_flags_dangerous_states(self):
        ok = {"password_locked": False, "pam_u2f": False}
        self.assertEqual(hk.health(ok, {}), [])                               # not set up: nothing to report
        hw = {"main": "111111", "backup": "222222", "disk": False}
        locked_out = hk.health({"password_locked": True, "pam_u2f": False}, hw)
        self.assertTrue(any(sev == "critical" and "locked" in text for sev, text in locked_out))

    def test_boot_asks_once(self):
        """One PIN, one touch: graphical screen, volumes in sequence, extra volumes PIN-only."""
        s = self.scripts()
        first_unit = "systemd-cryptsetup@luks\\x2d" + self.U1.replace("-", "\\x2d") + ".service"
        for name in ("disk", "boot"):
            self.assertIn("After=" + first_unit, s[name], name)              # others wait for the first
            self.assertIn(hk.ORDER_DROPIN, s[name])
            self.assertIn(f'install_items+=" {hk.ORDER_DROPIN} "', s[name])  # … also inside the boot image
            self.assertIn('--args="rhgb quiet"', s[name])
            self.assertNotIn("--remove-args", s[name])
        self.assertIn("--remove-args", s["disk-plain"])
        # first volume keeps the touch, the additional one unlocks with the cached PIN alone
        self.assertEqual(s["disk"].count("--fido2-with-user-presence=yes /dev/nvme0n1p3"), 1)
        self.assertEqual(s["disk"].count("--fido2-with-user-presence=no /dev/sda1"), 1)
        self.assertNotIn("/dev/nvme0n1p3", s["boot"].split("Tell the boot process")[0])   # first volume untouched
        self.assertEqual(s["boot"].count("--wipe-slot=fido2"), 1)            # old entries replaced once
        self.assertNotIn("--wipe-slot=password", s["boot"])

    def test_crypttab_edit(self):
        """The sed program from the disk script, run on sample crypttab lines."""
        script = hk.disk_script(self.DEVS)
        program = script.split("sudo sed -i -E '", 1)[1].split("' /etc/crypttab", 1)[0]
        paths.ensure_dirs()
        f = paths.DATA_DIR / "crypttab"
        f.write_text("# comment stays\n"
                     "luks-aaaa UUID=aaaa none discard\n"
                     "luks-bbbb UUID=bbbb none\n"
                     "luks-cccc UUID=cccc none discard,fido2-device=auto\n")
        system.run(["sed", "-i", "-E", program, str(f)], check=True)
        self.assertEqual(f.read_text().splitlines(), [
            "# comment stays",
            "luks-aaaa UUID=aaaa none discard,fido2-device=auto",
            "luks-bbbb UUID=bbbb none fido2-device=auto",
            "luks-cccc UUID=cccc none discard,fido2-device=auto"])


class YubiKeyPins(unittest.TestCase):
    """PIN changes must survive interrupted sessions without burning PIN attempts."""

    class Bad(Exception):
        pass

    def make(self, pin, fail_plan):
        """A fake key holding `pin`; `fail_plan` = per-call behaviour:
        'ok', 'interrupt-before' (nothing applied), 'interrupt-after' (applied, then error)."""
        test = self
        state = {"pin": pin, "calls": [], "verifies": 0}
        plan = list(fail_plan)

        class Session:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def change_pin(self, old, new):
                step = plan.pop(0) if plan else "ok"
                state["calls"].append(step)
                if step == "interrupt-before":
                    raise OSError("Card was reset")
                if old != state["pin"]:
                    raise test.Bad("wrong pin")
                state["pin"] = new
                if step == "interrupt-after":
                    raise OSError("INVALID_INSTRUCTION")

            def verify_pin(self, pin):
                state["verifies"] += 1
                if pin != state["pin"]:
                    raise test.Bad("wrong pin")
        return state, Session

    def change(self, session_cls, old, new):
        ykpins.change(session_cls, old, new, "change_pin", "verify_pin",
                      lambda e: isinstance(e, self.Bad), sleep=lambda s: None)

    def test_plain_change(self):
        state, cls = self.make("123456", [])
        self.change(cls, "123456", "new-pin")
        self.assertEqual(state["pin"], "new-pin")

    def test_interrupted_before_the_key_acted_is_simply_repeated(self):
        state, cls = self.make("123456", ["interrupt-before", "interrupt-before", "ok"])
        self.change(cls, "123456", "new-pin")
        self.assertEqual((state["pin"], len(state["calls"]), state["verifies"]), ("new-pin", 3, 0))

    def test_interrupted_after_the_key_acted_is_recognised(self):
        state, cls = self.make("123456", ["interrupt-after"])
        self.change(cls, "123456", "new-pin")            # retry sees "wrong pin", then confirms the new one
        self.assertEqual((state["pin"], state["verifies"]), ("new-pin", 1))

    def test_a_wrong_pin_is_never_retried(self):
        state, cls = self.make("secret", [])
        with self.assertRaises(ykpins.WrongPin):
            self.change(cls, "123456", "new-pin")
        self.assertEqual((state["pin"], len(state["calls"]), state["verifies"]), ("secret", 1, 0))

    def test_pins_already_set_are_not_forced_again(self):
        asked = []

        def no(label):
            asked.append(label)
            return False
        self.assertEqual(ykpins.plan(set(), no), {"pin": True, "admin": True})      # fresh key: must change
        self.assertEqual(asked, [])
        self.assertEqual(ykpins.plan({"pin", "admin"}, no), {"pin": False, "admin": False})
        self.assertEqual(asked, ["PIN", "Admin PIN"])                                 # offered, not forced
        self.assertEqual(ykpins.plan({"pin"}, no), {"pin": False, "admin": True})    # interrupted half-way
        self.assertEqual(ykpins.plan({"pin", "admin"}, lambda label: True), {"pin": True, "admin": True})
        paths.ensure_dirs()
        f = paths.DATA_DIR / "key.done"
        f.unlink(missing_ok=True)
        ykpins.add_state(f, "pin")
        ykpins.add_state(f, "pin")
        self.assertEqual((f.read_text(), ykpins.read_state(f)), ("pin\n", {"pin"}))
        self.assertEqual(ykpins.read_state(None), set())

    def test_key_script_uses_the_helper_instead_of_idle_prompts(self):
        script = hk.key_script("main", reset=True)
        self.assertIn("ykpins.py", script)
        self.assertNotIn("openpgp access change-pin", script)      # ykman would wait with the key open
        self.assertIn('--state "$STATE/hwkey-$serial.done"', script)
        self.assertIn("flock -n 9", script)                        # two steps at once fight over the key
        self.assertIn("HUP INT TERM", script)                      # closing the window still wipes secrets
        self.assertNotIn("Change it? [y/N]", script)               # a set FIDO2 PIN is simply kept


class KeyringUnlock(unittest.TestCase):
    """The keyring switch-over, against a fake daemon that behaves like oo7 does:
    unlocking checks the password; changing the password of an open keyring does not;
    and a restart ends every session, so a connection made before it can no longer
    hand over a password."""

    class Ring:
        def __init__(self, password, take_changes=True):
            self.password, self.is_locked, self.take_changes = password, False, take_changes

        def locked(self):
            return self.is_locked

        def lock(self):
            self.is_locked = True

        def unlock(self, password):
            if password != self.password:
                raise OSError("Incorrect secret")
            self.is_locked = False

        def change_password(self, old, new):
            if self.is_locked:
                raise OSError("locked")
            if self.take_changes:
                self.password = new          # note: `old` is not checked, as in the real daemon

    class Client:
        """One connection to a `Ring`; `alive` goes False when the daemon is restarted."""

        def __init__(self, ring):
            self.ring, self.alive = ring, True

        def locked(self):
            return self.ring.locked()

        def lock(self):
            self.ring.lock()

        def unlock(self, password):
            self._session()
            self.ring.unlock(password)

        def change_password(self, old, new):
            self._session()
            self.ring.change_password(old, new)

        def _session(self):
            if not self.alive:
                raise OSError("The session does not exist.")

    def setUp(self):
        # Belt and braces: nothing in here may reach the real keyring, systemd or credential.
        for name in ("Keyring", "store_credential", "read_credential", "restart_daemon", "connect"):
            patch = mock.patch.object(keyring_unlock, name, side_effect=AssertionError(f"real {name} used"))
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(keyring_unlock, "credential_file",
                                  return_value=paths.DATA_DIR / "no-credstore" / keyring_unlock.CREDENTIAL)
        patch.start()
        self.addCleanup(patch.stop)

    def run_setup(self, ring, typed, stored=None, store_ok=True, opens_after_restart=True, **more):
        stored, log = {} if stored is None else stored, []

        def store(pw):
            if not store_ok:
                raise RuntimeError("cannot encrypt")
            self.at_store = ring.password                # what the keyring's password was at that moment
            stored["pw"] = pw

        def restart():
            ring.is_locked = not (opens_after_restart and stored.get("pw") == ring.password)
            return ring
        kwargs = dict(say=log.append, ring=ring, store=store, restart=restart,
                      remove=lambda: stored.pop("pw", None), read=lambda: stored.get("pw"))
        try:
            keyring_unlock.setup(typed, **{**kwargs, **more})
            return None, stored, log
        except BaseException as e:
            return e, stored, log

    def test_switches_over_and_verifies(self):
        ring = self.Ring("login-pw")
        err, stored, _ = self.run_setup(ring, "login-pw")
        self.assertIsNone(err)
        self.assertEqual(stored["pw"], ring.password)
        self.assertNotEqual(ring.password, "login-pw")
        self.assertGreater(len(ring.password), 40)
        self.assertFalse(ring.locked())
        # The new password was stored while the keyring still had the old one: at no moment
        # does the keyring's password exist only in the helper's memory.
        self.assertEqual(self.at_store, "login-pw")

    def test_a_mistyped_password_changes_nothing(self):
        ring = self.Ring("login-pw")
        err, stored, _ = self.run_setup(ring, "typo")
        self.assertIsInstance(err, keyring_unlock.WrongPassword)
        self.assertEqual((ring.password, stored), ("login-pw", {}))

    def test_failure_to_store_changes_nothing(self):
        ring = self.Ring("login-pw")
        err, stored, _ = self.run_setup(ring, "login-pw", store_ok=False)
        self.assertIsInstance(err, RuntimeError)
        self.assertIn("not changed", str(err))
        self.assertEqual((ring.password, stored, ring.locked()), ("login-pw", {}, False))

    def test_failure_to_reopen_puts_the_old_password_back(self):
        ring = self.Ring("login-pw")
        err, stored, log = self.run_setup(ring, "login-pw", opens_after_restart=False)
        self.assertIsInstance(err, RuntimeError)
        self.assertEqual((ring.password, stored, ring.locked()), ("login-pw", {}, False))
        self.assertTrue(any("Restored" in line for line in log))

    def test_a_daemon_that_ignores_the_change_is_noticed(self):
        ring = self.Ring("login-pw", take_changes=False)
        err, stored, log = self.run_setup(ring, "login-pw")
        self.assertIsInstance(err, RuntimeError)
        self.assertEqual((ring.password, stored), ("login-pw", {}))
        # … and nothing is left behind: the keyring is open again, and no alarm about a
        # random password that never became the keyring's.
        self.assertFalse(ring.locked())
        self.assertTrue(any("Restored" in line for line in log))
        self.assertFalse(any("COULD NOT RESTORE" in line for line in log))

    def test_running_it_again_changes_nothing_and_leaves_the_keyring_open(self):
        ring = self.Ring("login-pw")
        _, stored, _ = self.run_setup(ring, "login-pw")
        switched = ring.password
        err, stored, log = self.run_setup(ring, "login-pw", stored=stored)     # the page's button, pressed again
        self.assertIsNone(err)
        self.assertEqual((ring.password, stored["pw"], ring.locked()), (switched, switched, False))
        self.assertTrue(any("Already done" in line for line in log))

    def test_an_interrupted_run_loses_nothing_and_can_be_repeated(self):
        """Ctrl+C or a closed window is not an `Exception`: no rollback runs. Whatever the
        keyring's password is at that moment must already be on disk."""
        def interrupt(*_):
            raise KeyboardInterrupt

        ring = self.Ring("login-pw")                               # … while waiting for the restart
        err, stored, _ = self.run_setup(ring, "login-pw", restart=interrupt)
        self.assertIsInstance(err, KeyboardInterrupt)
        self.assertEqual(stored["pw"], ring.password)              # switched, and the credential fits
        err, stored, log = self.run_setup(ring, "login-pw", stored=stored)
        self.assertIsNone(err)
        self.assertTrue(any("Already done" in line for line in log))
        self.assertFalse(ring.locked())

        ring = self.Ring("login-pw")                               # … before the keyring took the password
        with mock.patch.object(ring, "change_password", side_effect=interrupt):
            err, stored, _ = self.run_setup(ring, "login-pw")
        self.assertIsInstance(err, KeyboardInterrupt)
        self.assertEqual(ring.password, "login-pw")                # the typed password still opens it
        leftover = stored["pw"]
        err, stored, _ = self.run_setup(ring, "login-pw", stored=stored)        # the leftover is replaced
        self.assertIsNone(err)
        self.assertEqual(stored["pw"], ring.password)
        self.assertNotIn(ring.password, ("login-pw", leftover))
        self.assertFalse(ring.locked())

    def test_a_failed_restart_is_rolled_back_over_a_fresh_connection(self):
        ring, stored, log = self.Ring("login-pw"), {}, []
        old = self.Client(ring)

        def restart():                                             # the daemon comes back, systemctl says it failed
            old.alive = False
            ring.is_locked = False
            raise RuntimeError("Job for oo7-daemon.service failed")
        with self.assertRaises(RuntimeError):
            keyring_unlock.setup("login-pw", say=log.append, ring=old, store=lambda pw: stored.update(pw=pw),
                                 restart=restart, remove=lambda: stored.pop("pw", None),
                                 read=lambda: stored.get("pw"), reconnect=lambda: self.Client(ring))
        self.assertEqual((ring.password, stored, ring.locked()), ("login-pw", {}, False))
        self.assertTrue(any("Restored" in line for line in log))

        # Without a connection the new daemon accepts, nothing can be undone: then the stored
        # credential — the durable copy of the keyring's password — must stay.
        ring, stored, log = self.Ring("login-pw"), {}, []
        old = self.Client(ring)
        with self.assertRaises(RuntimeError):
            keyring_unlock.setup("login-pw", say=log.append, ring=old, store=lambda pw: stored.update(pw=pw),
                                 restart=restart, remove=lambda: stored.pop("pw", None),
                                 read=lambda: stored.get("pw"))
        self.assertEqual(stored["pw"], ring.password)
        self.assertTrue(any("COULD NOT RESTORE" in line for line in log))
        self.assertTrue(any(ring.password in line for line in log))             # and it is shown

    def test_a_test_double_is_never_mixed_with_the_real_thing(self):
        with self.assertRaises(TypeError):
            keyring_unlock.setup("login-pw", ring=self.Ring("login-pw"))
        with self.assertRaises(TypeError):                         # … not even for reading the credential back
            keyring_unlock.setup("login-pw", ring=self.Ring("login-pw"), store=lambda pw: None,
                                 restart=lambda: None, remove=lambda: None)
        with self.assertRaises(TypeError):
            keyring_unlock.undo("new", ring=self.Ring("x"), read=lambda: "x")

    def test_a_credential_that_cannot_be_read_back_changes_nothing(self):
        """The stored copy is about to be the only one: it has to prove readable first."""
        for read_back in (lambda: None, lambda: "something else"):
            ring = self.Ring("login-pw")
            err, stored, log = self.run_setup(ring, "login-pw", read=read_back)
            self.assertIsInstance(err, RuntimeError)
            self.assertIn("not changed", str(err))
            self.assertEqual((ring.password, stored, ring.locked()), ("login-pw", {}, False))
            self.assertFalse(any("Giving the keyring" in line for line in log))

    def test_undo(self):
        ring = self.Ring("random-secret")
        removed = []
        keyring_unlock.undo("my-new-pw", say=lambda m: None, ring=ring, read=lambda: "random-secret",
                            remove=lambda: removed.append(True))
        self.assertEqual((ring.password, removed, ring.locked()), ("my-new-pw", [True], False))

        ring = self.Ring("random-secret", take_changes=False)      # the change does not take: keep everything
        with self.assertRaises(RuntimeError):
            keyring_unlock.undo("my-new-pw", say=lambda m: None, ring=ring, read=lambda: "random-secret",
                                remove=lambda: removed.append(True))
        self.assertEqual((ring.password, removed, ring.locked()), ("random-secret", [True], False))

        ring = self.Ring("login-pw")                               # locked, and the credential is a leftover
        ring.lock()
        with self.assertRaises(RuntimeError) as failed:
            keyring_unlock.undo("my-new-pw", say=lambda m: None, ring=ring, read=lambda: "leftover",
                                remove=lambda: removed.append(True))
        self.assertIn("does not open the keyring", str(failed.exception))
        self.assertEqual((ring.password, removed, ring.locked()), ("login-pw", [True], True))    # all kept

    def test_the_command_reports_trouble_without_a_traceback(self):
        def run(**patches):
            out = io.StringIO()
            with mock.patch.multiple(keyring_unlock, supported=lambda: (True, ""), **patches), \
                    contextlib.redirect_stdout(out):
                return keyring_unlock.main(["setup"]), out.getvalue()

        def no_service():
            raise OSError("org.freedesktop.secrets was not provided by any .service files")
        code, out = run(Keyring=no_service)
        self.assertEqual(code, 1)
        self.assertIn("keyring service could not be used", out)

        ring = self.Ring("login-pw")                               # the window is closed at the question
        with mock.patch.object(keyring_unlock.getpass, "getpass", side_effect=EOFError):
            code, out = run(Keyring=lambda: ring, stored_password=lambda: None)
        self.assertEqual((code, ring.password, ring.locked()), (1, "login-pw", False))
        self.assertIn("No password was entered", out)

    def test_the_command_says_what_a_stored_password_that_does_not_fit_means(self):
        leftover = paths.DATA_DIR / "credstore-notes" / keyring_unlock.CREDENTIAL
        leftover.parent.mkdir(parents=True, exist_ok=True)
        leftover.write_text("an encrypted blob")
        self.addCleanup(shutil.rmtree, leftover.parent, ignore_errors=True)

        def run(ring, stored, typed):
            out = io.StringIO()

            def restart():
                ring.is_locked = stored.get("pw") != ring.password
                return ring
            with mock.patch.multiple(keyring_unlock, supported=lambda: (True, ""), Keyring=lambda: ring,
                                     credential_file=lambda: leftover, stored_password=lambda: stored.get("pw"),
                                     store_credential=lambda pw: stored.update(pw=pw),
                                     remove_credential=lambda: stored.pop("pw", None),
                                     restart_daemon=restart, connect=lambda *a: ring), \
                    mock.patch.object(keyring_unlock.getpass, "getpass", return_value=typed), \
                    contextlib.redirect_stdout(out):
                return keyring_unlock.main(["setup"]), out.getvalue()

        ring, stored = self.Ring("login-pw"), {"pw": "left-by-an-unfinished-run"}
        code, out = run(ring, stored, "login-pw")                  # readable, but it is not the keyring's
        self.assertEqual(code, 0)
        self.assertIn("does not open the keyring", out)
        self.assertEqual((stored["pw"], ring.locked()), (ring.password, False))  # replaced by one that fits
        self.assertNotEqual(ring.password, "login-pw")

        ring = self.Ring("a-random-password-nobody-knows")         # after a reinstall: cannot be decrypted
        code, out = run(ring, {}, "login-pw")
        self.assertEqual(code, 1)
        self.assertIn("cannot decrypt it", out)
        self.assertEqual(ring.password, "a-random-password-nobody-knows")

    def test_the_command_asks_for_no_password_when_it_is_already_done(self):
        ring, stored, typed = self.Ring("login-pw"), {}, []

        def restart():
            ring.is_locked = stored.get("pw") != ring.password
            return ring

        def run(password):
            out = io.StringIO()
            with mock.patch.multiple(keyring_unlock, supported=lambda: (True, ""), Keyring=lambda: ring,
                                     stored_password=lambda: stored.get("pw"),
                                     store_credential=lambda pw: stored.update(pw=pw),
                                     remove_credential=lambda: stored.pop("pw", None),
                                     restart_daemon=restart, connect=lambda *a: ring), \
                    mock.patch.object(keyring_unlock.getpass, "getpass",
                                      side_effect=lambda prompt: typed.append(prompt) or password), \
                    contextlib.redirect_stdout(out):
                return keyring_unlock.main(["setup"]), out.getvalue()

        code, out = run("typo")
        self.assertEqual((code, len(typed), ring.password, stored), (1, 3, "login-pw", {}))
        code, out = run("login-pw")
        self.assertEqual((code, len(typed), stored["pw"]), (0, 4, ring.password))
        self.assertIn("Done:", out)
        code, out = run("login-pw")                                # again: recognised before any question
        self.assertEqual((code, len(typed), ring.locked()), (0, 4, False))
        self.assertIn("Already set up", out)

    def test_credential_is_forced_to_disk_and_its_kind_is_recognised(self):
        target = paths.DATA_DIR / "credstore-test" / keyring_unlock.CREDENTIAL
        target.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, target.parent, ignore_errors=True)
        with mock.patch.object(keyring_unlock.os, "fsync", wraps=os.fsync) as fsync:
            keyring_unlock._write_durably(target, b"first")
            keyring_unlock._write_durably(target, b"second")
        self.assertEqual(fsync.call_count, 4)                      # each time: the file, then its folder
        self.assertEqual((target.read_bytes(), target.stat().st_mode & 0o777), (b"second", 0o600))
        self.assertEqual([p.name for p in target.parent.iterdir()], [target.name])       # no temp file left

        def blob(kind):
            return base64.b64encode(bytes.fromhex(kind) + b"\0" * 40)
        host_only = "55b9ed1d38594d43a8319d2ebb332ac6"            # what systemd writes without a TPM
        with_tpm = "93a894094874449090caf2fc93cab553"
        self.assertFalse(keyring_unlock.bound_to_tpm(blob(host_only)))
        self.assertTrue(keyring_unlock.bound_to_tpm(blob(with_tpm)))
        self.assertTrue(keyring_unlock.bound_to_tpm(blob(with_tpm)[:30] + b"\n" + blob(with_tpm)[30:]))
        self.assertFalse(keyring_unlock.bound_to_tpm(b""))
        self.assertFalse(keyring_unlock.bound_to_tpm(b"not base64 !!"))

    def test_support_check_reads_coloured_output_too(self):
        def systemctl(version, unit="LoadState=loaded\nImportCredential=oo7.keyring-encryption-password\n"):
            def run(cmd, **kw):
                self.assertEqual(kw["env"]["SYSTEMD_COLORS"], "0")
                return types.SimpleNamespace(stdout=version if "--version" in cmd else unit)
            return mock.patch.object(keyring_unlock.subprocess, "run", side_effect=run)
        with systemctl("\x1b[0;1;39msystemd 262\x1b[0m (262.1-1.fc45)\n+PAM +AUDIT\n"):
            self.assertEqual(keyring_unlock.supported(), (True, ""))
        with systemctl("systemd 257 (257.9-1.fc42)\n"):
            self.assertFalse(keyring_unlock.supported()[0])
        with systemctl("systemd 262 (262.1-1.fc45)\n", unit="LoadState=not-found\nImportCredential=\n"):
            self.assertFalse(keyring_unlock.supported()[0])
        with mock.patch.object(keyring_unlock.subprocess, "run", side_effect=FileNotFoundError("systemctl")):
            self.assertFalse(keyring_unlock.supported()[0])

    def test_helpers_are_run_without_the_script_folder_on_the_import_path(self):
        """ykman imports a library called `keyring`; a file of ours must never shadow it."""
        self.assertFalse((paths.PKG_DIR / "keyring.py").exists())
        self.assertIn("python3 -P ", hk.key_script("main", False))
        self.assertIn("python3 -P ", hk.keyring_script())


class StatusUpdates(unittest.TestCase):
    def snap(self, **over):
        s = node.demo_snapshot(synced=True)
        for key, changes in over.items():
            s[key] = {**s[key], **changes}
        return s

    def test_fulcrum_log_line_is_parsed(self):
        line = "[2026-11-16 18:01:02.123] <Controller> Processed height: 412000, 43.2%, 1234.5 blocks/sec"
        height, fraction = node.fulcrum_progress(line)
        self.assertEqual(height, 412000)
        self.assertAlmostEqual(fraction, 0.432)
        self.assertIsNone(node.fulcrum_progress("<Controller> Initializing header merkle cache"))
        self.assertIsNone(node.fulcrum_progress(""))

    def test_summary_has_a_line_per_service(self):
        lines = node.summary(self.snap())
        self.assertEqual([line.split(":")[0] for line in lines], ["Bitcoin Core", "Tor", "Fulcrum", "Mempool"])
        self.assertIn("synced · block", lines[0])
        self.assertEqual(lines[2:], ["Fulcrum: serving wallets", "Mempool: explorer ready"])
        self.assertEqual(node.summary({"installed": False}), ["Not installed"])
        # While Fulcrum still builds its index the explorer is up but not complete: say so.
        indexing = self.snap(fulcrum={"state": "syncing", "message": "Building the wallet index: 43.2%"},
                             mempool={"message": "Blocks and transactions ready — address lookups wait for Fulcrum"})
        lines = node.summary(indexing)
        self.assertIn("43.2%", lines[2])
        self.assertIn("wait for Fulcrum", lines[3])
        self.assertNotIn("explorer ready", lines[3])
        # A sync that is not finished is never shown as 100 %.
        almost = node.demo_snapshot(synced=False)
        almost["bitcoin"]["progress"] = 0.9999
        self.assertIn("syncing 99.9%", node.summary(almost)[0])

    def test_sync_milestones_are_announced_once(self):
        syncing = node.demo_snapshot(synced=False)              # 47 %
        events, seen = node.status_events(syncing, {})
        self.assertEqual([title for title, _ in events], ["Blockchain sync 40%"])
        self.assertEqual(node.status_events(syncing, seen)[0], [])            # not again
        syncing["bitcoin"]["progress"] = 0.52
        self.assertEqual(node.status_events(syncing, seen)[0][0][0], "Blockchain sync 50%")

    def test_a_synced_node_catching_up_is_not_a_sync_milestone(self):
        """After a restart a synced node is 'syncing' at 99.99 % for a moment — in phase 'ready'."""
        behind = self.snap(bitcoin={"state": "syncing", "progress": 0.9999, "blocks": 975_310, "headers": 975_312})
        events, seen = node.status_events(behind, {"fulcrum_ready": True, "mempool_ready": True})
        self.assertEqual((events, seen.get("sync")), ([], None))

    def test_a_new_sync_or_index_is_announced_afresh(self):
        old = {"sync": 90, "fulcrum_index": 75, "fulcrum_ready": True, "mempool_ready": True, "failed": []}
        syncing = node.demo_snapshot(synced=False)
        syncing["bitcoin"]["progress"] = 0.05                      # a sync from the start (new data folder)
        events, seen = node.status_events(syncing, old)
        self.assertEqual((events, seen["sync"]), ([], 0))
        self.assertFalse(seen.get("fulcrum_ready") or seen.get("mempool_ready") or seen.get("fulcrum_index"))
        syncing["bitcoin"]["progress"] = 0.12
        self.assertEqual(node.status_events(syncing, seen)[0][0][0], "Blockchain sync 10%")
        syncing["bitcoin"]["progress"] = 0.499                     # a dip at a boundary is not a new sync
        self.assertEqual(node.status_events(syncing, {"sync": 50})[1]["sync"], 50)

        rebuilding = self.snap(fulcrum={"state": "syncing", "progress": 0.03}, mempool={"state": "running"})
        events, seen = node.status_events(rebuilding, old)         # Fulcrum's database is built again
        self.assertEqual((events, seen["fulcrum_index"]), ([], 0))
        self.assertFalse(seen.get("fulcrum_ready") or seen.get("mempool_ready"))
        events, seen = node.status_events(self.snap(), seen)
        self.assertEqual({title for title, _ in events}, {"Fulcrum is ready", "Mempool explorer is ready"})

    def test_services_becoming_ready_and_failing(self):
        events, seen = node.status_events(self.snap(), {})
        self.assertEqual({title for title, _ in events}, {"Fulcrum is ready", "Mempool explorer is ready"})
        self.assertEqual(node.status_events(self.snap(), seen)[0], [])
        broken = self.snap(fulcrum={"state": "error", "message": "Failed — see Logs"})
        events, seen2 = node.status_events(broken, seen)
        self.assertEqual(events[0][0], "A service stopped unexpectedly")
        self.assertIn("Fulcrum", events[0][1])
        self.assertEqual(node.status_events(broken, seen2)[0], [])            # one notice per failure
        indexing = self.snap(fulcrum={"state": "syncing", "progress": 0.6}, mempool={"state": "starting"})
        self.assertEqual(node.status_events(indexing, {})[0][0][0], "Fulcrum index 50%")
        # Two down, one comes back: the other one is not news again.
        both = self.snap(fulcrum={"state": "error"}, mempool={"state": "error"})
        events, seen3 = node.status_events(both, seen)
        self.assertIn("Fulcrum, Mempool", events[0][1])
        self.assertEqual(node.status_events(self.snap(mempool={"state": "error"}), seen3)[0], [])

    def test_explorer_is_ready_only_once_fulcrum_serves(self):
        indexing = self.snap(fulcrum={"state": "syncing", "progress": 0.12})    # Mempool already answers
        events, seen = node.status_events(indexing, {"failed": []})
        self.assertEqual(events, [])
        events, seen = node.status_events(self.snap(), seen)
        self.assertEqual({title for title, _ in events}, {"Fulcrum is ready", "Mempool explorer is ready"})

    def test_fulcrum_is_never_at_100_percent_before_it_serves(self):
        """Fulcrum rounds: its last progress lines read '100.0%' while it still works."""
        height, fraction = node.fulcrum_progress("<Controller> Processed height: 975000, 100.0%, 3.1 blocks/sec")
        self.assertEqual(height, 975000)
        self.assertLess(fraction, 1.0)
        almost = self.snap(fulcrum={"state": "syncing", "progress": fraction}, mempool={"state": "starting"})
        self.assertEqual(node.status_events(almost, {"fulcrum_index": 75, "failed": []})[0], [])
        self.assertEqual(node.status_events(almost, {"failed": []})[0][0][0], "Fulcrum index 75%")
        self.assertIsNone(node.fulcrum_progress("Processed height: 5, 1.2.3%"))       # never a crash on odd input

    def test_a_crashing_service_is_announced_though_systemd_never_calls_it_failed(self):
        """With Restart=on-failure a crashed unit is 'activating (auto-restart)', not 'failed'."""
        out = ("Id=bitfedot-bitcoind.service\nActiveState=active\nSubState=running\nNRestarts=0\n\n"
               "Id=bitfedot-fulcrum.service\nActiveState=activating\nSubState=auto-restart\nNRestarts=7\n")
        info = system._parse_units(out, [U_BITCOIND, U_FULCRUM, U_MEMPOOL])
        self.assertEqual(info[U_BITCOIND], {"state": "active", "sub": "running", "restarts": 0})
        self.assertEqual(info[U_FULCRUM], {"state": "activating", "sub": "auto-restart", "restarts": 7})
        self.assertEqual(info[U_MEMPOOL], {"state": "inactive", "sub": "", "restarts": 0})     # not listed
        card = node._restarting({"state": "syncing", "pill": "Indexing", "message": "last log line"}, info[U_FULCRUM])
        self.assertEqual((card["state"], card["pill"], card["restarts"]), ("starting", "Restarting", 7))
        self.assertIn("Stopped unexpectedly", card["message"])

        crashing = self.snap(fulcrum=card)
        seen = {"fulcrum_ready": True, "mempool_ready": True, "failed": []}
        events, seen = node.status_events(crashing, seen)
        self.assertEqual([(title, "Fulcrum" in body) for title, body in events],
                         [("A service stopped unexpectedly", True)])
        crashing["fulcrum"]["restarts"] = 8                        # 30 s later it crashed again: not every tick
        self.assertEqual(node.status_events(crashing, seen)[0], [])
        crashing["t"] += node.CRASH_NOTICE_EVERY + 1               # still crashing an hour later
        crashing["fulcrum"]["restarts"] = 90
        events, seen = node.status_events(crashing, seen)
        self.assertEqual(len(events), 1)
        self.assertEqual(seen, json.loads(json.dumps(seen)))       # survives the settings file as it is

        # systemd keeps the counter until the next start: a service that was stopped on purpose
        # after it crashed, or that waits for the VPN, is not "stopped unexpectedly" now.
        halted = self.snap(tor={"state": "blocked", "restarts": 2}, fulcrum={"state": "stopped", "restarts": 3})
        quiet = {"fulcrum_ready": True, "mempool_ready": True, "failed": []}
        events, seen = node.status_events(halted, quiet)
        self.assertEqual(events, [])
        back = self.snap(tor={"restarts": 0}, fulcrum={"restarts": 0})           # started again: counters cleared
        events, seen = node.status_events(back, seen)
        self.assertEqual(events, [])
        back["fulcrum"]["restarts"] = 1                            # … and a new crash is news again
        self.assertEqual(len(node.status_events(back, seen)[0]), 1)

    def test_mempool_status_and_whether_the_explorer_can_be_opened(self):
        s, core = cfg(phase="ready"), {"blocks": 975_312}

        def mempool(tip, fulcrum="running", info=True):
            with mock.patch.object(rpc, "http_text", return_value=tip), \
                    mock.patch.object(rpc, "http_ok", return_value=info):
                m = node._mempool(s, "active", core, {"state": fulcrum})
            return m["state"], m.get("pill"), node.explorer_available({"mempool": m}), m["message"]

        self.assertEqual(mempool("975311\n")[:3], ("running", None, True))
        state, pill, can_open, message = mempool("975311", fulcrum="syncing")
        self.assertEqual((state, pill, can_open), ("running", "Partly ready", True))
        self.assertIn("address lookups wait for Fulcrum", message)
        # two blocks behind: shown as catching up, but the explorer still answers
        self.assertEqual(mempool("975310")[:3], ("syncing", "Catching up", True))
        self.assertEqual(mempool(None)[:3], ("starting", "Loading", False))
        self.assertEqual(mempool(None, info=False)[:3], ("starting", None, False))
        self.assertEqual(mempool("²")[:3], ("starting", "Loading", False))               # digit-like, not a number
        self.assertFalse(node.explorer_available({"installed": False}))

    def test_nothing_is_announced_while_everything_is_stopped(self):
        stopped = self.snap()
        stopped["settings"] = {**stopped["settings"], "all_stopped": True}
        self.assertEqual(node.status_events(stopped, {}), ([], {}))


class Agent(unittest.TestCase):
    """The headless loop: what it announces, and that announcing never gets in the way."""

    def setUp(self):
        self.stored, self.sent, self.delivered = {}, [], True
        self.snap = node.demo_snapshot(synced=True)
        patches = (
            mock.patch.object(node, "snapshot", side_effect=lambda: self.snap),
            mock.patch.object(settings, "update", side_effect=lambda **kw: self.stored.update(kw)),
            mock.patch.object(system, "notify", side_effect=lambda title, body="": (self.sent.append(title),
                                                                                  self.delivered)[1]),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def settings_now(self, **over):
        return {**settings.DEFAULTS, "installed": True, "phase": "ready", "auto_check_updates": False,
                "notified": self.stored.get("notified", {}), **over}

    def test_the_first_look_only_takes_stock(self):
        agent.announce(self.settings_now())                        # an install that has long been running
        self.assertEqual(self.sent, [])
        self.assertTrue(self.stored["notified"]["fulcrum_ready"] and self.stored["notified"]["mempool_ready"])
        self.snap["fulcrum"] = {**self.snap["fulcrum"], "state": "error"}
        agent.announce(self.settings_now())                        # from then on, news is news
        self.assertEqual(self.sent, ["A service stopped unexpectedly"])

    def test_an_event_nobody_could_see_is_announced_later(self):
        agent.announce(self.settings_now())
        before = dict(self.stored["notified"])
        self.snap["fulcrum"] = {**self.snap["fulcrum"], "state": "error"}
        self.delivered = False                                     # logged out: no notification service
        agent.announce(self.settings_now())
        agent.announce(self.settings_now())
        self.assertEqual(self.stored["notified"], before)          # not counted as announced
        self.delivered = True
        agent.announce(self.settings_now())
        self.assertEqual(self.sent, ["A service stopped unexpectedly"] * 3)
        agent.announce(self.settings_now())
        self.assertEqual(len(self.sent), 3)                        # shown once: done

    def test_trouble_with_notifications_never_costs_the_vpn_watch_or_the_update_check(self):
        s = self.settings_now(tor_route="vpn", vpn_iface="wg0", auto_check_updates=True, last_update_check=0,
                              notified={"failed": []})
        with mock.patch.object(settings, "load", return_value=s), \
                mock.patch.object(node, "snapshot", side_effect=http.client.IncompleteRead(b"")), \
                mock.patch.object(system, "vpn_addresses", return_value=(None, None)), \
                mock.patch.object(services, "apply") as apply, \
                mock.patch.object(services, "unfinished", return_value=False), \
                mock.patch.object(installer, "check_updates") as check, \
                mock.patch.object(hardening, "check_os_updates", side_effect=RuntimeError("no dnf")), \
                contextlib.redirect_stdout(io.StringIO()) as log:
            agent.tick({"vpn": ("10.2.0.2", None)})                # the VPN has just gone
        apply.assert_called_once_with()
        check.assert_called_once()
        self.assertEqual(self.sent, ["Tor routing"])
        self.assertIn("agent: status: IncompleteRead", log.getvalue())

    def test_the_switch_also_covers_the_last_sync_notification(self):
        for wanted, expected in ((True, ["Blockchain synced"]), (False, [])):
            self.sent.clear()
            s = self.settings_now(phase="ibd", status_notifications=wanted)
            with mock.patch.object(settings, "load", return_value=s), \
                    mock.patch.object(agent, "sync_complete", return_value=True), \
                    mock.patch.object(node, "finalize_sync") as finalize:
                agent.tick({})
            finalize.assert_called_once()
            self.assertEqual(self.sent, expected)


class KeepAwake(unittest.TestCase):
    """A sleeping computer does not sync: the lock against sleep, who holds it, and what
    the Settings page says about it."""

    class Helper:
        def __init__(self, refused=False):
            self.code = 1 if refused else None           # refused by logind: it ends at once

        def poll(self):
            return self.code

    def setUp(self):
        self.started, self.released, self.refuse = [], [], False
        self.real = (system.hold_awake, system.release_awake)

        def hold(why):
            self.started.append(why)
            return self.Helper(self.refuse)

        def release(helper):
            self.released.append(helper)
            helper.code = -15
        for name, fake in (("hold_awake", hold), ("release_awake", release)):
            patch = mock.patch.object(system, name, side_effect=fake)
            patch.start()
            self.addCleanup(patch.stop)
        self.s = {**settings.DEFAULTS, "installed": True}
        self.log = io.StringIO()

    def look(self, state, **over):
        with contextlib.redirect_stdout(self.log):
            agent.keep_awake({**self.s, **over}, state)

    def test_it_is_on_by_default_and_held_while_the_node_is_meant_to_run(self):
        self.assertTrue(settings.DEFAULTS["keep_awake"])
        state = {}
        self.look(state)
        self.look(state)                                           # the next tick: still held, not taken twice
        self.assertEqual(self.started, [agent.AWAKE_WHY])
        self.assertIsNone(state["awake"].poll())
        self.assertIn("kept awake", self.log.getvalue())

    def test_it_is_given_up_when_everything_is_stopped_or_it_is_switched_off(self):
        for change in ({"all_stopped": True}, {"keep_awake": False}, {"installed": False}):
            state = {}
            self.look(state)
            helper = state["awake"]
            self.look(state, **change)
            self.assertEqual((self.released[-1], state), (helper, {}), change)
            self.look(state)                                       # started again: taken again at once
            self.assertIsNone(state["awake"].poll(), change)
        self.assertEqual(len(self.started), 6)
        self.look({}, installed=False)                             # nothing installed: nothing to keep awake for
        self.assertEqual(len(self.started), 6)

    def test_a_refused_lock_is_tried_again_later_not_every_tick(self):
        """logind grants it to a logged-in user only: with linger the agent runs before that."""
        self.refuse, state = True, {}
        self.look(state)
        for _ in range(5):                                         # 100 seconds of ticks
            self.look(state)
        self.assertEqual((len(self.started), state.get("awake")), (1, None))
        self.assertEqual(self.log.getvalue().count("not blocked"), 1)             # said once
        self.refuse, state["awake_next"] = False, 0                # two minutes on, the user has logged in
        self.look(state)
        self.look(state)
        self.assertEqual(len(self.started), 2)
        self.assertIsNone(state["awake"].poll())
        self.assertIn("kept awake", self.log.getvalue())

    def test_the_agent_looks_after_the_lock_before_anything_else(self):
        state = {}
        self.look(state)
        helper = state["awake"]
        with mock.patch.object(settings, "load", return_value={**self.s, "all_stopped": True}), \
                contextlib.redirect_stdout(self.log):
            agent.tick(state)                                      # "Stop all": the tick ends early — after this
        self.assertEqual(self.released, [helper])
        running = {**self.s, "phase": "ready", "auto_check_updates": False}      # nothing else to do this tick
        with mock.patch.object(settings, "load", return_value=running), \
                mock.patch.object(agent, "keep_awake", side_effect=OSError("cannot fork")), \
                mock.patch.object(agent, "announce") as announce, contextlib.redirect_stdout(self.log):
            agent.tick({})                                         # trouble here never costs the rest
        announce.assert_called_once()

    def test_who_blocks_sleep_is_read_from_logind(self):
        listing = json.dumps([
            {"who": "NetworkManager", "uid": 0, "what": "sleep", "why": "…", "mode": "delay"},
            {"who": "fedora", "uid": 1000, "what": "handle-lid-switch", "why": "…", "mode": "block"},
            {"who": "BitFedot", "uid": 1000, "what": "sleep", "why": agent.AWAKE_WHY, "mode": "block"},
            {"who": "Videos", "uid": 1000, "what": "sleep:idle", "why": "Playing", "mode": "block"}])
        self.assertEqual(system._sleep_blockers(listing), ["BitFedot", "Videos"])
        self.assertEqual(system._sleep_blockers(""), [])
        self.assertEqual(system._sleep_blockers("No inhibitors."), [])
        self.assertEqual(system._sleep_blockers('{"who": "BitFedot"}'), [])
        self.assertFalse(system.held_awake())                      # tests never ask the real logind

    def test_tests_never_take_a_real_lock_and_a_real_helper_is_ended_as_one(self):
        hold, release = self.real                                  # the real functions, for once
        self.assertIsNone(hold("a test"))                          # BITFEDOT_ROOT is set: nothing is started
        helper = subprocess.Popen(["sh", "-c", "sleep 30 & wait"], start_new_session=True)
        release(helper)
        self.assertIsNotNone(helper.poll())
        release(helper)                                            # twice, or never started: harmless
        release(None)

    def test_the_switch_says_what_it_does_and_whether_it_is_in_effect(self):
        snap = node.demo_snapshot(synced=False)
        self.assertTrue(node.awake_status(snap).endswith("In effect now."))
        self.assertIn("laptop's lid still puts it to sleep", node.awake_status(snap))
        snap["awake"] = False
        self.assertIn("Not in effect right now", node.awake_status(snap))
        self.assertIn("nobody is logged in", node.awake_status(snap))
        snap["settings"] = {**snap["settings"], "all_stopped": True}
        self.assertIn("everything is stopped", node.awake_status(snap))
        snap["settings"] = {**snap["settings"], "all_stopped": False, "keep_awake": False}
        self.assertEqual(node.awake_status(snap), node.AWAKE_INFO)

    def test_never_sleep_is_one_root_owned_file_and_nothing_else(self):
        lines = []
        with mock.patch.object(hardening, "as_root", side_effect=lines.append):
            hardening.set_never_sleep(True)
            hardening.set_never_sleep(False)
        on, off = ("\n".join(batch) for batch in lines)
        self.assertIn(f"cat > {hardening.SLEEP_CONF} <<", on)
        self.assertTrue(hardening.SLEEP_CONF.startswith("/etc/systemd/sleep.conf.d/"))
        for kind in ("Suspend", "Hibernation", "SuspendThenHibernate", "HybridSleep"):
            self.assertIn(f"\nAllow{kind}=no\n", on + "\n")
        self.assertEqual(off, f"rm -f {hardening.SLEEP_CONF}")
        with mock.patch.object(hardening, "SLEEP_CONF", str(paths.DATA_DIR / "no-such-sleep.conf")):
            self.assertFalse(hardening.never_sleep_enabled())


class LocalClients(unittest.TestCase):
    """A reply cut short or garbled is `http.client.HTTPException`, not OSError: it must
    still only mean 'not answering', for the status poll and for the agent."""

    class Broken:
        def __init__(self, *a, **kw):
            pass

        def request(self, *a, **kw):
            pass

        def getresponse(self):
            raise http.client.IncompleteRead(b"97")

        def close(self):
            pass

    def test_broken_replies_count_as_no_answer(self):
        with mock.patch.object(rpc.http.client, "HTTPConnection", self.Broken):
            self.assertIsNone(rpc.http_text(paths.MEMPOOL_PORT, "/api/blocks/tip/height"))
            self.assertFalse(rpc.http_ok(paths.MEMPOOL_PORT, "/api/v1/backend-info"))
            datadir = paths.DATA_DIR / "rpc-test"
            datadir.mkdir(parents=True, exist_ok=True)
            (datadir / ".cookie").write_text("__cookie__:secret")
            with self.assertRaises(OSError):
                rpc.BitcoinRPC(datadir).call("getblockchaininfo")

    def test_only_the_start_of_a_body_is_read_and_only_for_200(self):
        seen = []

        class Reply:
            def __init__(self, status):
                self.status = status

            def read(self, amount=None):
                seen.append(amount)
                return b"975312\n"

        class Conn(self.Broken):
            status = 200

            def getresponse(self):
                return Reply(self.status)
        with mock.patch.object(rpc.http.client, "HTTPConnection", Conn):
            self.assertEqual(rpc.http_text(4080), "975312\n")
            Conn.status = 503
            self.assertIsNone(rpc.http_text(4080))
        self.assertEqual(seen, [4096])                             # bounded, and not read at all on a 503


class TrayMenu(unittest.TestCase):
    def test_a_click_runs_the_item_that_was_clicked(self):
        try:
            from bitfedot import tray
        except (ImportError, ValueError):
            self.skipTest("PyGObject is not available")
        ran, later = [], []
        menu = types.SimpleNamespace(items=[(10, "Bitcoin Core: synced", None), (4, "Open BitFedot", lambda: ran.append("open")),
                                            (8, "Quit…", lambda: ran.append("quit"))])
        with mock.patch.object(tray, "GLib", types.SimpleNamespace(idle_add=later.append)):
            tray.Tray._click(menu, 4)
        for callback in later:                                     # the main loop runs it afterwards
            callback()
        self.assertEqual(ran, ["open"])


class Quitting(unittest.TestCase):
    def test_the_app_can_be_closed_without_stopping_the_node(self):
        """The node is systemd services, not this window: restarting the app after an update
        must not cost Bitcoin Core its cache."""
        try:
            from bitfedot import app
        except (ImportError, ValueError):
            self.skipTest("PyGObject is not available")
        did = []
        window = types.SimpleNamespace(set_visible=lambda visible: did.append(("window", visible)))
        fake = types.SimpleNamespace(quit=lambda: did.append("quit"), _hold=lambda: did.append("hold"),
                                     _shut_down_and_quit=lambda: did.append("shutdown"), window=window)
        with mock.patch.object(node, "shut_down") as stop, mock.patch.object(node, "stop_all") as stop_all:
            app.App._quit_answer(fake, None, "quit")
            app.App._quit_answer(fake, None, "background")
            app.App._quit_answer(fake, None, "cancel")
            stop.assert_not_called()
            stop_all.assert_not_called()
        self.assertEqual(did, ["quit", "hold", ("window", False)])
        app.App._quit_answer(fake, None, "shutdown")               # only this one stops anything
        self.assertEqual(did[-1], "shutdown")


class About(unittest.TestCase):
    def test_bundled_whitepaper_is_genuine_and_can_be_saved(self):
        target = about.save_whitepaper(paths.DATA_DIR / "saved")
        self.assertTrue(target.name.endswith(".pdf"))
        self.assertEqual(verify.sha256_file(target), about.WHITEPAPER_SHA256)

    def test_everything_installed_is_thanked(self):
        thanked = " ".join(name for name, _url, _what in about.THANKS).lower()
        for word in ("bitcoin core", "fulcrum", "mempool", "tor", "sparrow", "mullvad", "obscura",
                     "librewolf", "element", "simplex", "fedora"):
            self.assertIn(word, thanked)
        self.assertEqual(about.SATOSHI[0], "Satoshi Nakamoto")


class Misc(unittest.TestCase):
    def test_versions(self):
        self.assertTrue(net.is_newer("32.1", "32.0"))
        self.assertTrue(net.is_newer("2.10.0", "2.9.9"))
        self.assertFalse(net.is_newer("32.1", "32.1"))
        self.assertFalse(net.is_newer("", "32.1"))

    def test_fedora_release_detection(self):
        paths.ensure_dirs()
        f = paths.DATA_DIR / "os-release"
        f.write_text('NAME="Fedora Linux"\nID=fedora\nVERSION_ID=45\n')
        self.assertEqual(system.fedora_release(f), 45)
        f.write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
        self.assertIsNone(system.fedora_release(f))
        self.assertIsNone(system.fedora_release(paths.DATA_DIR / "missing"))
        self.assertEqual(system.MIN_FEDORA, 45)

    def test_expected_hash(self):
        paths.ensure_dirs()
        f = paths.DATA_DIR / "sums"
        f.write_text("aa11  other.tar.gz\nBB22 *wanted.tar.gz\n")
        self.assertEqual(verify.expected_hash(f, "wanted.tar.gz"), "bb22")
        with self.assertRaises(verify.VerificationError):
            verify.expected_hash(f, "missing.tar.gz")

    def test_unsigned_file_has_no_good_signatures(self):
        paths.ensure_dirs()
        data, sig = paths.DATA_DIR / "data", paths.DATA_DIR / "data.asc"
        data.write_text("x")
        sig.write_text("not a signature")
        keys = sorted((paths.KEYS_DIR / "bitcoin").glob("*.gpg"))
        self.assertGreaterEqual(len(keys), verify.BITCOIN_MIN_SIGNERS)
        self.assertEqual(verify.good_signatures(sig, data, keys), [])

    def test_signature_helpers_reject_unsigned_input(self):
        paths.ensure_dirs()
        f = paths.DATA_DIR / "plain.txt"
        f.write_text("not signed")
        keys = list((paths.KEYS_DIR / "fulcrum").glob("*.asc"))
        self.assertTrue(keys)
        with self.assertRaises(verify.VerificationError):
            verify.signed_file(keys, (verify.FULCRUM_FPR,), f, f)
        with self.assertRaises((verify.VerificationError, OSError)):
            verify.clearsigned_text(keys, (verify.FULCRUM_FPR,), f)

    def test_settings_merge_and_delete(self):
        settings.update(versions={"bitcoin": "1"})
        s = settings.update(versions={"fulcrum": "2"})
        self.assertEqual((s["versions"]["bitcoin"], s["versions"]["fulcrum"]), ("1", "2"))
        self.assertNotIn("fulcrum", settings.update(versions={"fulcrum": None})["versions"])


class Migration(unittest.TestCase):
    """Adopting a pre-release install: nothing may be lost, and wherever it stops it can be run again."""

    def setUp(self):
        self.oc, self.od = paths.LEGACY_CONFIG_DIR, paths.LEGACY_DATA_DIR
        for folder in (paths.CONFIG_DIR, paths.DATA_DIR, self.oc, self.od):
            shutil.rmtree(folder, ignore_errors=True)
        (self.od / "chain/bitcoin").mkdir(parents=True)
        (self.od / "chain/bitcoin/blk00000.dat").write_text("blocks")
        (self.od / "tor/hs_fulcrum").mkdir(parents=True)
        (self.od / "tor/hs_fulcrum/hostname").write_text("old.onion\n")
        self.oc.mkdir(parents=True)
        (self.oc / "settings.json").write_text(json.dumps({
            "installed": True, "phase": "ibd", "data_dir": str(self.od / "chain"),
            "versions": {"bitcoin": "32.1"}, "secrets": {"rpc_salt": "abcd", "mempool_rpc_password": "x"}}))
        settings.update(theme="dark")                # BitFedot was opened once before adopting
        self.assertTrue(migrate.pending())

    def adopted(self):
        s = settings.load()
        self.assertTrue(s["installed"])
        self.assertFalse(s["adopting"])
        self.assertEqual(s["data_dir"], str(paths.DATA_DIR / "chain"))
        self.assertEqual(s["theme"], "dark")
        self.assertEqual(s["secrets"]["rpc_salt"], "abcd")
        self.assertEqual((paths.DATA_DIR / "chain/bitcoin/blk00000.dat").read_text(), "blocks")
        self.assertEqual((paths.TOR_DIR / "hs_fulcrum/hostname").read_text(), "old.onion\n")
        self.assertFalse(self.oc.exists() or self.od.exists())
        self.assertIn(str(paths.DATA_DIR / "chain" / "bitcoin"), (paths.UNIT_DIR / U_BITCOIND).read_text())
        self.assertFalse(migrate.pending())
        self.assertFalse(services.unfinished())
        self.assertTrue(node.snapshot()["installed"])

    def test_adopts_a_pre_release_install(self):
        migrate.adopt()
        self.adopted()

    def test_stopped_between_the_two_moves_the_old_install_is_still_found(self):
        real = os.rename

        def rename(src, dst):
            if Path(dst) == paths.CONFIG_DIR:
                raise OSError(errno.EACCES, "Permission denied")
            return real(src, dst)
        with mock.patch.object(migrate.os, "rename", rename), self.assertRaises(RuntimeError) as failure:
            migrate.adopt()
        self.assertIn("could not be renamed", str(failure.exception))
        self.assertFalse(self.od.exists())                              # the data is across,
        self.assertTrue(self.oc.exists())                               # the configuration is not:
        self.assertTrue(migrate.pending())                              # still an install to adopt,
        self.assertFalse(settings.load()["installed"])                  # and not mistaken for a working node
        self.assertFalse(node.snapshot()["installed"])
        migrate.adopt()
        self.adopted()

    def test_the_process_dying_at_any_step_leaves_something_that_can_be_run_again(self):
        steps = [(migrate, "_stop_old_services"), (migrate, "_complete_settings"), (settings, "ensure_secrets"),
                 (migrate, "_remove_old_app"), (services, "apply")]
        for index, (module, name) in enumerate(steps):
            with self.subTest(dies_in=name):
                if index:
                    self.setUp()
                with mock.patch.object(module, name, side_effect=Systemd.Killed(name)):
                    with self.assertRaises(Systemd.Killed):
                        migrate.adopt()
                self.assertTrue(migrate.pending())
                self.assertFalse(node.snapshot()["installed"])          # the wizard keeps it until it is done
                migrate.adopt()
                self.adopted()

    def test_nothing_is_stopped_or_moved_when_a_destination_holds_data(self):
        (paths.DATA_DIR / "chain/bitcoin").mkdir(parents=True)
        (paths.DATA_DIR / "chain/bitcoin/blk00001.dat").write_text("a chain of BitFedot's own")
        with Systemd() as sd, self.assertRaises(RuntimeError) as refusal:
            migrate.adopt()
        self.assertIn("already contains data (for example chain/bitcoin/blk00001.dat)", str(refusal.exception))
        self.assertEqual(sd.calls, [])                                  # the old node was not even stopped
        self.assertTrue(self.oc.exists() and self.od.exists())
        self.assertEqual((paths.DATA_DIR / "chain/bitcoin/blk00001.dat").read_text(), "a chain of BitFedot's own")
        self.assertTrue(migrate.pending())

    def test_what_is_left_of_downloads_is_not_in_the_way(self):
        (paths.DOWNLOADS_DIR / "bitcoin-32.1").mkdir(parents=True)
        (paths.DOWNLOADS_DIR / "bitcoin-32.1/SHA256SUMS").write_text("of an install that was started and given up")
        migrate.adopt()
        self.adopted()

    def test_nothing_is_moved_while_an_old_service_is_still_running(self):
        old_core = f"{paths.LEGACY_NAME}-bitcoind.service"
        (paths.UNIT_DIR / old_core).parent.mkdir(parents=True, exist_ok=True)
        (paths.UNIT_DIR / old_core).write_text("[Service]\n")
        with Systemd({old_core}) as sd:
            sd.refuse[("stop", old_core)] = (124, "systemctl: timed out")
            with self.assertRaises(RuntimeError) as failure:
                migrate.adopt()
            self.assertIn("Bitcoin Core of the old installation did not stop. Nothing was moved.",
                          str(failure.exception))
            self.assertTrue(self.oc.exists() and self.od.exists())
            self.assertTrue((paths.UNIT_DIR / old_core).exists())       # nor is its unit taken away under it
            sd.refuse.clear()
            migrate.adopt()
            self.assertNotIn(old_core, sd.running)
        self.assertFalse((paths.UNIT_DIR / old_core).exists())
        self.adopted()

    def test_started_but_not_running_yet_it_is_finished_by_running_it_again(self):
        with mock.patch.object(services, "apply", side_effect=RuntimeError("Fulcrum could not be started")):
            with self.assertRaises(RuntimeError):
                migrate.adopt()
        self.assertFalse(self.oc.exists() or self.od.exists())          # moved …
        s = settings.load()
        self.assertTrue(s["installed"] and s["adopting"])               # … but not a running node yet:
        self.assertFalse(node.snapshot()["installed"])                  # the wizard keeps it,
        self.assertFalse(node.on_launch())                              # and nothing starts it half done
        self.assertTrue(migrate.pending())
        migrate.adopt()
        self.adopted()

    def test_a_lock_file_that_reappears_during_the_move_is_not_in_the_way(self):
        real, calls = os.rename, []

        def rename(src, dst):
            calls.append(Path(dst))
            if Path(dst) == paths.CONFIG_DIR and calls.count(paths.CONFIG_DIR) == 1:
                paths.CONFIG_DIR.mkdir()                                # the app's status poll looked at its settings
                (paths.CONFIG_DIR / ".lock").touch()
                raise OSError(errno.ENOTEMPTY, "Directory not empty")
            return real(src, dst)
        with mock.patch.object(migrate.os, "rename", rename):
            migrate.adopt()
        self.assertEqual(calls.count(paths.CONFIG_DIR), 2)
        self.adopted()

    def test_a_folder_is_never_copied(self):
        with mock.patch.object(migrate.os, "rename", side_effect=OSError(errno.EXDEV, "Invalid cross-device link")), \
                mock.patch.object(migrate.shutil, "move") as move, mock.patch.object(migrate.shutil, "copytree") as copy:
            with self.assertRaises(RuntimeError) as failure:
                migrate.adopt()
        self.assertIn("could not be renamed", str(failure.exception))
        move.assert_not_called()
        copy.assert_not_called()
        self.assertEqual((self.od / "chain/bitcoin/blk00000.dat").read_text(), "blocks")
        self.assertTrue(migrate.pending())


if __name__ == "__main__":
    unittest.main()
