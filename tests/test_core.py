"""Offline tests: config rendering, service orchestration, hardening rules,
verification, explorer helpers and migration. No network, no systemd, no root.

    python3 -m unittest discover tests
"""
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["BITFEDOT_ROOT"] = tempfile.mkdtemp(prefix="bitfedot-test-")

from bitfedot import (about, apps, eta, explorer, hardening, installer, migrate, net, paths,  # noqa: E402
                      pins, selfupdate, services, settings, system, verify)
from bitfedot.catalog import CATALOG, CATEGORIES  # noqa: E402
from bitfedot.paths import U_BITCOIND, U_FULCRUM, U_MEMPOOL, U_TOR  # noqa: E402


def cfg(**kw):
    s = settings.ensure_secrets()
    return {**settings.DEFAULTS, **s, "installed": True, "versions": {"mempool": "3.3.2"}, **kw}


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
        s = cfg(phase="ready")
        services.apply(s)
        self.assertEqual(services.apply(s), set())
        self.assertTrue((paths.QUADLET_DIR / "bitfedot-mempool.pod").exists())
        services.apply({**s, "mempool_enabled": False})
        self.assertFalse((paths.QUADLET_DIR / "bitfedot-mempool.pod").exists())
        self.assertEqual(services.activity(), "")

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

    def run_apply(self, s, running, restart=()):
        calls = []

        def fake_systemctl(*args, **_kw):
            calls.append(args)
        states = {u: ("active" if u in running else "inactive") for u in services.desired_units(s)}
        with mock.patch.object(system, "systemctl", fake_systemctl), \
                mock.patch.object(system, "unit_states", lambda units: states):
            services.apply(s, restart=restart)
        stops = [a[-1] for a in calls if a[0] == "stop"]
        starts = [a[-1] for a in calls if "start" in a and a[-1] != paths.U_AGENT]
        return stops, starts

    def setUp(self):
        self.s = cfg(phase="ready")
        services.apply(self.s)                       # files on disk match: no change pending
        self.all = {U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL}

    def test_no_change_touches_nothing(self):
        self.assertEqual(self.run_apply(self.s, self.all), ([], []))

    def test_bitcoind_restart_cycles_dependents_in_order(self):
        stops, starts = self.run_apply(self.s, self.all, restart=[U_BITCOIND])
        self.assertEqual(stops, [U_MEMPOOL, U_FULCRUM, U_BITCOIND])
        self.assertEqual(starts, [U_BITCOIND, U_FULCRUM, U_MEMPOOL])

    def test_tor_restart_leaves_the_rest_alone(self):
        stops, starts = self.run_apply(self.s, self.all, restart=[U_TOR])
        self.assertEqual((stops, starts), ([U_TOR], [U_TOR]))

    def test_stop_all_then_start_all(self):
        stops, starts = self.run_apply({**self.s, "all_stopped": True}, self.all)
        self.assertEqual(stops, [U_MEMPOOL, U_FULCRUM, U_BITCOIND, U_TOR])
        self.assertEqual(starts, [])
        stops, starts = self.run_apply(self.s, set())
        self.assertEqual(stops, [])
        self.assertEqual(starts, [U_TOR, U_BITCOIND, U_FULCRUM, U_MEMPOOL])

    def test_stopping_bitcoind_takes_dependents_down_first(self):
        stops, _ = self.run_apply({**self.s, "bitcoind_enabled": False}, self.all)
        self.assertEqual(stops, [U_MEMPOOL, U_FULCRUM, U_BITCOIND])


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
    def test_adopts_a_pre_release_install(self):
        shutil.rmtree(paths.CONFIG_DIR, ignore_errors=True)
        shutil.rmtree(paths.DATA_DIR, ignore_errors=True)
        oc, od = paths.LEGACY_CONFIG_DIR, paths.LEGACY_DATA_DIR
        (od / "chain/bitcoin").mkdir(parents=True)
        (od / "chain/bitcoin/blk00000.dat").write_text("blocks")
        oc.mkdir(parents=True)
        (oc / "settings.json").write_text(json.dumps({
            "installed": True, "phase": "ibd", "data_dir": str(od / "chain"),
            "versions": {"bitcoin": "32.1"}, "secrets": {"rpc_salt": "abcd", "mempool_rpc_password": "x"}}))
        settings.update(theme="dark")                # BitFedot was opened once before adopting
        self.assertTrue(migrate.pending())
        migrate.adopt()
        s = settings.load()
        self.assertTrue(s["installed"])
        self.assertEqual(s["data_dir"], str(paths.DATA_DIR / "chain"))
        self.assertEqual(s["theme"], "dark")
        self.assertEqual((paths.DATA_DIR / "chain/bitcoin/blk00000.dat").read_text(), "blocks")
        self.assertFalse(oc.exists() or od.exists())
        self.assertFalse(migrate.pending())


if __name__ == "__main__":
    unittest.main()
