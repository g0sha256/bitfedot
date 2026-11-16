"""Connectivity: Tor up/down and routing, Bitcoin Core network mode, inbound
connections, onion services.

Choices are staged and applied together, because applying them restarts
Bitcoin Core (and, in order, everything that depends on it)."""
from gi.repository import Adw, Gtk

from .. import hardening, node, services, settings, system
from .widgets import copy_text, error_text, fmt_bytes, icon_button, radio_row, run_async, toast

MODES = [
    ("clearnet", "Clearnet only",
     "Peers over IPv4/IPv6 only. Fastest, with the most peers — but every peer and your ISP can "
     "see your IP address running a Bitcoin node. Bitcoin Core does not use Tor at all."),
    ("dual", "Clearnet + Tor  (recommended)",
     "Connects over IPv4/IPv6 and to onion peers through Tor. Most resilient against network "
     "partitioning and eclipse attacks, and bridges Tor-only nodes to the rest of the network. "
     "Your IP is still visible to clearnet peers."),
    ("tor_only", "Tor only",
     "Only onion peers; no clearnet connection or DNS lookup is ever made. Hides your IP from "
     "peers and hides from your ISP that you run a node (they only see Tor). Blocks arrive a "
     "little slower and the node depends entirely on Tor being reachable."),
    ("tor_proxy", "Everything through Tor  (onion + clearnet via exits)",
     "Onion peers directly, IPv4/IPv6 peers through Tor exit nodes. Hides your IP while still "
     "reaching the whole network, at the cost of relying on shared exit nodes that some peers "
     "ban or rate-limit."),
]
STAGED = ("net_mode", "listen_onion", "listen_clearnet", "natpmp", "tor_route", "vpn_iface",
          "onion_fulcrum", "onion_mempool")


class ConnectivityPage(Gtk.Box):
    title = "Connectivity"
    icon = "network-workgroup-symbolic"

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo = demo
        self.saved = None          # settings as last loaded/applied
        self.loading = False
        self.vpns = []

        self.banner = Adw.Banner(title="Initial sync runs over clearnet for speed. "
                                       "These choices take effect automatically when it completes.")
        self.append(self.banner)
        page = Adw.PreferencesPage(vexpand=True)
        self.append(page)

        # ---- Tor ----------------------------------------------------------
        g = Adw.PreferencesGroup(title="Tor")
        self.tor_row = Adw.SwitchRow(title="Tor", subtitle="Down")
        self.tor_row.add_prefix(Gtk.Image(icon_name="security-high-symbolic"))
        self.tor_row.connect("notify::active", self._tor_switched)
        g.add(self.tor_row)
        row = Adw.ActionRow(title="Reconnect", subtitle="Restart Tor and build fresh connections "
                                                        "to the network")
        self.reconnect = Gtk.Button(label="Reconnect", valign=Gtk.Align.CENTER)
        self.reconnect.connect("clicked", lambda *_: self._tor_action(node.tor_reconnect, "Tor is reconnecting"))
        row.add_suffix(self.reconnect)
        g.add(row)
        row = Adw.ActionRow(title="New identity", subtitle="Keep Tor running but switch to new "
                                                           "circuits for future connections")
        self.newnym = Gtk.Button(label="New identity", valign=Gtk.Align.CENTER)
        self.newnym.connect("clicked", lambda *_: self._tor_action(node.tor_new_identity, "New circuits requested"))
        row.add_suffix(self.newnym)
        g.add(row)
        page.add(g)

        # ---- Tor routing --------------------------------------------------
        g = Adw.PreferencesGroup(title="How Tor reaches the internet")
        self.route_direct_row, self.route_direct = radio_row("Directly (clearnet)", "")
        self.route_vpn_row, self.route_vpn = radio_row("Through a VPN", "", self.route_direct)
        self.vpn_combo = Adw.ComboRow(title="VPN interface")
        self.vpn_status = Adw.ActionRow(title="VPN route check")
        for w in (self.route_direct_row, self.route_vpn_row, self.vpn_combo, self.vpn_status):
            g.add(w)
        self.route_direct.connect("toggled", self._changed)
        self.vpn_combo.connect("notify::selected", self._changed)
        page.add(g)

        # ---- Bitcoin network mode ----------------------------------------
        g = Adw.PreferencesGroup(title="Bitcoin Core network",
                                 description="Which networks your node uses to find and talk to peers.")
        self.mode_checks = {}
        first = None
        for key, title, text in MODES:
            row, check = radio_row(title, text, first)
            first = first or check
            check.connect("toggled", self._changed)
            self.mode_checks[key] = check
            g.add(row)
        page.add(g)

        # ---- inbound ------------------------------------------------------
        g = Adw.PreferencesGroup(title="Incoming connections",
                                 description="Accepting incoming peers makes your node a full "
                                             "contributor instead of only a consumer.")
        self.in_onion = Adw.SwitchRow(
            title="Accept peers over Tor",
            subtitle="Publishes an onion service for your node. Other nodes can reach you "
                     "without learning your IP address; no router setup needed.")
        self.in_clear = Adw.SwitchRow(
            title="Accept peers on your public IP",
            subtitle="Listens on port 8333. Strengthens the network but advertises your IP as "
                     "a Bitcoin node. Needs port 8333 open on your router and firewall.")
        self.natpmp = Adw.SwitchRow(
            title="Automatic port forwarding",
            subtitle="Ask the router to open port 8333 using PCP / NAT-PMP.")
        self.onion_addr = Adw.ActionRow(title="Your node's onion address", subtitle="—",
                                        subtitle_selectable=True)
        self.onion_addr.add_suffix(icon_button(
            "edit-copy-symbolic", "Copy", lambda: copy_text(self, self.onion_addr.get_subtitle())))
        for w in (self.in_onion, self.in_clear, self.natpmp):
            w.connect("notify::active", self._changed)
            g.add(w)
        g.add(self.onion_addr)
        page.add(g)

        # ---- onion services ----------------------------------------------
        g = Adw.PreferencesGroup(title="Remote access over Tor",
                                 description="Reach your own services from anywhere with a "
                                             "Tor-capable wallet or Tor Browser. Nothing is exposed "
                                             "on clearnet.")
        self.hs = {}
        for key, title, sub in (("fulcrum", "Fulcrum (Electrum server)", "Connect Sparrow, Electrum or a "
                                 "hardware-wallet app to your own node."),
                                ("mempool", "Mempool explorer", "Open your private block explorer in Tor Browser.")):
            sw = Adw.SwitchRow(title=title, subtitle=sub)
            sw.connect("notify::active", self._changed)
            addr = Adw.ActionRow(title="Address", subtitle="—", subtitle_selectable=True, visible=False)
            addr.add_suffix(icon_button("edit-copy-symbolic", "Copy",
                                        lambda a=addr: copy_text(self, a.get_subtitle())))
            g.add(sw)
            g.add(addr)
            self.hs[key] = (sw, addr)
        page.add(g)

        # ---- apply bar ----------------------------------------------------
        self.bar = Gtk.ActionBar(revealed=False)
        self.bar_label = Gtk.Label(label="Unsaved changes", xalign=0)
        self.bar_label.add_css_class("dim-label")
        self.bar.pack_start(self.bar_label)
        apply = Gtk.Button(label="Apply")
        apply.add_css_class("suggested-action")
        apply.connect("clicked", lambda *_: self._apply())
        revert = Gtk.Button(label="Revert")
        revert.connect("clicked", lambda *_: self._load(self.saved))
        self.bar.pack_end(apply)
        self.bar.pack_end(revert)
        self.apply_button = apply
        self.append(self.bar)

    # -------------------------------------------------------------- state --
    def _staged(self) -> dict:
        idx = self.vpn_combo.get_selected()
        via_vpn = self.route_vpn.get_active()
        return {
            "net_mode": next(k for k, c in self.mode_checks.items() if c.get_active()),
            "listen_onion": self.in_onion.get_active(),
            "listen_clearnet": self.in_clear.get_active(),
            "natpmp": self.natpmp.get_active(),
            "tor_route": "vpn" if via_vpn else "direct",
            "vpn_iface": self.vpns[idx]["name"] if via_vpn and 0 <= idx < len(self.vpns)
            else self.saved["vpn_iface"],
            "onion_fulcrum": self.hs["fulcrum"][0].get_active(),
            "onion_mempool": self.hs["mempool"][0].get_active(),
        }

    def _load(self, s):
        self.loading = True
        self.saved = {k: s[k] for k in STAGED}
        self.mode_checks[s["net_mode"]].set_active(True)
        self.in_onion.set_active(s["listen_onion"])
        self.in_clear.set_active(s["listen_clearnet"])
        self.natpmp.set_active(s["natpmp"])
        self._refresh_vpns(force=True)
        (self.route_vpn if s["tor_route"] == "vpn" else self.route_direct).set_active(True)
        for key in self.hs:
            self.hs[key][0].set_active(s[f"onion_{key}"])
        self.loading = False
        self._changed()

    def _refresh_vpns(self, force=False):
        vpns = system.vpn_interfaces()
        names = [v["name"] for v in vpns]
        if not force and names == [v["name"] for v in self.vpns]:
            self.vpns = vpns
            return
        was_loading, self.loading = self.loading, True
        want = self.saved["vpn_iface"] if force else (
            self.vpns[self.vpn_combo.get_selected()]["name"]
            if 0 <= self.vpn_combo.get_selected() < len(self.vpns) else self.saved["vpn_iface"])
        self.vpns = vpns
        self.vpn_combo.set_model(Gtk.StringList.new([f"{v['name']}  ({v['kind']})" for v in vpns]))
        if want in names:
            self.vpn_combo.set_selected(names.index(want))
        self.loading = was_loading

    def _changed(self, *_):
        if self.loading or self.saved is None:
            return
        st = self._staged()
        mode = st["net_mode"]
        self.in_onion.set_sensitive(mode != "clearnet")
        self.in_clear.set_sensitive(mode in ("clearnet", "dual"))
        self.natpmp.set_sensitive(mode in ("clearnet", "dual") and st["listen_clearnet"])
        via_vpn = st["tor_route"] == "vpn"
        self.vpn_combo.set_visible(via_vpn)
        self.vpn_status.set_visible(via_vpn)
        self._describe_routes(st)
        dirty = st != self.saved
        self.bar.set_revealed(dirty)

    def _describe_routes(self, st):
        dev = system.default_route_device()
        self.route_direct_row.set_title("Directly (clearnet)")
        if any(v["name"] == dev for v in self.vpns):
            self.route_direct_row.set_title("System default route")
            self.route_direct_row.set_subtitle(
                f"Tor follows the system's default route — right now that is the VPN “{dev}”, so "
                "Tor already leaves through it. If the VPN disconnects, Tor silently continues "
                "over your normal connection.")
        else:
            self.route_direct_row.set_subtitle(
                f"Tor connects straight out through your default route ({dev or 'none'}). Your "
                "ISP can see that you use Tor, but not what for.")
        if self.vpns:
            self.route_vpn_row.set_sensitive(True)
            self.route_vpn_row.set_subtitle(
                "Tor's connections are bound to the VPN interface. Your ISP sees only the VPN; the "
                "VPN provider sees Tor traffic but not its content. Kill switch: if the VPN drops, "
                "Tor stops rather than falling back to clearnet.")
        else:
            self.route_vpn_row.set_sensitive(self.route_vpn.get_active())
            self.route_vpn_row.set_subtitle("No active VPN interface detected. Connect your VPN "
                                            "(WireGuard, OpenVPN, …) and it will appear here.")
        if st["tor_route"] == "vpn":
            v = next((v for v in self.vpns if v["name"] == st["vpn_iface"]), None)
            if not v:
                self.vpn_status.set_subtitle(f"“{st['vpn_iface'] or 'VPN'}” is down — Tor stays stopped until it returns.")
            else:
                src = (v["v4"] or v["v6"])[0]
                ok = system.route_device(src, "1.1.1.1" if v["v4"] else "2606:4700:4700::1111") == v["name"]
                self.vpn_status.set_subtitle(
                    f"✓ Traffic from {src} leaves through {v['name']}." if ok else
                    f"⚠ The system does not route traffic from {src} through {v['name']} "
                    "(split-tunnel VPN?). Tor would be unable to connect.")

    def update(self, snap):
        s, tor, btc = snap["settings"], snap["tor"], snap["bitcoin"]
        if self.saved is None:
            self._load(s)
        else:
            self._refresh_vpns()
            if not self.bar.get_revealed():
                self._describe_routes(self._staged())
        ibd_clear = services.in_ibd(s) and s["ibd_clearnet"]
        self.banner.set_revealed(ibd_clear)

        self.loading = True
        self.tor_row.set_active(s["tor_enabled"])
        self.loading = False
        self.tor_row.set_sensitive(not ibd_clear)
        if ibd_clear:
            sub = "Starts automatically when the initial sync completes"
        elif tor["state"] == "running":
            sub = f"Connected · ↓ {fmt_bytes(tor.get('read'))}  ↑ {fmt_bytes(tor.get('written'))}"
        else:
            sub = tor["message"]
        self.tor_row.set_subtitle(sub)
        up = tor["state"] in ("running", "starting")
        self.reconnect.set_sensitive(up)
        self.newnym.set_sensitive(tor["state"] == "running")

        self.onion_addr.set_subtitle(btc.get("onion") or "Not published")
        for key, (sw, addr) in self.hs.items():
            onion = snap[key].get("onion", "")
            addr.set_visible(bool(onion))
            if onion:
                addr.set_subtitle(f"{onion}:50001" if key == "fulcrum" else f"http://{onion}")

    # ------------------------------------------------------------ actions --
    def _tor_switched(self, row, _p):
        if self.loading:
            return
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        up = row.get_active()
        run_async(lambda: node.tor_set(up), lambda _r: toast(self, "Tor is starting" if up else "Tor stopped"),
                  lambda e: toast(self, error_text(e)))

    def _tor_action(self, fn, done):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        run_async(fn, lambda _r: toast(self, done), lambda e: toast(self, error_text(e)))

    def _apply(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        st = self._staged()
        self.apply_button.set_sensitive(False)

        def done(changed):
            self.apply_button.set_sensitive(True)
            self.saved = st
            self.bar.set_revealed(False)
            toast(self, "Applied — services were restarted safely" if changed else "Applied")
            self.get_root().app.poll_now()

        def failed(e):
            self.apply_button.set_sensitive(True)
            toast(self, error_text(e))
        def work():
            changed = node.apply_settings(**st)
            # The strict firewall zone opens port 8333 only while clearnet peers are accepted.
            if hardening.firewall_out_of_sync(settings.load()):
                hardening.sync_firewall()
            return changed
        self.get_root().app.poll_now()
        run_async(work, done, failed)
