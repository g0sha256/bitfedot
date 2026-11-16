"""Security page: check-up of this Fedora system plus the hardening switches.

Switches that need administrator rights (firewall, kill switch) run one polkit
prompt; if it is cancelled or fails, the switch snaps back and nothing changed.
"""
from gi.repository import Adw, Gtk

from .. import hardening, node, settings, system
from .widgets import error_text, run_async, toast

KS_HELP = ("Loaded before the network comes up and kept across reboots. Your VPN app can still "
           "reconnect (its own tunnel packets are recognised), and the local network stays "
           "reachable if allowed below. To switch it off without this app:  "
           "sudo systemctl disable --now bitfedot-killswitch")


class SecurityPage(Gtk.Box):
    title = "Security"
    icon = "channel-secure-symbolic"

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo = demo
        self.loading = False
        self.snap = None
        self.check_rows = []
        self.vpns = []
        self.checked = False
        page = Adw.PreferencesPage(vexpand=True)
        self.append(page)

        # ---- check-up -----------------------------------------------------
        self.g_check = Adw.PreferencesGroup(title="Security check-up",
                                            description="How this Fedora system is set up right now.")
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", valign=Gtk.Align.CENTER,
                             tooltip_text="Check again")
        refresh.add_css_class("flat")
        refresh.connect("clicked", lambda *_: self.run_checkup())
        self.g_check.set_header_suffix(refresh)
        page.add(self.g_check)

        # ---- services -----------------------------------------------------
        g = Adw.PreferencesGroup(title="Services")
        self.sandbox = Adw.SwitchRow(
            title="Sandbox every service",
            subtitle="Bitcoin Core, Tor and Fulcrum see the system read-only, can write only to "
                     "their own data, get no devices and no new privileges; Mempool's containers "
                     "drop all capabilities. Changing this restarts the services safely.")
        self.sandbox.connect("notify::active", lambda r, _p: self._setting("sandbox", r.get_active(),
                                                                           "Restarting services safely…"))
        self.private = Adw.SwitchRow(
            title="Broadcast my transactions privately",
            subtitle="Transactions you send leave over short-lived Tor connections to random "
                     "peers instead of your regular ones, so nobody can link them to your node. "
                     "Needs a network mode that uses Tor.")
        self.private.connect("notify::active", lambda r, _p: self._setting(
            "private_broadcast", r.get_active(), "Restarting Bitcoin Core safely…"))
        g.add(self.sandbox)
        g.add(self.private)
        page.add(g)

        # ---- supply chain -------------------------------------------------
        g = Adw.PreferencesGroup(
            title="Software supply chain",
            description="How much independent confirmation BitFedot demands before it installs or "
                        "runs something.")
        self.signers = Adw.SpinRow.new_with_range(3, 8, 1)
        self.signers.set_title("Bitcoin Core: builder signatures required")
        self.signers.set_subtitle(
            "Bitcoin Core releases are built reproducibly by independent developers who each sign "
            "the result. More required signatures means more people would have to collude — but a "
            "new release can only be installed once that many have signed (usually 8–12 do).")
        self.signers.connect("notify::value", lambda r, _p: self._plain_setting(
            "core_min_signers", int(r.get_value())))
        self.pinned = Adw.SwitchRow(
            title="Only run vouched-for container images",
            subtitle="Mempool does not sign its container images. With this on, only images whose "
                     "exact content hash is listed in BitFedot — itself delivered through signed "
                     "updates — are downloaded and run. New Mempool versions then arrive with a "
                     "BitFedot update instead of straight from the registry.")
        self.pinned.connect("notify::active", lambda r, _p: self._plain_setting(
            "pinned_images_only", r.get_active()))
        g.add(self.signers)
        g.add(self.pinned)
        page.add(g)

        # ---- firewall -----------------------------------------------------
        g = Adw.PreferencesGroup(
            title="Firewall",
            description="Fedora Workstation ships with every port from 1025 upwards open to the "
                        "network. BitFedot's services only listen on this computer, but other "
                        "programs may not.")
        self.fw_status = Adw.ActionRow(title="Current state", subtitle="…")
        self.fw_strict = Adw.SwitchRow(
            title="Strict firewall",
            subtitle="Moves this computer into its own firewalld zone that refuses all incoming "
                     "connections — except the Bitcoin port, and only while you accept clearnet "
                     "peers. Asks for your password.")
        self.fw_strict.connect("notify::active", lambda r, _p: self._firewall(r.get_active()))
        self.fw_ssh = Adw.SwitchRow(title="Keep SSH reachable",
                                    subtitle="Leave port 22 open in the strict zone.")
        self.fw_ssh.connect("notify::active", lambda r, _p: self._firewall_ssh(r.get_active()))
        for w in (self.fw_status, self.fw_strict, self.fw_ssh):
            g.add(w)
        page.add(g)

        # ---- kill switch --------------------------------------------------
        g = Adw.PreferencesGroup(
            title="VPN kill switch",
            description="System-wide: nothing on this computer may reach the internet except "
                        "through the VPN. If the VPN drops, traffic stops instead of leaking "
                        "over your normal connection.")
        self.ks = Adw.SwitchRow(title="Block all traffic outside the VPN", subtitle=KS_HELP)
        self.ks.connect("notify::active", lambda r, _p: self._killswitch(r.get_active()))
        self.ks_iface = Adw.ComboRow(title="VPN interface")
        self.ks_lan = Adw.SwitchRow(title="Allow the local network", active=True,
                                    subtitle="Printers, file shares and SSH on your LAN keep working.")
        self.ks_endpoints = Adw.EntryRow(title="VPN server addresses (optional, comma-separated)")
        self.ks_note = Adw.ActionRow(
            title="When is the address list needed?",
            subtitle="Only for VPN clients that do not mark their own packets (plain OpenVPN, "
                     "some IPsec setups). WireGuard-based apps and NetworkManager need nothing here.")
        for w in (self.ks, self.ks_iface, self.ks_lan, self.ks_endpoints, self.ks_note):
            g.add(w)
        page.add(g)

    # --------------------------------------------------------------- state --
    def update(self, snap):
        self.snap = snap
        s = snap["settings"]
        self.loading = True
        self.sandbox.set_active(bool(s["sandbox"]))
        self.private.set_active(bool(s["private_broadcast"]))
        self.private.set_sensitive(s["net_mode"] != "clearnet")
        self.signers.set_value(max(3, int(s["core_min_signers"])))
        self.pinned.set_active(bool(s["pinned_images_only"]))
        self.fw_strict.set_active(bool(s["fw_strict"]))
        self.fw_ssh.set_active(bool(s["fw_allow_ssh"]))
        self.fw_ssh.set_visible(bool(s["fw_strict"]))
        self.ks.set_active(bool(s["killswitch"]))
        editable = not s["killswitch"]        # options are fixed while the switch is on
        for w in (self.ks_iface, self.ks_lan, self.ks_endpoints):
            w.set_sensitive(editable)
        if not editable:
            self.ks_lan.set_active(bool(s["ks_allow_lan"]))
            if self.ks_endpoints.get_text() != s["ks_endpoints"]:
                self.ks_endpoints.set_text(s["ks_endpoints"])
        self._refresh_vpns(s)
        self.loading = False
        busy = bool(snap.get("activity"))
        self.sandbox.set_sensitive(not busy)
        if self.get_mapped() and not self.checked:
            self.run_checkup()

    def refresh(self):
        self.run_checkup()

    def _refresh_vpns(self, s):
        vpns = system.vpn_interfaces()
        names = [v["name"] for v in vpns]
        if s["killswitch"] and s["ks_iface"] and s["ks_iface"] not in names:
            names.append(s["ks_iface"])              # configured interface is currently down
        if names != self.vpns:
            current = self.vpns[self.ks_iface.get_selected()] if \
                0 <= self.ks_iface.get_selected() < len(self.vpns) else (s["ks_iface"] or s["vpn_iface"])
            self.vpns = names
            self.ks_iface.set_model(Gtk.StringList.new(names or ["No VPN interface found"]))
            if current in names:
                self.ks_iface.set_selected(names.index(current))
        if s["killswitch"] and s["ks_iface"] in self.vpns:
            self.ks_iface.set_selected(self.vpns.index(s["ks_iface"]))
        self.ks.set_sensitive(bool(self.vpns) or bool(s["killswitch"]))

    def run_checkup(self):
        if self.snap is None:
            return
        self.checked = True
        s = self.snap["settings"]

        def work():
            if self.demo:
                return ([{"title": "SELinux", "ok": True, "detail": "Enforcing"},
                         {"title": "Firewall", "ok": True, "detail": "firewalld is active (zone “bitfedot”)"},
                         {"title": "Inbound ports", "ok": True,
                          "detail": "Only explicitly allowed services are reachable"},
                         {"title": "Disk encryption", "ok": True,
                          "detail": "Node data is on an encrypted (LUKS) volume"},
                         {"title": "Service sandbox", "ok": True,
                          "detail": "Every service runs in a systemd sandbox"},
                         {"title": "Automatic security updates", "ok": False,
                          "detail": "Off — you install updates manually (see Updates)"}],
                        {"running": True, "zone": "bitfedot", "strict": True, "wide_open": False,
                         "services": ["dhcpv6-client"], "ports": []})
            return hardening.checkup(s), hardening.firewall_status()

        def done(result):
            items, fw = result
            for row in self.check_rows:
                self.g_check.remove(row)
            self.check_rows = []
            for item in items:
                row = Adw.ActionRow(title=item["title"], subtitle=item["detail"])
                icon, css = {True: ("object-select-symbolic", "success"),
                             False: ("dialog-warning-symbolic", "warning"),
                             None: ("dialog-information-symbolic", "dim-label")}[item["ok"]]
                img = Gtk.Image(icon_name=icon)
                img.add_css_class(css)
                row.add_prefix(img)
                self.g_check.add(row)
                self.check_rows.append(row)
            if not fw.get("running"):
                self.fw_status.set_subtitle("firewalld is not running")
                self.fw_strict.set_sensitive(bool(self.snap["settings"]["fw_strict"]))
            else:
                opened = ", ".join(fw["services"] + fw["ports"]) or "nothing"
                self.fw_status.set_subtitle(f"Zone “{fw['zone']}” · open to the network: {opened}")
                self.fw_strict.set_sensitive(True)
        run_async(work, done, lambda e: toast(self, error_text(e)))

    # ------------------------------------------------------------- actions --
    def _guard(self) -> bool:
        """True if the change should be ignored (programmatic update or demo)."""
        if self.loading:
            return True
        if self.demo:
            toast(self, "Demo mode — nothing is changed")
            return True
        return False

    def _after(self, message=None):
        def done(_result=None):
            if message:
                toast(self, message)
            self.get_root().app.poll_now()
            self.run_checkup()
        return done

    def _failed(self, e):
        toast(self, error_text(e))
        self.get_root().app.poll_now()      # snaps the switch back to the real state

    def _setting(self, key, value, message):
        if self._guard():
            return
        toast(self, message)
        run_async(lambda: node.apply_settings(**{key: value}), self._after(), self._failed)

    def _plain_setting(self, key, value):
        """A preference that only affects future installs: nothing to restart."""
        if self._guard():
            return
        run_async(lambda: settings.update(**{key: value}), None, self._failed)

    def _firewall(self, enable):
        if self._guard():
            return
        if not enable:
            return run_async(lambda: hardening.set_strict_firewall(False),
                             self._after("Firewall restored to its previous zone"), self._failed)
        ssh_running = system.run(["systemctl", "is-active", "sshd"]).stdout.strip() == "active"
        dlg = Adw.AlertDialog(
            heading="Close all incoming ports?",
            body="This computer will refuse every incoming connection: file sharing, media "
                 "casting, KDE Connect, game servers and similar will stop being reachable from "
                 "other devices. Outgoing connections are not affected.\n\n"
                 + ("An SSH server is running — it will stay reachable." if ssh_running else
                    "You can switch this off again at any time."))
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Enable strict firewall")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)

        def answer(_d, response):
            if response != "ok":
                return self.get_root().app.poll_now()
            run_async(lambda: hardening.set_strict_firewall(True, allow_ssh=ssh_running),
                      self._after("Strict firewall is active"), self._failed)
        dlg.connect("response", answer)
        dlg.present(self.get_root())

    def _firewall_ssh(self, allow):
        if self._guard():
            return
        run_async(lambda: hardening.set_strict_firewall(True, allow_ssh=allow), self._after(), self._failed)

    def _killswitch(self, enable):
        if self._guard():
            return
        if not enable:
            return run_async(lambda: hardening.set_killswitch(False),
                             self._after("Kill switch removed"), self._failed)
        idx = self.ks_iface.get_selected()
        iface = self.vpns[idx] if 0 <= idx < len(self.vpns) else ""
        lan, endpoints = self.ks_lan.get_active(), self.ks_endpoints.get_text()
        try:
            hardening.killswitch_rules(iface, lan, endpoints)       # validate before asking
        except ValueError as e:
            toast(self, f"Check the settings: {e}")
            return self.get_root().app.poll_now()
        dlg = Adw.AlertDialog(
            heading=f"Allow internet traffic only through “{iface}”?",
            body="Everything on this computer — browser, updates, the node — will be cut off from "
                 f"the internet whenever “{iface}” is not connected, including right after boot "
                 "until the VPN is up.\n\nTo undo it without this app:\n"
                 "sudo systemctl disable --now bitfedot-killswitch")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Enable kill switch")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.DESTRUCTIVE)

        def answer(_d, response):
            if response != "ok":
                return self.get_root().app.poll_now()
            run_async(lambda: hardening.set_killswitch(True, iface, lan, endpoints),
                      self._after("Kill switch is active"), self._failed)
        dlg.connect("response", answer)
        dlg.present(self.get_root())
