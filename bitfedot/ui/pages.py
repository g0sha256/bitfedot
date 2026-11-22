"""Logs and Settings pages."""

from gi.repository import Adw, Gio, Gtk

from .. import hardening, installer, node, paths, services, settings, system
from .widgets import error_text, run_async, toast

THEMES = ("system", "light", "dark")


class LogsPage(Gtk.Box):
    title = "Logs"
    icon = "utilities-terminal-symbolic"
    UNITS = [("Bitcoin Core", paths.U_BITCOIND), ("Tor", paths.U_TOR), ("Fulcrum", paths.U_FULCRUM),
             ("Mempool backend", paths.U_MEMPOOL_PARTS[1]), ("Mempool database", paths.U_MEMPOOL_PARTS[0]),
             ("Mempool web", paths.U_MEMPOOL_PARTS[2]), ("BitFedot agent", paths.U_AGENT)]

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo = demo
        self.loading = False
        bar = Gtk.Box(spacing=12, margin_top=12, margin_bottom=12, margin_start=18, margin_end=18)
        self.drop = Gtk.DropDown.new_from_strings([n for n, _ in self.UNITS])
        self.drop.connect("notify::selected", lambda *_: self.refresh())
        self.follow = Gtk.CheckButton(label="Follow", active=True)
        bar.append(self.drop)
        bar.append(self.follow)
        self.append(bar)
        self.view = Gtk.TextView(editable=False, monospace=True, cursor_visible=False,
                                 wrap_mode=Gtk.WrapMode.CHAR)
        self.view.add_css_class("bf-log")
        self.scroll = Gtk.ScrolledWindow(child=self.view, vexpand=True)
        self.scroll.add_css_class("card")
        self.scroll.set_margin_start(18)
        self.scroll.set_margin_end(18)
        self.scroll.set_margin_bottom(18)
        self.append(self.scroll)

    def update(self, snap):
        if self.get_mapped() and self.follow.get_active():
            self.refresh()

    def refresh(self):
        if self.loading:
            return
        if self.demo:
            self.view.get_buffer().set_text("Demo mode — no services are running.")
            return
        self.loading = True
        unit = self.UNITS[self.drop.get_selected()][1]

        def done(text):
            self.loading = False
            buf = self.view.get_buffer()
            text = text.strip() or "No log entries yet."
            if buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False) != text:
                buf.set_text(text)
                adj = self.scroll.get_vadjustment()
                from gi.repository import GLib
                GLib.idle_add(lambda: adj.set_value(adj.get_upper()) and False)
        run_async(lambda: system.journal(unit, 300), done,
                  lambda e: setattr(self, "loading", False))


class SettingsPage(Gtk.Box):
    title = "Settings"
    icon = "emblem-system-symbolic"

    def __init__(self, demo=False, app=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo, self.app = demo, app
        self.loading = False
        self.snap = None
        page = Adw.PreferencesPage(vexpand=True)
        self.append(page)

        g = Adw.PreferencesGroup(title="Appearance")
        self.theme = Adw.ComboRow(title="Theme", model=Gtk.StringList.new(
            ["Follow system", "Light", "Dark"]))
        self.theme.connect("notify::selected", lambda r, _p: self._theme(r.get_selected()))
        g.add(self.theme)
        page.add(g)

        g = Adw.PreferencesGroup(title="Running")
        self.sw = {}
        self.sleep_busy = False
        self._switch(g, "linger", "Keep the node running when logged out",
                     "Services keep running after you log out and start at boot, without a session.")
        self._switch(g, "keep_awake", "Keep the computer awake while the node runs", node.AWAKE_INFO)
        self.never_sleep = Adw.SwitchRow(
            title="Never sleep, also with nobody logged in",
            subtitle="Switches sleep off for the whole computer; asks for administrator rights. Without "
                     "it the login screen puts an idle computer to sleep after a while, and the node "
                     "with it.")
        self.never_sleep.connect("notify::active", lambda r, _p: self._never_sleep(r.get_active()))
        g.add(self.never_sleep)
        for key, title, sub in (
            ("autostart", "Start BitFedot at login", "Opens quietly in the background / tray."),
            ("background", "Keep running when the window is closed",
             "Closing the window hides it; use the tray icon or launch the app again to return."),
        ):
            self._switch(g, key, title, sub)
        self.tray_row = Adw.ActionRow(title="Tray icon")
        self.tray_btn = Gtk.Button(label="Enable", valign=Gtk.Align.CENTER, visible=False)
        self.tray_btn.connect("clicked", lambda *_: self._install_tray())
        self.tray_row.add_suffix(self.tray_btn)
        g.add(self.tray_row)
        page.add(g)

        g = Adw.PreferencesGroup(title="Notifications")
        self._switch(g, "status_notifications", "Announce progress",
                     "Desktop notifications for sync milestones, Fulcrum's index, the explorer becoming "
                     "ready, and a service that stopped unexpectedly.")
        page.add(g)

        g = Adw.PreferencesGroup(title="Updates")
        self._switch(g, "auto_check_updates", "Check for updates daily",
                     "You are notified; nothing is ever installed without your confirmation.")
        self._switch(g, "updates_via_tor", "Check and download through Tor",
                     "Used whenever Tor is up, so update servers never see your IP address.")
        page.add(g)

        g = Adw.PreferencesGroup(title="Storage")
        self.data_row = Adw.ActionRow(title="Blockchain data", subtitle_selectable=True)
        open_btn = Gtk.Button(icon_name="folder-open-symbolic", valign=Gtk.Align.CENTER,
                              tooltip_text="Open folder")
        open_btn.add_css_class("flat")
        open_btn.connect("clicked", lambda *_: self._open_data())
        self.data_row.add_suffix(open_btn)
        self.free_row = Adw.ActionRow(title="Free space")
        g.add(self.data_row)
        g.add(self.free_row)
        page.add(g)

        g = Adw.PreferencesGroup(title="Node")
        row = Adw.ActionRow(title="Remove services",
                            subtitle="Stops everything and removes the background services. "
                                     "Blockchain data, downloads and settings are kept; run the "
                                     "installer again to resume.")
        btn = Gtk.Button(label="Remove…", valign=Gtk.Align.CENTER)
        btn.add_css_class("destructive-action")
        btn.connect("clicked", lambda *_: self._confirm_remove())
        row.add_suffix(btn)
        g.add(row)
        page.add(g)

    def _switch(self, group, key, title, sub):
        row = Adw.SwitchRow(title=title, subtitle=sub)
        row.connect("notify::active", lambda r, _p, k=key: self._toggled(k, r.get_active()))
        group.add(row)
        self.sw[key] = row

    def update(self, snap):
        self.snap = snap
        s = snap["settings"]
        self.loading = True
        for key, row in self.sw.items():
            row.set_active(bool(s[key]))
        self.theme.set_selected(THEMES.index(s["theme"]) if s["theme"] in THEMES else 0)
        if not self.sleep_busy and not snap.get("demo"):
            self.never_sleep.set_active(hardening.never_sleep_enabled())
        self.loading = False
        self.sw["keep_awake"].set_subtitle(node.awake_status(snap))
        self.data_row.set_subtitle(s["data_dir"])
        free = snap.get("disk_free_gb")
        self.free_row.set_subtitle(f"{free:,.0f} GB" if free is not None else "—")
        tray = self.app.tray if self.app else None
        if tray is not None and tray.registered:
            self.tray_row.set_subtitle("Active")
            self.tray_btn.set_visible(False)
        else:
            self.tray_row.set_subtitle(
                "GNOME has no system tray by default. Enable the AppIndicator extension to get "
                "the BitFedot icon in the top bar (takes effect after logging in again).")
            self.tray_btn.set_visible(True)

    def _theme(self, index):
        if self.loading:
            return
        name = THEMES[index]
        self.app.apply_theme(name)                 # instant, also in demo mode
        if not self.demo:
            run_async(lambda: settings.update(theme=name), None, lambda e: toast(self, error_text(e)))

    def _toggled(self, key, value):
        if self.loading:
            return
        if self.demo:
            return toast(self, "Demo mode — nothing is running")

        def work():
            s = settings.update(**{key: value})
            if key == "linger":
                system.set_linger(value)
            if key == "autostart":
                services.write_autostart(s)
        run_async(work, None, lambda e: toast(self, error_text(e)))

    def _never_sleep(self, enable):
        if self.loading:
            return
        if self.demo:
            return toast(self, "Demo mode — nothing is changed")
        self.sleep_busy = True              # the switch is not synced back while the dialog is open

        def finish(message):
            self.sleep_busy = False
            self.loading = True
            self.never_sleep.set_active(hardening.never_sleep_enabled())
            self.loading = False
            toast(self, message)
        run_async(lambda: hardening.set_never_sleep(enable),
                  lambda _r: finish("This computer no longer goes to sleep" if enable
                                    else "Sleep is allowed again"),
                  lambda e: finish(error_text(e)))

    def _install_tray(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        self.tray_btn.set_sensitive(False)
        run_async(lambda: installer.install_system_packages(want_tray=True),
                  lambda _r: (self.tray_btn.set_sensitive(True),
                              toast(self, "Tray support installed — log out and back in to see the icon")),
                  lambda e: (self.tray_btn.set_sensitive(True), toast(self, error_text(e))))

    def _open_data(self):
        if self.snap:
            Gio.AppInfo.launch_default_for_uri(Gio.File.new_for_path(
                system.existing_parent(self.snap["settings"]["data_dir"])).get_uri(), None)

    def _confirm_remove(self):
        dlg = Adw.AlertDialog(heading="Remove node services?",
                              body="Bitcoin Core, Tor, Fulcrum and Mempool will be stopped and their "
                                   "background services removed. Your blockchain data is kept.")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("remove", "Stop and remove")
        dlg.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.connect("response", lambda _d, r: r == "remove" and self._remove())
        dlg.present(self.get_root())

    def _remove(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        toast(self, "Stopping services — Bitcoin Core may take a few minutes to flush…")
        self.get_root().app.poll_now()
        # The node counts as removed only once everything has stopped; if a service
        # will not stop, it stays installed and the agent brings it back up.
        run_async(services.remove_all, lambda _r: self.get_root().show_wizard(),
                  lambda e: (toast(self, error_text(e)), self.get_root().app.poll_now()))
