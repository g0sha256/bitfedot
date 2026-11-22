"""First-run installer: welcome → choices → live install progress."""
import os

from gi.repository import Adw, GLib, Gtk

from .. import installer, migrate, settings, system
from .connectivity import MODES
from .widgets import error_text, label, run_async


class Wizard(Adw.Bin):
    def __init__(self, window, tray_available):
        super().__init__()
        self.window = window
        self.data_dir = settings.load()["data_dir"]
        self.offer_tray = (not tray_available and
                           "GNOME" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper())
        self.nav = Adw.NavigationView()
        self.set_child(self.nav)
        self.nav.add(self._adopt() if migrate.pending() else self._welcome())

    # -------------------------------------------------------------- adopt --
    def _adopt(self):
        """Shown instead of the welcome page when a pre-release ("Nodestead")
        install exists: offer to carry it over instead of installing again. Also
        shown when that move was begun and has not been finished (migrate.pending())."""
        resuming = settings.load()["adopting"]
        status = Adw.StatusPage(
            icon_name="io.github.g0sha256.BitFedot",
            title="Your node is now called BitFedot",
            description="Moving your Nodestead installation to BitFedot was begun and not finished.\n"
                        "Nothing is lost: its folders are in place under their new names. What is "
                        "left is to set up the services and start the node."
                        if resuming else
                        "An existing Nodestead installation was found on this computer.\n"
                        "BitFedot can take it over as it is: the services are stopped safely, the "
                        "folders are renamed — nothing is copied or downloaded again, and all sync "
                        "progress is kept — and the node starts again right away.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, halign=Gtk.Align.CENTER)
        self.adopt_btn = Gtk.Button(label="Finish the move" if resuming else "Move my node to BitFedot",
                                    halign=Gtk.Align.CENTER)
        for c in ("pill", "suggested-action"):
            self.adopt_btn.add_css_class(c)
        self.adopt_btn.connect("clicked", lambda *_: self._run_adopt())
        self.adopt_spinner = Adw.Spinner(visible=False, halign=Gtk.Align.CENTER)
        self.adopt_spinner.set_size_request(32, 32)
        self.adopt_msg = label("", "dim-label", xalign=0.5, wrap=True)
        for w in (self.adopt_btn, self.adopt_spinner, self.adopt_msg):
            box.append(w)
        status.set_child(box)
        return self._page(status, "Welcome", "welcome")

    def _run_adopt(self):
        self.adopt_btn.set_visible(False)
        self.adopt_spinner.set_visible(True)
        app = self.window.app
        app.pause_polling(True)           # nothing may touch the folders while they move

        def report(msg, _frac=None):
            GLib.idle_add(lambda: self.adopt_msg.set_label(msg) and False)

        def done(_s):
            app.pause_polling(False)
            self.window.show_main()
            self.window.toast("Welcome to BitFedot — your node carried on where it left off")

        def failed(e):
            app.pause_polling(False)
            self.adopt_spinner.set_visible(False)
            self.adopt_btn.set_visible(True)
            self.adopt_msg.set_label(error_text(e))
        run_async(lambda: migrate.adopt(report), done, failed)

    # ------------------------------------------------------------ welcome --
    def _welcome(self):
        status = Adw.StatusPage(
            icon_name="io.github.g0sha256.BitFedot",
            title="Your own Bitcoin node",
            description="BitFedot installs and looks after a complete, private Bitcoin stack "
                        "on this computer.\nEvery download is checked against the developers' "
                        "signatures before it runs.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24, halign=Gtk.Align.CENTER)
        group = Adw.PreferencesGroup()
        for icon, title, sub in (
            ("network-server-symbolic", "Bitcoin Core", "Validates every block and transaction yourself"),
            ("network-transmit-receive-symbolic", "Fulcrum", "Fast Electrum server for your wallets"),
            ("system-search-symbolic", "Mempool", "Your private block explorer"),
            ("security-high-symbolic", "Tor", "Network privacy once the chain is synced"),
        ):
            row = Adw.ActionRow(title=title, subtitle=sub)
            row.add_prefix(Gtk.Image(icon_name=icon))
            group.add(row)
        box.append(Adw.Clamp(child=group, maximum_size=460))
        start = Gtk.Button(label="Get started", halign=Gtk.Align.CENTER)
        for c in ("pill", "suggested-action"):
            start.add_css_class(c)
        start.connect("clicked", lambda *_: self.nav.push(self._options()))
        box.append(start)
        status.set_child(box)
        return self._page(status, "Welcome", "welcome")

    def _page(self, child, title, tag):
        view = Adw.ToolbarView(content=child)
        view.add_top_bar(Adw.HeaderBar())
        return Adw.NavigationPage(child=view, title=title, tag=tag)

    # ------------------------------------------------------------ options --
    def _options(self):
        page = Adw.PreferencesPage()

        g = Adw.PreferencesGroup(title="Storage",
                                 description=f"The full blockchain with indexes needs about "
                                             f"{system.REQUIRED_GB:,} GB. An SSD is strongly recommended.")
        self.dir_row = Adw.ActionRow(title="Data location")
        choose = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        choose.connect("clicked", lambda *_: self._choose_dir())
        self.dir_row.add_suffix(choose)
        g.add(self.dir_row)
        self.issues = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=10)
        g.add(self.issues)
        page.add(g)

        g = Adw.PreferencesGroup(title="Synchronisation")
        self.ibd_clear = Adw.SwitchRow(
            title="Sync over clearnet first (fastest)", active=True,
            subtitle="The initial download uses your normal connection. Tor is launched "
                     "automatically as soon as the chain is synced. Turn off to sync through "
                     "Tor from the start — private, but several times slower.")
        g.add(self.ibd_clear)
        ram = system.ram_mb()
        g.add(Adw.ActionRow(
            title="Tuned for this machine",
            subtitle=f"{system.dbcache_ibd():,} MB database cache of {ram / 1024:.0f} GB RAM · "
                     f"{system.cpu_count()} verification threads · transaction relay and indexes "
                     "deferred until synced"))
        page.add(g)

        g = Adw.PreferencesGroup(title="After sync",
                                 description="Can be changed any time under Connectivity.")
        self.mode = Adw.ComboRow(title="Bitcoin Core network",
                                 model=Gtk.StringList.new([m[1] for m in MODES]), selected=1)
        self.mode_help = Adw.ActionRow(subtitle=MODES[1][2])
        self.mode.connect("notify::selected", lambda *_: self.mode_help.set_subtitle(
            MODES[self.mode.get_selected()][2]))
        g.add(self.mode)
        g.add(self.mode_help)
        page.add(g)

        g = Adw.PreferencesGroup(title="This computer")
        self.linger = Adw.SwitchRow(title="Keep the node running when logged out", active=True,
                                    subtitle="Recommended: syncing continues without a desktop session.")
        self.autostart = Adw.SwitchRow(title="Start BitFedot at login", active=True)
        g.add(self.linger)
        g.add(self.autostart)
        self.tray = Adw.SwitchRow(title="Add tray icon support to GNOME", active=True,
                                  subtitle="Installs the AppIndicator extension from Fedora "
                                           "(active after your next login).", visible=self.offer_tray)
        g.add(self.tray)
        page.add(g)

        g = Adw.PreferencesGroup()
        self.install_btn = Gtk.Button(label="Install", halign=Gtk.Align.CENTER)
        for c in ("pill", "suggested-action"):
            self.install_btn.add_css_class(c)
        self.install_btn.connect("clicked", lambda *_: self._start())
        g.add(self.install_btn)
        page.add(g)
        self._set_dir(self.data_dir)
        return self._page(page, "Set up", "options")

    def _choose_dir(self):
        dlg = Gtk.FileDialog(title="Where should the blockchain be stored?")

        def done(d, res):
            try:
                folder = d.select_folder_finish(res)
            except GLib.Error:
                return
            self._set_dir(os.path.join(folder.get_path(), "bitfedot"))
        dlg.select_folder(self.window, None, done)

    def _set_dir(self, path):
        self.data_dir = path
        free = system.disk_free_gb(path)
        self.dir_row.set_subtitle(f"{path}\n{free:,.0f} GB free")
        child = self.issues.get_first_child()
        while child:
            self.issues.remove(child)
            child = self.issues.get_first_child()
        blocked = False
        for severity, text in installer.preflight(path):
            blocked |= severity == "error"
            row = Gtk.Box(spacing=8)
            row.append(Gtk.Image(icon_name="dialog-error-symbolic" if severity == "error"
                                 else "dialog-warning-symbolic"))
            lab = label(text, "error" if severity == "error" else "warning", wrap=True)
            row.append(lab)
            self.issues.append(row)
        self.install_btn.set_sensitive(not blocked)

    # ----------------------------------------------------------- progress --
    def _progress(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_top=24,
                      margin_bottom=24, margin_start=24, margin_end=24, valign=Gtk.Align.CENTER)
        box.append(label("Installing your node", "title-1", xalign=0.5))
        self.p_sub = label("You will be asked for your password once, to install Tor from Fedora.",
                           "dim-label", xalign=0.5, wrap=True)
        self.p_sub.set_justify(Gtk.Justification.CENTER)
        box.append(self.p_sub)
        group = Adw.PreferencesGroup()
        self.steps = {}
        for key, title, sub in installer.INSTALL_STEPS:
            row = Adw.ActionRow(title=title, subtitle=sub)
            icon = Gtk.Image(icon_name="content-loading-symbolic")
            icon.add_css_class("dim-label")
            spinner = Adw.Spinner(visible=False)
            row.add_prefix(icon)
            row.add_prefix(spinner)
            group.add(row)
            self.steps[key] = (row, icon, spinner, sub)
        box.append(group)
        self.p_bar = Gtk.ProgressBar()
        box.append(self.p_bar)
        self.p_error = label("", "error", wrap=True, selectable=True, xalign=0.5)
        self.p_error.set_visible(False)
        box.append(self.p_error)
        self.p_retry = Gtk.Button(label="Try again", halign=Gtk.Align.CENTER, visible=False)
        self.p_retry.add_css_class("pill")
        self.p_retry.connect("clicked", lambda *_: self._run())
        box.append(self.p_retry)
        page = self._page(Adw.Clamp(child=box, maximum_size=560), "Installing", "progress")
        page.set_can_pop(False)
        return page

    def _start(self):
        self.options = {
            "data_dir": self.data_dir,
            "ibd_clearnet": self.ibd_clear.get_active(),
            "net_mode": MODES[self.mode.get_selected()][0],
            "linger": self.linger.get_active(),
            "autostart": self.autostart.get_active(),
            "_want_tray": self.offer_tray and self.tray.get_active(),
        }
        self.nav.push(self._progress())
        self._run()

    def _step(self, key, status, message, fraction):
        def ui():
            keys = [k for k, _, _ in installer.INSTALL_STEPS]
            row, icon, spinner, sub = self.steps[key]
            running = status == "running"
            spinner.set_visible(running)
            icon.set_visible(not running)
            if status == "done":
                icon.set_from_icon_name("object-select-symbolic")
                icon.remove_css_class("dim-label")
                icon.add_css_class("success")
                row.set_subtitle(sub)
            elif message:
                row.set_subtitle(message + (f" {fraction * 100:.0f}%" if fraction else ""))
            base = keys.index(key) / len(keys)
            self.p_bar.set_fraction(base + (fraction or 0) / len(keys) if running
                                    else (keys.index(key) + 1) / len(keys))
            return False
        GLib.idle_add(ui)

    def _run(self):
        self.p_error.set_visible(False)
        self.p_retry.set_visible(False)

        def failed(e):
            for row, icon, spinner, _sub in self.steps.values():
                if spinner.get_visible():
                    spinner.set_visible(False)
                    icon.set_visible(True)
                    icon.set_from_icon_name("dialog-error-symbolic")
            self.p_error.set_label(error_text(e))
            self.p_error.set_visible(True)
            self.p_retry.set_visible(True)
        run_async(lambda: installer.run_install(self.options, self._step),
                  lambda _r: self.window.show_main(installed_now=True), failed)
