"""Updates page: node software (verified downloads) and Fedora itself."""
import time

from gi.repository import Adw, GLib, Gtk

from .. import hardening, installer, net, node, selfupdate, settings
from ..catalog import CATALOG
from .widgets import error_text, fmt_ago, run_async, toast

TRUST = {
    "bitcoin": "Checksums must be signed by at least 3 independent Bitcoin Core builders whose "
               "keys ship with this app; the download must match the signed SHA-256.",
    "fulcrum": "Checksums must be signed by Fulcrum's release key (Calin Culianu, …2031 C02C); "
               "the download must match the signed SHA-256.",
    "mempool": "Container images by exact release tag over TLS. Upstream does not sign images, "
               "so the content digest is recorded instead.",
    "tor": "Installed from the Fedora repositories; dnf verifies the RPM signature.",
    # optional apps: verified against the key pinned in their catalog entry
    **{app.id: f"Verified against the pinned key of {app.signer} before anything is installed. "
               "Details on the Apps page." for app in CATALOG},
}


class UpdatesPage(Gtk.Box):
    title = "Updates"
    icon = "software-update-available-symbolic"

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo = demo
        self.busy = set()
        self.loading = False
        self.os_busy = False
        page = Adw.PreferencesPage(vexpand=True)
        self.append(page)

        # ---- BitFedot itself ----------------------------------------------
        g = Adw.PreferencesGroup(title="BitFedot")
        self.self_row = Adw.ActionRow(title="This app", subtitle="…")
        self.self_spinner = Adw.Spinner(visible=False)
        self.self_btn = Gtk.Button(label="Update", valign=Gtk.Align.CENTER, visible=False)
        self.self_btn.add_css_class("suggested-action")
        self.self_btn.connect("clicked", lambda *_: self._self_update())
        self.self_restart = Gtk.Button(label="Restart BitFedot", valign=Gtk.Align.CENTER, visible=False)
        self.self_restart.add_css_class("suggested-action")
        self.self_restart.connect("clicked", lambda *_: self._relaunch())
        for w in (self.self_spinner, self.self_btn, self.self_restart):
            self.self_row.add_suffix(w)
        g.add(self.self_row)
        self.self_note = Adw.ActionRow(title="How this is verified", subtitle="")
        g.add(self.self_note)
        self.rollback_row = Adw.ActionRow(
            title="Previous version", visible=False,
            subtitle="The version that was replaced by the last update is kept, in case the new one misbehaves.")
        back = Gtk.Button(label="Go back", valign=Gtk.Align.CENTER)
        back.connect("clicked", lambda *_: self._rollback())
        self.rollback_row.add_suffix(back)
        g.add(self.rollback_row)
        self.auto_self = Adw.SwitchRow(
            title="Install BitFedot updates automatically",
            subtitle="Only releases signed with the key this copy already carries, and only after the "
                     "new version passes its own tests. You are notified; a restart of the app applies it.")
        self.auto_self.connect("notify::active", lambda r, _p: self._auto_self(r.get_active()))
        g.add(self.auto_self)
        page.add(g)
        self.self_busy = False

        # ---- node software ------------------------------------------------
        self.group = Adw.PreferencesGroup(title="Node software and apps")
        self.check_btn = Gtk.Button(label="Check for updates", valign=Gtk.Align.CENTER)
        self.check_btn.add_css_class("suggested-action")
        self.check_btn.connect("clicked", lambda *_: self.check())
        self.group.set_header_suffix(self.check_btn)
        self.rows = {}
        for name in installer.COMPONENTS + tuple(a.id for a in CATALOG if not a.self_updates):
            row = Adw.ExpanderRow(title=installer.TITLES[name])
            btn = Gtk.Button(label="Update", valign=Gtk.Align.CENTER, visible=False)
            btn.add_css_class("suggested-action")
            btn.connect("clicked", lambda _b, n=name: self.update_component(n))
            spinner = Adw.Spinner(visible=False)
            row.add_suffix(spinner)
            row.add_suffix(btn)
            row.add_row(Adw.ActionRow(title="How this is verified", subtitle=TRUST[name]))
            result = Adw.ActionRow(title="Last verification", subtitle="—", subtitle_selectable=True,
                                   visible=False)
            row.add_row(result)
            self.group.add(row)
            self.rows[name] = (row, btn, spinner, result)
        page.add(self.group)

        # ---- Fedora -------------------------------------------------------
        g = Adw.PreferencesGroup(title="Fedora",
                                 description="Operating-system packages, installed with dnf. "
                                             "Package signatures are verified by dnf.")
        self.os_row = Adw.ActionRow(title="System updates", subtitle="Not checked yet")
        self.os_spinner = Adw.Spinner(visible=False)
        self.os_security = Gtk.Button(label="Security only", valign=Gtk.Align.CENTER, visible=False)
        self.os_security.connect("clicked", lambda *_: self._os_install(True))
        self.os_all = Gtk.Button(label="Install all", valign=Gtk.Align.CENTER, visible=False)
        self.os_all.add_css_class("suggested-action")
        self.os_all.connect("clicked", lambda *_: self._os_install(False))
        for w in (self.os_spinner, self.os_security, self.os_all):
            self.os_row.add_suffix(w)
        g.add(self.os_row)
        self.reboot_row = Adw.ActionRow(
            title="Restart required",
            subtitle="Updated system components are only active after a restart. A safe restart "
                     "first stops every service cleanly; they come back by themselves.",
            visible=False)
        reboot = Gtk.Button(label="Restart safely…", valign=Gtk.Align.CENTER)
        reboot.add_css_class("destructive-action")
        reboot.connect("clicked", lambda *_: self._confirm_reboot())
        self.reboot_row.add_suffix(reboot)
        g.add(self.reboot_row)
        self.auto = Adw.SwitchRow(
            title="Install security updates automatically",
            subtitle="Uses Fedora's dnf5 automatic timer for security fixes only. Never restarts "
                     "the computer by itself. Asks for your password.")
        self.auto.connect("notify::active", lambda r, _p: self._auto(r.get_active()))
        g.add(self.auto)
        page.add(g)
        self.auto_known = None

    # --------------------------------------------------------------- state --
    def update(self, snap):
        s = snap["settings"]
        last = s.get("last_update_check")
        via_tor = s["updates_via_tor"] and snap["tor"]["state"] == "running"
        self.group.set_description((f"Last checked {fmt_ago(last)}" + (" · through Tor" if via_tor else ""))
                                   if last else "Not checked yet")
        if not self.self_busy and not self.self_restart.get_visible():
            me = selfupdate.status(s)
            if snap.get("demo"):
                me.update(can_install=True, note="Installed only if signed by the BitFedot release key "
                                                 "shipped with this version.")
            self.self_row.set_subtitle(
                f"Version {me['current']} · {me['latest']} available" if me["newer"]
                else f"Version {me['current']}" + (" · up to date" if me["latest"] else ""))
            self.self_note.set_subtitle(me["note"])
            self.self_btn.set_label(f"Update to {me['latest']}")
            self.self_btn.set_visible(me["newer"] and me["can_install"])
            self.rollback_row.set_visible(me["can_rollback"])
            self.loading = True
            self.auto_self.set_active(bool(s["auto_self_update"]))
            self.auto_self.set_sensitive(me["can_install"] or bool(snap.get("demo")))
            self.loading = False
        present = installer.components(s)
        for name, (row, btn, spinner, _result) in self.rows.items():
            row.set_visible(name in present)
            if name in self.busy:
                continue
            have = s["versions"].get(name, "")
            latest = s.get("available", {}).get(name, "")
            if snap.get("demo") and name in snap["updates"]:
                latest = snap["updates"][name]
            newer = net.is_newer(latest, have)
            row.set_subtitle(f"Installed {have or '—'} · {latest} available" if newer
                             else f"Installed {have or '—'} · up to date" if latest
                             else f"Installed {have or '—'}")
            btn.set_label(f"Update to {latest}")
            btn.set_visible(newer)
            btn.set_sensitive(not snap.get("activity"))

        if not self.os_busy:
            info = {"count": 14, "security": 3, "reboot": False, "checked": time.time() - 5400} \
                if snap.get("demo") else s.get("os_updates") or {}
            if info.get("checked"):
                n, sec = info.get("count", 0), info.get("security", 0)
                self.os_row.set_subtitle(
                    (f"{n} update(s) available, {sec} of them security fixes" if n
                     else "Fedora is up to date") + f" · checked {fmt_ago(info['checked'])}")
                self.os_all.set_visible(n > 0)
                self.os_security.set_visible(0 < sec < n)
                self.reboot_row.set_visible(bool(info.get("reboot")))
        if self.get_mapped() and self.auto_known is None and not snap.get("demo"):
            self.auto_known = False
            run_async(hardening.auto_updates_enabled, self._set_auto)

    def _set_auto(self, enabled):
        self.auto_known = True
        self.loading = True
        self.auto.set_active(bool(enabled))
        self.loading = False

    # ----------------------------------------------------------- BitFedot --
    def _self_update(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        self.self_busy = True
        self.self_btn.set_visible(False)
        self.self_spinner.set_visible(True)

        def report(msg, frac=None):
            text = msg + (f" {frac * 100:.0f}%" if frac not in (None, 0.0, 1.0) else "")
            GLib.idle_add(lambda: self.self_row.set_subtitle(text) and False)

        def done(res):
            self.self_busy = False
            self.self_spinner.set_visible(False)
            self.self_row.set_subtitle(f"Version {res['version']} is installed — restart to use it. "
                                       f"Signed by {'; '.join(res['signers'])}")
            self.self_restart.set_visible(True)
            toast(self, f"BitFedot {res['version']} installed")

        def failed(e):
            self.self_busy = False
            self.self_spinner.set_visible(False)
            self.self_note.set_subtitle(f"✗ {error_text(e)}")
            toast(self, "BitFedot was not updated")
        run_async(lambda: selfupdate.update(report), done, failed)

    def _auto_self(self, on):
        if self.loading:
            return
        if self.demo:
            return toast(self, "Demo mode — nothing is changed")
        run_async(lambda: settings.update(auto_self_update=on), None, lambda e: toast(self, error_text(e)))

    def _rollback(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")

        def done(version):
            self.self_row.set_subtitle(f"Version {version} is back — restart to use it.")
            self.self_restart.set_visible(True)
        run_async(selfupdate.rollback, done, lambda e: toast(self, error_text(e)))

    def _relaunch(self):
        selfupdate.relaunch()
        self.get_root().app.quit()

    # ------------------------------------------------------- node software --
    def check(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        self.check_btn.set_sensitive(False)
        self.check_btn.set_label("Checking…")
        self._os_busy(True, "Asking dnf…")

        def work():
            res = installer.check_updates()
            try:
                hardening.check_os_updates()
            except RuntimeError as e:
                res["errors"]["fedora"] = str(e)
            return res

        def done(res):
            self.check_btn.set_sensitive(True)
            self.check_btn.set_label("Check for updates")
            self._os_busy(False)
            s = settings.load()
            if res["errors"]:
                toast(self, "Could not check: " + ", ".join(
                    installer.TITLES.get(n, "Fedora") for n in res["errors"]))
            else:
                pending = len(installer.pending_updates(s)) + (1 if s["os_updates"].get("count") else 0)
                toast(self, f"{pending} update(s) available" if pending else "Everything is up to date")
            self.get_root().app.poll_now()
        run_async(work, done, lambda e: (done({"errors": {}}), toast(self, error_text(e))))

    def update_component(self, name):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        row, btn, spinner, result = self.rows[name]
        self.busy.add(name)
        btn.set_visible(False)
        spinner.set_visible(True)

        def report(msg, frac=None):
            text = msg + (f" {frac * 100:.0f}%" if frac not in (None, 0.0, 1.0) else "")
            GLib.idle_add(lambda: row.set_subtitle(text) and False)

        def finish(res=None, err=None):
            self.busy.discard(name)
            spinner.set_visible(False)
            result.set_visible(True)
            if err:
                result.set_subtitle(f"✗ {error_text(err)}")
                row.set_expanded(True)
                toast(self, f"{installer.TITLES[name]} update failed")
            else:
                result.set_subtitle("✓ " + "; ".join(res.get("signers", [])) +
                                    (f"\nSHA-256 {res['sha256']}" if res.get("sha256") else ""))
                toast(self, f"{installer.TITLES[name]} updated to {res['version']}")
            self.get_root().app.poll_now()
        run_async(lambda: installer.update_component(name, report), finish, lambda e: finish(err=e))

    # -------------------------------------------------------------- Fedora --
    def _os_busy(self, on, text=None):
        self.os_busy = on
        self.os_spinner.set_visible(on)
        for b in (self.os_all, self.os_security):
            b.set_sensitive(not on)
        if text:
            self.os_row.set_subtitle(text)

    def _os_install(self, security_only):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        self._os_busy(True, "Installing updates with dnf — this can take several minutes…")

        def done(warnings=None):
            self._os_busy(False)
            toast(self, warnings[0] if warnings else "Fedora updates installed")
            self.get_root().app.poll_now()
        run_async(lambda: hardening.install_os_updates(security_only), done,
                  lambda e: (self._os_busy(False), toast(self, error_text(e)),
                             self.get_root().app.poll_now()))

    def _auto(self, enable):
        if self.loading:
            return
        if self.demo:
            return toast(self, "Demo mode — nothing is changed")
        run_async(lambda: hardening.set_auto_updates(enable),
                  lambda _r: toast(self, "Automatic security updates " + ("enabled" if enable else "disabled")),
                  lambda e: (toast(self, error_text(e)),
                             run_async(hardening.auto_updates_enabled, self._set_auto)))

    def _confirm_reboot(self):
        dlg = Adw.AlertDialog(
            heading="Restart this computer?",
            body="Mempool, Fulcrum, Bitcoin Core and Tor are stopped one after another and given "
                 "time to write everything to disk, then the computer restarts. Save your work "
                 "in other applications first.")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("reboot", "Stop services and restart")
        dlg.set_response_appearance("reboot", Adw.ResponseAppearance.DESTRUCTIVE)

        def answer(_d, response):
            if response != "reboot":
                return
            if self.demo:
                return toast(self, "Demo mode — nothing is running")
            toast(self, "Stopping services safely before restarting…")
            self.get_root().app.poll_now()
            run_async(node.safe_reboot, None, lambda e: toast(self, error_text(e)))
        dlg.connect("response", answer)
        dlg.present(self.get_root())
