"""Apps page: the optional apps from catalog.py, grouped by category.

Entirely generated from the catalog — adding an app there makes it appear here
with install / open / update / remove and its verification details.
"""
from gi.repository import Adw, Gio, GLib, Gtk

from .. import apps
from ..catalog import CATALOG, CATEGORIES
from .widgets import error_text, run_async, toast

KIND_TEXT = {
    "archive": "Downloaded from the developers and unpacked into your home folder. No administrator rights.",
    "apt": "Taken from the developers' signed package repository and unpacked into your home folder. "
           "No administrator rights.",
    "flatpak": "Installed as a Flatpak for your user from Flathub. No administrator rights.",
    "dnf": "Installed system-wide with dnf from the vendor's own repository, which is then also used "
           "for updates. Asks for your password.",
}
VERIFY_TEXT = {
    "archive": "The download must carry a valid signature from {signer}, whose key ({fpr}) ships "
               "inside BitFedot. Anything else is deleted, not installed.",
    "apt": "The repository index must be signed by {signer} ({fpr}, pinned in BitFedot), and the "
           "package must match the hash in that signed index.",
    "flatpak": "Flathub is added with its signing key pinned in BitFedot ({fpr}); Flatpak verifies "
               "every download against it. Publisher: {signer}.",
    "dnf": "BitFedot installs the vendor's signing key from its own pinned copy ({fpr}, {signer}) "
           "instead of fetching it at install time, and dnf checks every package signature.",
}


def _short_fpr(app) -> str:
    return ", ".join("…" + f[-16:-12] + " " + f[-12:-8] + " " + f[-8:-4] + " " + f[-4:] for f in app.fingerprints)


class AppsPage(Gtk.Box):
    title = "Apps"
    icon = "view-app-grid-symbolic"

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo = demo
        self.busy = set()
        self.rows = {}
        self.synced = False
        page = Adw.PreferencesPage(
            vexpand=True, description="Optional companions for your node. Each one is checked against "
                                      "its developers' signing key before it is installed or updated. "
                                      "BitFedot never touches the data these apps create.")
        self.append(page)
        for cat, (title, description) in CATEGORIES.items():
            group = Adw.PreferencesGroup(title=title, description=description)
            for app in (a for a in CATALOG if a.category == cat):
                group.add(self._row(app))
            page.add(group)

    def _row(self, app):
        row = Adw.ExpanderRow(title=app.title, subtitle=app.summary)
        spinner = Adw.Spinner(visible=False, valign=Gtk.Align.CENTER)
        main = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
        main.connect("clicked", lambda *_: self._main(app))
        row.add_suffix(spinner)
        row.add_suffix(main)

        state = Adw.ActionRow(title="Status", subtitle="Not installed")
        row.add_row(state)
        if app.setup:
            row.add_row(Adw.ActionRow(title="Set up for you", subtitle=app.setup))
        row.add_row(Adw.ActionRow(title="How it is installed", subtitle=KIND_TEXT[app.kind]))
        row.add_row(Adw.ActionRow(
            title="How it is verified",
            subtitle=VERIFY_TEXT[app.kind].format(signer=app.signer, fpr=_short_fpr(app))))
        about = Adw.ActionRow(title="Project", subtitle=f"{app.homepage} · {app.license}", activatable=True)
        about.add_suffix(Gtk.Image(icon_name="adw-external-link-symbolic"))
        about.connect("activated", lambda *_: Gio.AppInfo.launch_default_for_uri(app.homepage, None))
        row.add_row(about)
        result = Adw.ActionRow(title="Last verification", subtitle_selectable=True, visible=False)
        row.add_row(result)

        manage = Adw.ActionRow(title="Manage", visible=False)
        update = Gtk.Button(label="Update", valign=Gtk.Align.CENTER, visible=False)
        update.add_css_class("suggested-action")
        update.connect("clicked", lambda *_: self._install(app))
        reconnect = Gtk.Button(label="Reconnect to node", valign=Gtk.Align.CENTER,
                               visible=bool(app.spec.get("configure")),
                               tooltip_text="Write the connection settings again")
        reconnect.connect("clicked", lambda *_: self._reconnect(app))
        remove = Gtk.Button(label="Remove", valign=Gtk.Align.CENTER)
        remove.add_css_class("destructive-action")
        remove.connect("clicked", lambda *_: self._confirm_remove(app))
        for b in (update, reconnect, remove):
            manage.add_suffix(b)
        row.add_row(manage)
        self.rows[app.id] = {"row": row, "main": main, "spinner": spinner, "state": state,
                             "manage": manage, "update": update, "result": result, "installed": ""}
        return row

    # --------------------------------------------------------------- state --
    def update(self, snap):
        s = snap["settings"]
        demo_installed = {"sparrow": "2.5.6", "obscura": "1.186", "torbrowser": "16.0.1"}
        for app in CATALOG:
            w = self.rows[app.id]
            if app.id in self.busy:
                continue
            if snap.get("demo"):
                version = demo_installed.get(app.id, "")
                info = {"installed": version, "ready": bool(version), "note": ""}
            else:
                info = apps.status(app.id, s, snap.get("fulcrum"))
            w["installed"] = info["installed"]
            w["note"] = info["note"] if info["installed"] else ""
            # What stands in the way is shown without opening the row.
            note = w["note"][:1].upper() + w["note"][1:]
            w["row"].set_subtitle(app.summary + (f"\n{note}." if note else ""))
            w["manage"].set_visible(bool(info["installed"]))
            latest = s.get("available", {}).get(app.id, "")
            newer = bool(info["installed"]) and apps.net.is_newer(latest, info["installed"]) \
                and not app.self_updates
            w["update"].set_label(f"Update to {latest}")
            w["update"].set_visible(newer)
            if not apps.supported(app):
                w["state"].set_subtitle("No build available for this CPU architecture")
                w["main"].set_sensitive(False)
            elif info["installed"]:
                extra = " · keeps itself up to date" if app.self_updates else \
                    f" · {latest} available" if newer else ""
                w["state"].set_subtitle(f"Version {info['installed']} installed"
                                        + (f" · {info['note']}" if info["note"] else extra))
                w["main"].set_label("Open")
                w["main"].remove_css_class("suggested-action")
                w["main"].set_sensitive(info["ready"])
            else:
                w["state"].set_subtitle("Not installed")
                w["main"].set_label("Install")
                w["main"].add_css_class("suggested-action")
                w["main"].set_sensitive(True)

    def refresh(self):
        """Opening the page re-reads what dnf and Flatpak have installed."""
        if not self.demo and not self.synced:
            self.synced = True
            run_async(apps.sync_versions, lambda _s: self.get_root().app.poll_now(),
                      lambda e: None)

    # ------------------------------------------------------------- actions --
    def _main(self, app):
        if self.demo:
            return toast(self, "Demo mode — nothing is installed")
        if not self.rows[app.id]["installed"]:
            return self._install(app)
        try:
            apps.launch(app.id)
        except OSError as e:
            return toast(self, error_text(e))
        if self.rows[app.id].get("note"):                # e.g. Fulcrum is still building its index
            toast(self, f"{app.title} {self.rows[app.id]['note']}")

    def _busy(self, app, on):
        (self.busy.add if on else self.busy.discard)(app.id)
        w = self.rows[app.id]
        w["spinner"].set_visible(on)
        w["main"].set_sensitive(not on)
        w["update"].set_sensitive(not on)

    def _install(self, app):
        if self.demo:
            return toast(self, "Demo mode — nothing is installed")
        w = self.rows[app.id]
        updating = bool(w["installed"])
        self._busy(app, True)

        def report(msg, frac=None):
            text = msg + (f" {frac * 100:.0f}%" if frac not in (None, 0.0, 1.0) else "")
            GLib.idle_add(lambda: w["state"].set_subtitle(text) and False)

        def done(res):
            self._busy(app, False)
            w["result"].set_visible(True)
            w["result"].set_subtitle("✓ " + "; ".join(res.get("signers", []))
                                     + (f"\nSHA-256 {res['sha256']}" if res.get("sha256") else ""))
            toast(self, f"{app.title} {res['version']} {'updated' if updating else 'installed'}")
            self.get_root().app.poll_now()

        def failed(e):
            self._busy(app, False)
            w["result"].set_visible(True)
            w["result"].set_subtitle(f"✗ {error_text(e)}")
            w["row"].set_expanded(True)
            toast(self, f"{app.title} was not {'updated' if updating else 'installed'}")
            self.get_root().app.poll_now()
        run_async(lambda: apps.install(app.id, report), done, failed)

    def _reconnect(self, app):
        if self.demo:
            return toast(self, "Demo mode — nothing is changed")
        run_async(lambda: apps.reconfigure(app.id),
                  lambda _r: toast(self, f"Connection settings written — restart {app.title}"),
                  lambda e: toast(self, error_text(e)))

    def _confirm_remove(self, app):
        dlg = Adw.AlertDialog(heading=f"Remove {app.title}?",
                              body="Only the program is removed. Everything you created with it — "
                                   "wallets, profiles, chats, settings — stays where it is.")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("remove", "Remove")
        dlg.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)

        def answer(_d, response):
            if response != "remove":
                return
            if self.demo:
                return toast(self, "Demo mode — nothing is changed")
            self._busy(app, True)
            run_async(lambda: apps.remove(app.id),
                      lambda _r: (self._busy(app, False), toast(self, f"{app.title} removed"),
                                  self.get_root().app.poll_now()),
                      lambda e: (self._busy(app, False), toast(self, error_text(e)),
                                 self.get_root().app.poll_now()))
        dlg.connect("response", answer)
        dlg.present(self.get_root())
