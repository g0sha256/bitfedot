"""About page: author, links, licence, the Bitcoin whitepaper, and thanks."""
from gi.repository import Adw, Gio, GLib, Gtk

from .. import __version__, about, paths
from .widgets import error_text, label, toast


def _link_row(title, subtitle, url):
    row = Adw.ActionRow(title=title, subtitle=subtitle, activatable=True)
    row.add_suffix(Gtk.Image(icon_name="adw-external-link-symbolic"))
    row.connect("activated", lambda *_: Gio.AppInfo.launch_default_for_uri(url, None))
    return row


class AboutPage(Gtk.Box):
    title = "About"
    icon = "help-about-symbolic"

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        page = Adw.PreferencesPage(vexpand=True)
        self.append(page)

        # ---- header -------------------------------------------------------
        g = Adw.PreferencesGroup()
        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=12, margin_bottom=6)
        head.append(Gtk.Image(icon_name=paths.APP_ID, pixel_size=96))
        head.append(label(paths.APP_NAME, "title-1", xalign=0.5))
        head.append(label(f"Version {__version__}", "dim-label", xalign=0.5))
        tagline = label("A complete, private, hardened Bitcoin node for Fedora.\n"
                        "Don't trust. Verify.", xalign=0.5, wrap=True)
        tagline.set_justify(Gtk.Justification.CENTER)
        head.append(tagline)
        g.add(head)
        page.add(g)

        # ---- project ------------------------------------------------------
        g = Adw.PreferencesGroup(title="Project")
        g.add(_link_row(f"Made by {about.AUTHOR}", about.AUTHOR_URL, about.AUTHOR_URL))
        g.add(_link_row("Source code", about.REPO_URL, about.REPO_URL))
        g.add(_link_row("Report a problem or suggest an improvement", about.ISSUES_URL, about.ISSUES_URL))
        g.add(_link_row(about.LICENSE_NAME, about.LICENSE_SUMMARY, about.LICENSE_URL))
        page.add(g)

        # ---- whitepaper ---------------------------------------------------
        g = Adw.PreferencesGroup(
            title="The Bitcoin whitepaper",
            description="“Bitcoin: A Peer-to-Peer Electronic Cash System” — nine pages by Satoshi "
                        "Nakamoto, published on 31 October 2008. A copy ships with BitFedot.")
        row = Adw.ActionRow(title="Read it", subtitle="Opens in your PDF viewer")
        open_btn = Gtk.Button(label="Open", valign=Gtk.Align.CENTER)
        open_btn.connect("clicked", lambda *_: Gio.AppInfo.launch_default_for_uri(
            Gio.File.new_for_path(str(about.WHITEPAPER)).get_uri(), None))
        row.add_suffix(open_btn)
        g.add(row)
        row = Adw.ActionRow(title="Keep a copy", subtitle="Checked against its SHA-256 before it is saved")
        for text, which in (("Save to Documents", GLib.UserDirectory.DIRECTORY_DOCUMENTS),
                            ("Save to Desktop", GLib.UserDirectory.DIRECTORY_DESKTOP)):
            b = Gtk.Button(label=text, valign=Gtk.Align.CENTER)
            b.connect("clicked", lambda _b, w=which: self._save(w))
            row.add_suffix(b)
        g.add(row)
        page.add(g)

        # ---- thanks -------------------------------------------------------
        g = Adw.PreferencesGroup(
            title="Thank you",
            description="BitFedot only arranges other people's work. It exists because of them.")
        name, url, why = about.SATOSHI
        satoshi = _link_row(name, why, url)
        satoshi.add_prefix(Gtk.Image(icon_name="starred-symbolic"))
        g.add(satoshi)
        for name, url, what in about.THANKS:
            g.add(_link_row(name, what, url))
        page.add(g)

    def update(self, snap):
        pass

    def _save(self, which):
        folder = GLib.get_user_special_dir(which) or GLib.get_home_dir()
        try:
            target = about.save_whitepaper(folder)
        except (OSError, RuntimeError) as e:
            return toast(self, error_text(e))
        toast(self, f"Saved to {target.parent}")
