"""Main window: sidebar navigation + pages, or the first-run wizard."""
from gi.repository import Adw, Gio, Gtk

from .. import __version__, net, paths
from .about import AboutPage
from .apps import AppsPage
from .connectivity import ConnectivityPage
from .explorer import ExplorerPage
from .overview import OverviewPage
from .pages import LogsPage, SettingsPage
from .security import SecurityPage
from .updates import UpdatesPage
from .widgets import label
from .wizard import Wizard


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=paths.APP_NAME, default_width=1080, default_height=760)
        self.app = app
        self.set_size_request(400, 480)
        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)
        self.root_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.toasts.set_child(self.root_stack)
        self.wizard = None
        self._build_main()

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=4))

    # --------------------------------------------------------------- main --
    def _build_main(self):
        demo = self.app.demo is not None
        self.pages = [OverviewPage(demo), ExplorerPage(demo), AppsPage(demo),
                      ConnectivityPage(demo), SecurityPage(demo), UpdatesPage(demo),
                      LogsPage(demo), SettingsPage(demo, self.app), AboutPage(demo)]
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE, vexpand=True)
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.listbox.add_css_class("navigation-sidebar")
        self.badges = {}
        for page in self.pages:
            self.stack.add_named(page, page.title)
            row = Gtk.Box(spacing=12, margin_top=4, margin_bottom=4)
            row.append(Gtk.Image(icon_name=page.icon))
            row.append(label(page.title))
            badge = Gtk.Label(visible=False, hexpand=True, halign=Gtk.Align.END)
            badge.add_css_class("bf-pill")
            badge.add_css_class("busy")
            row.append(badge)
            self.badges[page.title] = badge
            self.listbox.append(row)
        self.listbox.connect("row-selected", self._selected)

        menu = Gio.Menu()
        menu.append("About BitFedot", "app.about")
        menu.append("Quit…", "app.quit")
        side_header = Adw.HeaderBar(show_title=False)
        brand = Gtk.Box(spacing=8)
        brand.append(Gtk.Image(icon_name=paths.APP_ID, pixel_size=22))
        brand.append(label(paths.APP_NAME, "bf-brand"))
        side_header.pack_start(brand)
        side_header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu,
                                            tooltip_text="Main menu"))
        side = Adw.ToolbarView(content=Gtk.ScrolledWindow(child=self.listbox))
        side.add_top_bar(side_header)

        self.content_title = Adw.WindowTitle(title="Overview")
        content_header = Adw.HeaderBar(title_widget=self.content_title)
        content = Adw.ToolbarView(content=self.stack)
        content.add_top_bar(content_header)
        # Shows what a running reconfiguration is doing (stopping/starting services).
        self.activity = Adw.Banner(revealed=False)
        content.add_top_bar(self.activity)

        self.split = Adw.NavigationSplitView(
            sidebar=Adw.NavigationPage(child=side, title=paths.APP_NAME),
            content=Adw.NavigationPage(child=content, title="Overview"),
            min_sidebar_width=210, max_sidebar_width=240)
        bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 720sp"))
        bp.add_setter(self.split, "collapsed", True)
        self.add_breakpoint(bp)
        self.root_stack.add_named(self.split, "main")
        self.listbox.select_row(self.listbox.get_row_at_index(0))

    def _selected(self, _lb, row):
        if row is None:
            return
        page = self.pages[row.get_index()]
        self.stack.set_visible_child(page)
        self.content_title.set_title(page.title)
        self.split.get_content().set_title(page.title)
        self.split.set_show_content(True)
        if hasattr(page, "refresh"):
            page.refresh()

    def select_page(self, title):
        for i, page in enumerate(self.pages):
            if page.title.lower() == title.lower():
                self.listbox.select_row(self.listbox.get_row_at_index(i))

    # ------------------------------------------------------------- wizard --
    def show_wizard(self):
        if self.wizard is not None:
            self.root_stack.remove(self.wizard)
        self.wizard = Wizard(self, self.app.tray is not None and self.app.tray.registered)
        self.root_stack.add_named(self.wizard, "wizard")
        self.root_stack.set_visible_child_name("wizard")

    def show_main(self, installed_now=False):
        self.root_stack.set_visible_child_name("main")
        if installed_now:
            self.toast("Installed — your node is syncing")
            self.app.poll_now()

    # ----------------------------------------------------------- snapshot --
    def update(self, snap):
        if not snap["installed"]:
            if self.root_stack.get_visible_child_name() != "wizard":
                self.show_wizard()
            return
        if self.root_stack.get_visible_child_name() == "wizard" and \
                self.wizard.nav.get_visible_page().get_tag() != "progress":
            self.show_main()
        activity = snap.get("activity") or ""
        if activity:
            self.activity.set_title(activity)
        self.activity.set_revealed(bool(activity))
        for page in self.pages:
            page.update(snap)
        own = snap["settings"].get("available", {}).get("bitfedot", "")
        n = len(snap.get("updates") or {}) + (1 if snap["settings"]["os_updates"].get("count") else 0) \
            + (1 if net.is_newer(own, __version__) else 0)
        self.badges["Updates"].set_label(str(n))
        self.badges["Updates"].set_visible(n > 0)
