"""Application: single instance, background/tray behaviour, status polling."""
import argparse
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from . import __version__, node, paths, settings  # noqa: E402
from .tray import Tray  # noqa: E402
from .ui.window import MainWindow  # noqa: E402


class App(Adw.Application):
    def __init__(self, demo=None, background=False, screenshot=None, page=None, theme=None):
        super().__init__(application_id=paths.APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.demo, self.start_hidden = demo, background
        self.screenshot, self.start_page, self.force_theme = screenshot, page, theme
        self.window = None
        self.tray = None
        self.snap = None
        self.held = False
        self._wake = threading.Event()
        self._notified_bg = False
        self._paused = False

    # ------------------------------------------------------------ startup --
    def do_startup(self):
        Adw.Application.do_startup(self)
        display = Gdk.Display.get_default()
        Gtk.IconTheme.get_for_display(display).add_search_path(str(paths.ASSETS_DIR / "icons"))
        css = Gtk.CssProvider()
        css.load_from_path(str(paths.ASSETS_DIR / "style.css"))
        Gtk.StyleContext.add_provider_for_display(display, css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        Gtk.Window.set_default_icon_name(paths.APP_ID)
        try:
            self.apply_theme(self.force_theme or settings.load()["theme"])
        except RuntimeError:
            pass

        for name, cb in (("quit", lambda *_: self.ask_quit()), ("about", self._about),
                         ("show", lambda *_: self.activate())):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", cb)
            self.add_action(action)
        self.set_accels_for_action("app.quit", ["<primary>q"])
        try:
            self.tray = Tray(self.activate)
        except GLib.Error:
            self.tray = None
        if not self.demo:
            self._resume_if_shut_down()
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def apply_theme(self, name):
        """'system' follows the desktop's light/dark preference."""
        Adw.StyleManager.get_default().set_color_scheme({
            "light": Adw.ColorScheme.FORCE_LIGHT, "dark": Adw.ColorScheme.FORCE_DARK,
        }.get(name, Adw.ColorScheme.DEFAULT))

    def do_activate(self):
        first = self.window is None
        if first:
            self.window = MainWindow(self)
            self.window.connect("close-request", self._close_request)
            if self.snap:
                self.window.update(self.snap)
            if self.start_page:
                self.window.select_page(self.start_page)
        if first and self.start_hidden:
            self._hold()
            return
        self.window.present()
        self.poll_now()
        if first and self.screenshot:
            GLib.timeout_add(1800, self._take_screenshot)

    def _hold(self):
        if not self.held:
            self.hold()
            self.held = True

    def _close_request(self, window):
        keep = self.demo is None and bool(self.snap and self.snap["settings"].get("background")
                                          and self.snap["installed"])
        if not keep:
            return False                      # default: destroy → app quits
        self._hold()
        window.set_visible(False)
        if not (self.tray and self.tray.registered) and not self._notified_bg:
            self._notified_bg = True
            n = Gio.Notification.new("BitFedot is still running")
            n.set_body("Your node keeps working in the background. Open BitFedot again to see it.")
            self.send_notification("background", n)
        return True

    # ------------------------------------------------------------ polling --
    def poll_now(self):
        self._wake.set()

    def pause_polling(self, paused: bool):
        """Suspend status polling (which reads the settings file) during a migration."""
        self._paused = paused
        if not paused:
            self.poll_now()

    def _poll_loop(self):
        while True:
            if self._paused:
                self._wake.wait(1)
                self._wake.clear()
                continue
            try:
                snap = node.demo_snapshot(self.demo == "synced") if self.demo else node.snapshot()
            except Exception as e:           # keep polling through transient errors
                print(f"status: {type(e).__name__}: {e}", file=sys.stderr)
                snap = None
            if snap is not None:
                GLib.idle_add(self._on_snapshot, snap)
            visible = self.window is not None and self.window.get_visible()
            self._wake.wait(3 if visible else 15)
            self._wake.clear()

    def _on_snapshot(self, snap):
        prev, self.snap = self.snap, snap
        if self.window is not None:
            self.window.update(snap)
            if prev and prev["installed"] and prev["phase"] == "ibd" and snap["phase"] == "ready":
                self.window.select_page("Overview")
                self.window.toast("Blockchain synced — Tor, Fulcrum and Mempool are starting")
        self._update_tray(snap)
        return False

    def _update_tray(self, snap):
        if self.tray is None:
            return
        if not snap["installed"]:
            status = "Not installed"
        else:
            b = snap["bitcoin"]
            if "blocks" in b:
                status = (f"Synced · block {b['blocks']:,}" if b["state"] == "synced"
                          else f"Syncing {b['progress'] * 100:.1f}% · block {b['blocks']:,}")
            else:
                status = b["message"]
        items = [(1, status, None)]
        if snap["installed"]:
            items.append((2, f"Tor: {snap['tor']['message']}", None))
        items += [(3, "-", None), (4, "Open BitFedot", self.activate)]
        if snap["installed"] and snap["mempool"]["state"] == "running":
            items.append((5, "Open Mempool explorer", lambda: Gio.AppInfo.launch_default_for_uri(
                f"http://127.0.0.1:{paths.MEMPOOL_PORT}", None)))
        if snap["installed"] and snap["tor"]["state"] == "running" and not self.demo:
            items.append((6, "Tor: reconnect", lambda: threading.Thread(
                target=node.tor_reconnect, daemon=True).start()))
        if snap["installed"] and not self.demo:
            stopped = snap["settings"]["all_stopped"]
            action = node.start_all if stopped else node.stop_all
            items.append((9, "Start all services" if stopped else "Stop all services safely",
                          lambda: threading.Thread(target=lambda: (action(), self.poll_now()),
                                                   daemon=True).start()))
        items += [(7, "-", None), (8, "Quit…", self.ask_quit)]
        self.tray.set_menu(items, status)

    # --------------------------------------------------------------- misc --
    def _about(self, *_):
        self.activate()
        self.window.select_page("About")

    # --------------------------------------------------------------- quit --
    def ask_quit(self):
        """Quitting offers the two things it can mean for a node."""
        installed = bool(self.snap and self.snap["installed"])
        if self.demo or not installed or self.snap["settings"]["all_stopped"]:
            return self.quit()                    # nothing is running that needs a decision
        self.activate()
        dlg = Adw.AlertDialog(
            heading="Quit BitFedot?",
            body="Run in background keeps your node working — syncing, serving your wallets, "
                 "relaying — with BitFedot in the tray.\n\n"
                 "Shut down safely stops Mempool, Fulcrum, Bitcoin Core and Tor one after another, "
                 "waits until everything is written to disk, then quits. The node starts again the "
                 "next time BitFedot is opened.")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("background", "Run in background")
        dlg.add_response("shutdown", "Shut down safely")
        dlg.set_response_appearance("background", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_response_appearance("shutdown", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("background")
        dlg.set_close_response("cancel")
        dlg.connect("response", self._quit_answer)
        dlg.present(self.window)

    def _quit_answer(self, _dlg, response):
        if response == "background":
            self._hold()
            self.window.set_visible(False)
        elif response == "shutdown":
            self._shut_down_and_quit()

    def _shut_down_and_quit(self):
        progress = Adw.AlertDialog(heading="Shutting down safely",
                                   body="Stopping services…\n\nPlease keep this window open.")
        progress.set_can_close(False)
        progress.set_extra_child(Adw.Spinner(width_request=32, height_request=32))
        progress.present(self.window)

        def report(msg, _frac=None):
            GLib.idle_add(lambda: progress.set_body(f"{msg}\n\nPlease keep this window open.") and False)

        def work():
            try:
                node.shut_down(report)
                error = None
            except Exception as e:               # still let the user out, and say what happened
                error = str(e)
            GLib.idle_add(done, error)

        def done(error):
            progress.force_close()
            if error:
                self.window.toast(f"Shutdown did not complete: {error}"[:200])
            else:
                self.quit()
            return False
        threading.Thread(target=work, daemon=True).start()

    def _resume_if_shut_down(self):
        """Counterpart of "Shut down safely": opening BitFedot starts the node again."""
        try:
            if not settings.load()["resume_on_launch"]:
                return
        except RuntimeError:
            return
        threading.Thread(target=lambda: (node.start_all(), self.poll_now()), daemon=True).start()

    def _take_screenshot(self):
        w = self.window
        paintable = Gtk.WidgetPaintable.new(w)
        snapshot = Gtk.Snapshot()
        paintable.snapshot(snapshot, w.get_width(), w.get_height())
        texture = w.get_renderer().render_texture(snapshot.to_node(), None)
        texture.save_to_png(self.screenshot)
        self.quit()
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bitfedot", description="Bitcoin node manager for Fedora")
    ap.add_argument("--background", action="store_true", help="start hidden (tray / background)")
    ap.add_argument("--demo", choices=("syncing", "synced"),
                    help="preview the interface with sample data; touches nothing")
    ap.add_argument("--theme", choices=("system", "light", "dark"), help="override the theme for this run")
    ap.add_argument("--page", help=argparse.SUPPRESS)
    ap.add_argument("--screenshot", metavar="PNG", help=argparse.SUPPRESS)
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    app = App(args.demo, args.background, args.screenshot, args.page, args.theme)
    if args.demo:   # never collide with / take over a real running instance
        app.set_application_id(paths.APP_ID + ".Demo")
    return app.run([sys.argv[0]])
