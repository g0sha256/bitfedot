"""Shared UI helpers and small custom widgets."""
import math
import threading
import time
import traceback

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Adw, Gdk, GdkPixbuf, Gio, GLib, Gtk  # noqa: E402

ORANGE = (0.969, 0.576, 0.102)
GREEN = (0.180, 0.761, 0.494)


def run_async(fn, on_done=None, on_error=None):
    """Run blocking `fn` off the main loop; deliver the result back on it."""
    def work():
        try:
            result = fn()
        except Exception as e:
            traceback.print_exc()
            if on_error:
                # Bind now: Python clears `e` when the except block ends, long
                # before the main loop gets to run the callback.
                GLib.idle_add(lambda err=e: on_error(err) and False)
            return
        if on_done:
            GLib.idle_add(lambda: on_done(result) and False)
    threading.Thread(target=work, daemon=True).start()


def toast(widget, text):
    root = widget.get_root()
    if root is not None and hasattr(root, "toast"):
        root.toast(text)


def error_text(e) -> str:
    return (str(e).strip() or type(e).__name__)[:300]


def copy_text(widget, text, what="Copied"):
    widget.get_clipboard().set(text)
    toast(widget, what)


def label(text="", css=(), xalign=0.0, wrap=False, selectable=False, ellipsize=False):
    lab = Gtk.Label(label=text, xalign=xalign, wrap=wrap, selectable=selectable)
    if ellipsize:
        lab.set_ellipsize(3)  # Pango.EllipsizeMode.END
    for c in ([css] if isinstance(css, str) else css):
        lab.add_css_class(c)
    return lab


def svg_texture(data: bytes, size: int):
    """SVG bytes -> a texture at most 2 × `size` pixels wide and high (so that it stays sharp
    on a dense screen when shown at `size`), or None if it cannot be drawn. Never raises."""
    try:
        stream = Gio.MemoryInputStream.new_from_bytes(GLib.Bytes.new(data))
        pixbuf = GdkPixbuf.Pixbuf.new_from_stream_at_scale(stream, size * 2, size * 2, True, None)
        layout = Gdk.MemoryFormat.R8G8B8A8 if pixbuf.get_has_alpha() else Gdk.MemoryFormat.R8G8B8
        return Gdk.MemoryTexture.new(pixbuf.get_width(), pixbuf.get_height(), layout,
                                     pixbuf.read_pixel_bytes(), pixbuf.get_rowstride())
    except (GLib.Error, TypeError, ValueError):
        return None


def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1000


def fmt_duration(sec) -> str:
    if sec is None:
        return "estimating…"
    sec = int(sec)
    if sec < 90:
        return "about a minute"
    if sec < 5400:
        return f"about {round(sec / 60)} minutes"
    if sec < 172800:
        return f"about {sec / 3600:.1f} hours"
    return f"about {sec / 86400:.1f} days"


def fmt_ago(ts) -> str:
    d = max(0, int(time.time() - ts))
    if d < 60:
        return "just now"
    if d < 3600:
        return f"{d // 60} min ago"
    if d < 172800:
        return f"{d // 3600} h {d % 3600 // 60} min ago"
    if d < 86400 * 60:
        return f"{d // 86400} days ago"
    return f"{d / (86400 * 365.25):.1f} years ago"


PILL = {  # state -> (text, css class)
    "running": ("Running", "ok"), "synced": ("Synced", "ok"),
    "syncing": ("Syncing", "busy"), "starting": ("Starting", "busy"), "stopping": ("Stopping", "busy"),
    "error": ("Error", "bad"), "blocked": ("Waiting", "bad"), "stopped": ("Stopped", "off"),
}


class Pill(Gtk.Label):
    def __init__(self):
        super().__init__(valign=Gtk.Align.CENTER)
        self.add_css_class("bf-pill")
        self._cls = None

    def set_state(self, state, text=None):
        default, cls = PILL.get(state, (state.title(), "off"))
        self.set_label(text or default)
        if cls != self._cls:
            if self._cls:
                self.remove_css_class(self._cls)
            self.add_css_class(cls)
            self._cls = cls


class Ring(Gtk.DrawingArea):
    """Circular progress indicator."""

    def __init__(self, size=168, width=13):
        super().__init__(content_width=size, content_height=size)
        self.fraction, self.done, self.line = 0.0, False, width
        self.set_draw_func(self._draw)

    def set_progress(self, fraction, done=False):
        if (fraction, done) != (self.fraction, self.done):
            self.fraction, self.done = fraction, done
            self.queue_draw()

    def _draw(self, _area, cr, w, h):
        r = min(w, h) / 2 - self.line / 2 - 1
        cx, cy = w / 2, h / 2
        fg = self.get_color()
        cr.set_line_width(self.line)
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.10)
        cr.arc(cx, cy, r, 0, 2 * math.pi)
        cr.stroke()
        if self.fraction > 0:
            cr.set_line_cap(1)  # round
            cr.set_source_rgb(*(GREEN if self.done else ORANGE))
            start = -math.pi / 2
            cr.arc(cx, cy, r, start, start + 2 * math.pi * max(0.004, min(self.fraction, 1.0)))
            cr.stroke()


def icon_button(icon, tooltip, callback, css=("flat",)):
    b = Gtk.Button(icon_name=icon, tooltip_text=tooltip, valign=Gtk.Align.CENTER)
    for c in css:
        b.add_css_class(c)
    b.connect("clicked", lambda *_: callback())
    return b


def radio_row(title, subtitle, group=None):
    """An ActionRow with a leading radio button. -> (row, check)"""
    check = Gtk.CheckButton(valign=Gtk.Align.CENTER)
    if group is not None:
        check.set_group(group)
    row = Adw.ActionRow(title=title, subtitle=subtitle, activatable_widget=check)
    row.add_prefix(check)
    return row, check
