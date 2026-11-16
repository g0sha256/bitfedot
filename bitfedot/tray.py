"""System tray icon: a StatusNotifierItem with a com.canonical.dbusmenu menu,
implemented directly on D-Bus (works with GTK 4; no AppIndicator library).

KDE Plasma shows it natively. GNOME needs the "AppIndicator and
KStatusNotifierItem Support" extension; the icon appears automatically as soon
as a watcher shows up on the bus."""
import os

from gi.repository import Gio, GLib

from . import paths

WATCHER = "org.kde.StatusNotifierWatcher"

SNI_XML = """
<node><interface name="org.kde.StatusNotifierItem">
  <property name="Category" type="s" access="read"/>
  <property name="Id" type="s" access="read"/>
  <property name="Title" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconName" type="s" access="read"/>
  <property name="IconThemePath" type="s" access="read"/>
  <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
  <property name="ItemIsMenu" type="b" access="read"/>
  <property name="Menu" type="o" access="read"/>
  <method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="ContextMenu"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="Scroll"><arg type="i" direction="in"/><arg type="s" direction="in"/></method>
  <signal name="NewTitle"/><signal name="NewIcon"/><signal name="NewToolTip"/>
  <signal name="NewStatus"><arg type="s"/></signal>
</interface></node>"""

MENU_XML = """
<node><interface name="com.canonical.dbusmenu">
  <property name="Version" type="u" access="read"/>
  <property name="TextDirection" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconThemePath" type="as" access="read"/>
  <method name="GetLayout">
    <arg type="i" direction="in"/><arg type="i" direction="in"/><arg type="as" direction="in"/>
    <arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/>
  </method>
  <method name="GetGroupProperties">
    <arg type="ai" direction="in"/><arg type="as" direction="in"/>
    <arg type="a(ia{sv})" direction="out"/>
  </method>
  <method name="GetProperty">
    <arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/>
  </method>
  <method name="Event">
    <arg type="i" direction="in"/><arg type="s" direction="in"/>
    <arg type="v" direction="in"/><arg type="u" direction="in"/>
  </method>
  <method name="EventGroup">
    <arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/>
  </method>
  <method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
  <method name="AboutToShowGroup">
    <arg type="ai" direction="in"/><arg type="ai" direction="out"/><arg type="ai" direction="out"/>
  </method>
  <signal name="ItemsPropertiesUpdated"><arg type="a(ia{sv})"/><arg type="a(ias)"/></signal>
  <signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
  <signal name="ItemActivationRequested"><arg type="i"/><arg type="u"/></signal>
</interface></node>"""


class Tray:
    """items: list of (id, label, callback | None); label '-' is a separator,
    callback None renders a disabled informational line."""

    def __init__(self, on_activate):
        self.on_activate = on_activate
        self.items = []
        self.tooltip = paths.APP_NAME
        self.revision = 1
        self.registered = False
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        sni = Gio.DBusNodeInfo.new_for_xml(SNI_XML).interfaces[0]
        menu = Gio.DBusNodeInfo.new_for_xml(MENU_XML).interfaces[0]
        self.bus.register_object("/StatusNotifierItem", sni, self._sni_call, self._sni_get, None)
        self.bus.register_object("/MenuBar", menu, self._menu_call, self._menu_get, None)
        Gio.bus_own_name_on_connection(self.bus, self.name, Gio.BusNameOwnerFlags.NONE, None, None)
        Gio.bus_watch_name_on_connection(self.bus, WATCHER, Gio.BusNameWatcherFlags.NONE,
                                         self._watcher_up, self._watcher_down)

    # ------------------------------------------------------------ watcher --
    def _watcher_up(self, *_):
        def done(bus, res):
            try:
                bus.call_finish(res)
                self.registered = True
            except GLib.Error:
                self.registered = False
        self.bus.call(WATCHER, "/StatusNotifierWatcher", WATCHER, "RegisterStatusNotifierItem",
                      GLib.Variant("(s)", (self.name,)), None, Gio.DBusCallFlags.NONE, -1, None, done)

    def _watcher_down(self, *_):
        self.registered = False

    # ---------------------------------------------------------------- API --
    def set_menu(self, items, tooltip):
        if tooltip != self.tooltip:
            self.tooltip = tooltip
            self._emit("/StatusNotifierItem", "org.kde.StatusNotifierItem", "NewToolTip", None)
        if [(i, t, cb is None) for i, t, cb in items] != [(i, t, cb is None) for i, t, cb in self.items]:
            self.items = items
            self.revision += 1
            self._emit("/MenuBar", "com.canonical.dbusmenu", "LayoutUpdated",
                       GLib.Variant("(ui)", (self.revision, 0)))
        else:
            self.items = items

    def _emit(self, path, iface, signal, params):
        try:
            self.bus.emit_signal(None, path, iface, signal, params)
        except GLib.Error:
            pass

    # ---------------------------------------------------------------- SNI --
    def _sni_get(self, _c, _s, _p, _i, prop):
        return {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", paths.APP_ID),
            "Title": GLib.Variant("s", paths.APP_NAME),
            "Status": GLib.Variant("s", "Active"),
            "IconName": GLib.Variant("s", paths.APP_ID),
            "IconThemePath": GLib.Variant("s", str(paths.ASSETS_DIR / "icons")),
            "ToolTip": GLib.Variant("(sa(iiay)ss)", (paths.APP_ID, [], paths.APP_NAME, self.tooltip)),
            "ItemIsMenu": GLib.Variant("b", False),
            "Menu": GLib.Variant("o", "/MenuBar"),
        }.get(prop)

    def _sni_call(self, _c, _s, _p, _i, method, _params, invocation):
        if method in ("Activate", "SecondaryActivate"):
            GLib.idle_add(lambda: self.on_activate() and False)
        invocation.return_value(None)

    # --------------------------------------------------------------- menu --
    def _props(self, item):
        _id, text, cb = item
        if text == "-":
            return {"type": GLib.Variant("s", "separator")}
        return {"label": GLib.Variant("s", text), "enabled": GLib.Variant("b", cb is not None),
                "visible": GLib.Variant("b", True)}

    def _layout(self):
        children = [GLib.Variant("(ia{sv}av)", (item[0], self._props(item), []))
                    for item in self.items]
        return (0, {"children-display": GLib.Variant("s", "submenu")}, children)

    def _menu_get(self, _c, _s, _p, _i, prop):
        return {"Version": GLib.Variant("u", 3), "TextDirection": GLib.Variant("s", "ltr"),
                "Status": GLib.Variant("s", "normal"),
                "IconThemePath": GLib.Variant("as", [])}.get(prop)

    def _click(self, item_id):
        for _id, _text, cb in self.items:
            if _id == item_id and cb:
                # Bind now: the loop variable moves on before the main loop runs this,
                # and every click would run the last item's action ("Quit…").
                GLib.idle_add(lambda cb=cb: cb() and False)
                break

    def _menu_call(self, _c, _s, _p, _i, method, params, inv):
        if method == "GetLayout":
            inv.return_value(GLib.Variant("(u(ia{sv}av))", (self.revision, self._layout())))
        elif method == "GetGroupProperties":
            ids = params.unpack()[0]
            inv.return_value(GLib.Variant("(a(ia{sv}))", (
                [(it[0], self._props(it)) for it in self.items if not ids or it[0] in ids],)))
        elif method == "GetProperty":
            item_id, name = params.unpack()
            props = next((self._props(it) for it in self.items if it[0] == item_id), {})
            inv.return_value(GLib.Variant("(v)", (props.get(name, GLib.Variant("s", "")),)))
        elif method == "Event":
            item_id, event, _data, _ts = params.unpack()
            if event == "clicked":
                self._click(item_id)
            inv.return_value(None)
        elif method == "EventGroup":
            for item_id, event, _data, _ts in params.unpack()[0]:
                if event == "clicked":
                    self._click(item_id)
            inv.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            inv.return_value(GLib.Variant("(b)", (False,)))
        elif method == "AboutToShowGroup":
            inv.return_value(GLib.Variant("(aiai)", ([], [])))
        else:
            inv.return_value(None)
