"""Main menu: sync status, latest block, and the four services."""
from gi.repository import Adw, Gio, Gtk

from .. import node, paths, services
from .widgets import (Pill, Ring, copy_text, error_text, fmt_ago, fmt_bytes, fmt_duration,
                      icon_button, label, run_async, toast)


class Stat(Gtk.Box):
    def __init__(self, caption):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        self.value = label("—", "bf-stat-value")
        self.caption = label(caption.upper(), "bf-stat-caption")
        self.append(self.value)
        self.append(self.caption)

    def set(self, text):
        self.value.set_label(text)


class ServiceCard(Gtk.Box):
    """One service: status pill, a line of detail, start/stop + restart."""

    def __init__(self, page, key, title, icon, unit, setting):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12, hexpand=True)
        self.add_css_class("bf-card")
        self.page, self.key, self.unit, self.setting = page, key, unit, setting
        self.enabled = True

        head = Gtk.Box(spacing=12)
        badge = Gtk.Image(icon_name=icon, pixel_size=22, valign=Gtk.Align.CENTER)
        badge.add_css_class("bf-icon-badge")
        names = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True, valign=Gtk.Align.CENTER)
        names.append(label(title, "bf-card-title"))
        self.version = label("", ["dim-label", "caption"])
        names.append(self.version)
        self.pill = Pill()
        for w in (badge, names, self.pill):
            head.append(w)
        self.append(head)

        self.message = label("", "dim-label", wrap=True, ellipsize=True)
        self.message.set_lines(2)
        self.message.set_vexpand(True)
        self.message.set_valign(Gtk.Align.START)
        self.append(self.message)

        self.buttons = Gtk.Box(spacing=6)
        self.extra = Gtk.Box(spacing=6, hexpand=True)
        self.toggle = icon_button("media-playback-stop-symbolic", "Stop", self._toggle)
        self.restart = icon_button("view-refresh-symbolic", "Restart", self._restart)
        for w in (self.extra, self.restart, self.toggle):
            self.buttons.append(w)
        self.append(self.buttons)

    def add_action(self, text, callback):
        b = Gtk.Button(label=text)
        b.connect("clicked", lambda *_: callback())
        self.extra.append(b)
        return b

    def update(self, info, s):
        self.version.set_label(f"v{info['version']}" if info.get("version") else "")
        self.pill.set_state(info["state"], info.get("pill"))
        self.message.set_label(info.get("message", ""))
        self.message.set_tooltip_text(info.get("message", ""))
        self.enabled = bool(s[self.setting])
        stopped = info["state"] in ("stopped", "error", "blocked")
        self.toggle.set_icon_name("media-playback-stop-symbolic" if self.enabled
                                  else "media-playback-start-symbolic")
        self.toggle.set_tooltip_text("Stop" if self.enabled else "Start")
        self.restart.set_sensitive(not stopped)
        # Fulcrum, Mempool (and Tor during a clearnet sync) only exist once synced.
        gated = self.key in ("fulcrum", "mempool") and s["phase"] != "ready"
        gated = gated or (self.key == "tor" and services.in_ibd(s) and s["ibd_clearnet"])
        self.toggle.set_sensitive(not gated)

    def _toggle(self):
        if self.page.demo:
            return toast(self, "Demo mode — nothing is running")
        turn_on = not self.enabled
        self.toggle.set_sensitive(False)
        app = self.get_root().app
        app.poll_now()
        run_async(lambda: node.apply_settings(**{self.setting: turn_on}),
                  lambda _r: (toast(self, "Started" if turn_on else "Stopped safely"), app.poll_now()),
                  lambda e: (toast(self, error_text(e)), app.poll_now()))

    def _restart(self):
        if self.page.demo:
            return toast(self, "Demo mode — nothing is running")
        run_async(lambda: node.restart(self.unit), lambda _r: toast(self, "Restarting…"),
                  lambda e: toast(self, error_text(e)))


class OverviewPage(Gtk.ScrolledWindow):
    title = "Overview"
    icon = "go-home-symbolic"

    def __init__(self, demo=False):
        super().__init__(hscrollbar_policy=Gtk.PolicyType.NEVER)
        self.demo = demo
        self.snap = None
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                      margin_top=24, margin_bottom=32, margin_start=24, margin_end=24)
        self.set_child(Adw.Clamp(child=box, maximum_size=940))

        # ---- hero ---------------------------------------------------------
        self.hero = Gtk.Box(spacing=28)
        self.hero.add_css_class("bf-hero")
        self.ring = Ring()
        center = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER,
                         halign=Gtk.Align.CENTER)
        self.ring_value = label("—", "bf-ring-value", xalign=0.5)
        self.ring_caption = label("", "bf-ring-caption", xalign=0.5)
        center.append(self.ring_value)
        center.append(self.ring_caption)
        overlay = Gtk.Overlay(child=self.ring, valign=Gtk.Align.CENTER)
        overlay.add_overlay(center)
        self.hero.append(overlay)

        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True,
                        valign=Gtk.Align.CENTER)
        self.h_title = label("Starting…", "bf-hero-title", wrap=True)
        self.h_sub = label("", "dim-label", wrap=True)
        right.append(self.h_title)
        right.append(self.h_sub)
        stats = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True, margin_top=14,
                            min_children_per_line=2, max_children_per_line=4,
                            column_spacing=12, row_spacing=8)
        self.s_height, self.s_headers = Stat("Block height"), Stat("Headers")
        self.s_peers, self.s_disk = Stat("Peers out / in"), Stat("Chain on disk")
        for st in (self.s_height, self.s_headers, self.s_peers, self.s_disk):
            stats.append(st)
            st.get_parent().set_focusable(False)
        right.append(stats)
        self.hero.append(right)
        box.append(self.hero)

        # ---- latest block -------------------------------------------------
        block = Gtk.Box(spacing=18)
        block.add_css_class("bf-card")
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        left.append(label("LATEST BLOCK", "bf-section"))
        self.b_height = label("—", "bf-block-height")
        left.append(self.b_height)
        block.append(left)
        mid = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True,
                      valign=Gtk.Align.CENTER)
        self.b_hash = label("", "bf-mono", ellipsize=True)
        self.b_hash.set_ellipsize(2)  # middle
        self.b_meta = label("", "dim-label")
        mid.append(self.b_hash)
        mid.append(self.b_meta)
        block.append(mid)
        block.append(icon_button("edit-copy-symbolic", "Copy block hash", self._copy_hash))
        box.append(block)

        # ---- services -----------------------------------------------------
        head = Gtk.Box(spacing=12)
        head.append(label("SERVICES", "bf-section"))
        head.get_first_child().set_hexpand(True)
        self.all_btn = Gtk.Button(label="Stop all", tooltip_text="Stop every service safely, in order")
        self.all_btn.add_css_class("pill")
        self.all_btn.connect("clicked", lambda *_: self._toggle_all())
        head.append(self.all_btn)
        box.append(head)
        grid = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True,
                           min_children_per_line=1, max_children_per_line=2,
                           column_spacing=12, row_spacing=12)
        self.cards = {
            "bitcoin": ServiceCard(self, "bitcoin", "Bitcoin Core", "network-server-symbolic",
                                   paths.U_BITCOIND, "bitcoind_enabled"),
            "tor": ServiceCard(self, "tor", "Tor", "security-high-symbolic", paths.U_TOR, "tor_enabled"),
            "fulcrum": ServiceCard(self, "fulcrum", "Fulcrum", "network-transmit-receive-symbolic",
                                   paths.U_FULCRUM, "fulcrum_enabled"),
            "mempool": ServiceCard(self, "mempool", "Mempool", "system-search-symbolic",
                                   paths.U_MEMPOOL, "mempool_enabled"),
        }
        for card in self.cards.values():
            grid.append(card)
            card.get_parent().set_focusable(False)
        self.newnym = self.cards["tor"].add_action("New identity", self._newnym)
        self.cards["fulcrum"].add_action("Copy address", self._copy_fulcrum)
        self.open_mempool = self.cards["mempool"].add_action("Open explorer", self._open_mempool)
        box.append(grid)

    # ------------------------------------------------------------- updates --
    def update(self, snap):
        self.snap = snap
        b, s = snap["bitcoin"], snap["settings"]
        synced = b["state"] == "synced"
        (self.hero.add_css_class if synced else self.hero.remove_css_class)("synced")

        if s["all_stopped"] and "blocks" not in b:
            b = {**b, "message": "All services are stopped. Press “Start all” to bring the node back."}
        if "blocks" in b:
            pct = b["progress"] * 100
            self.ring.set_progress(b["progress"], synced)
            self.ring_value.set_label("100%" if synced else f"{pct:.1f}%" if pct < 99.95 else "99.9%")
            self.ring_caption.set_label("VALIDATED" if synced else "SYNCING")
            self.s_height.set(f"{b['blocks']:,}")
            self.s_headers.set(f"{b['headers']:,}")
            self.s_peers.set(f"{b['peers_out']} / {b['peers_in']}")
            self.s_disk.set(fmt_bytes(b["size_on_disk"]))
            self.b_height.set_label(f"{b['blocks']:,}")
            self.b_hash.set_label(b["best_hash"])
            txs = f" · {b['best_txs']:,} transactions" if b.get("best_txs") else ""
            self.b_meta.set_label(f"Mined {fmt_ago(b['best_time'])}{txs}")
            if synced:
                self.h_title.set_label("Fully synced")
                still = [f"{name}: {snap[key]['message']}" for key, name in (("fulcrum", "Fulcrum"), ("mempool", "Mempool"))
                         if s["phase"] == "ready" and snap[key]["state"] in ("syncing", "starting")]
                txi = b.get("txindex") or {}
                self.h_sub.set_label(
                    ("Every block verified by your own node." if txi.get("synced", True) or s["phase"] != "ready"
                     else "Chain verified. Building the transaction index for Fulcrum and Mempool…")
                    + ("\n" + "\n".join(still) if still else ""))
            else:
                self.h_title.set_label("Syncing the blockchain")
                if b.get("txs_total"):
                    work = (f"{b['txs_done'] / 1e6:,.0f} million of about "
                            f"{b['txs_total'] / 1e6:,.0f} million transactions verified")
                else:
                    work = f"{b['headers'] - b['blocks']:,} blocks to go"
                mode = "Running over clearnet for speed — Tor starts when the sync completes." \
                    if s["ibd_clearnet"] and s["phase"] != "ready" else "Catching up."
                self.h_sub.set_label(f"{work} · {fmt_duration(b.get('eta'))} remaining\n{mode}")
                self.h_sub.set_tooltip_text(
                    "The estimate counts transactions, not blocks: recent blocks hold thousands of "
                    "transactions each, so block height climbs more slowly as the sync goes on. It "
                    "also allows for the slower final stretch, where every signature is checked.")
        else:
            self.ring.set_progress(0)
            self.ring_value.set_label("—")
            self.ring_caption.set_label("")
            self.h_title.set_label({"stopped": "Node stopped", "error": "Bitcoin Core failed",
                                    "stopping": "Shutting down"}.get(b["state"], "Starting Bitcoin Core"))
            self.h_sub.set_label(b["message"])

        busy = bool(snap.get("activity"))
        for key, card in self.cards.items():
            card.update(snap[key], s)
            if busy or s["all_stopped"]:
                card.toggle.set_sensitive(False)   # one reconfiguration at a time
                card.restart.set_sensitive(False)
        self.all_btn.set_label("Start all" if s["all_stopped"] else "Stop all")
        self.all_btn.set_tooltip_text("Start every service again" if s["all_stopped"]
                                      else "Stop every service safely, in order")
        (self.all_btn.add_css_class if s["all_stopped"] else self.all_btn.remove_css_class)("suggested-action")
        self.all_btn.set_sensitive(not busy)
        self.open_mempool.set_sensitive(node.explorer_available(snap))
        self.newnym.set_sensitive(snap["tor"]["state"] == "running")

    # ------------------------------------------------------------- actions --
    def _toggle_all(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        stopped = bool(self.snap and self.snap["settings"]["all_stopped"])
        self.all_btn.set_sensitive(False)
        self.get_root().app.poll_now()
        run_async(node.start_all if stopped else node.stop_all,
                  lambda _r: (toast(self, "Services are starting" if stopped else "All services stopped"),
                              self.get_root().app.poll_now()),
                  lambda e: (toast(self, error_text(e)), self.get_root().app.poll_now()))

    def _copy_hash(self):
        h = (self.snap or {}).get("bitcoin", {}).get("best_hash")
        if h:
            copy_text(self, h, "Block hash copied")

    def _copy_fulcrum(self):
        onion = (self.snap or {}).get("fulcrum", {}).get("onion")
        addr = f"{onion}:50001:t" if onion else f"127.0.0.1:{paths.FULCRUM_PORT}:t"
        copy_text(self, addr, f"Copied {addr}")

    def _open_mempool(self):
        Gio.AppInfo.launch_default_for_uri(f"http://127.0.0.1:{paths.MEMPOOL_PORT}", None)

    def _newnym(self):
        if self.demo:
            return toast(self, "Demo mode — nothing is running")
        run_async(node.tor_new_identity, lambda _r: toast(self, "New Tor circuits requested"),
                  lambda e: toast(self, "Tor is not running"))
