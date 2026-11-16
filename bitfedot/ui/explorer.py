"""Built-in block explorer: a native front end to this node's Mempool API.

One page with its own back/forward-less history: home → block → transaction →
address, each fetched off the main loop and rendered with ordinary libadwaita
rows. Nothing here talks to anything but 127.0.0.1 (see explorer.py).
"""
import time

from gi.repository import Adw, Gtk

from .. import explorer as api
from .widgets import copy_text, fmt_ago, fmt_bytes, icon_button, label, run_async, toast

REFRESH_SECONDS = 30


def _when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) + f"  ({fmt_ago(ts)})"


def _short(text, head=10, tail=10) -> str:
    return text if len(text) <= head + tail + 1 else f"{text[:head]}…{text[-tail:]}"


def _rate(value) -> str:
    return f"{value:.0f}" if value >= 10 else f"{value:.1f}"


class ExplorerPage(Gtk.Box):
    title = "Explorer"
    icon = "system-search-symbolic"

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo = demo
        self.history = []            # [(kind, value)]
        self.backend_up = False
        self.loaded_at = 0
        self.busy = False

        bar = Gtk.Box(spacing=8, margin_top=10, margin_bottom=10, margin_start=18, margin_end=18)
        self.back = icon_button("go-previous-symbolic", "Back", self._go_back, css=())
        self.home = icon_button("go-home-symbolic", "Explorer home", lambda: self.open("home"), css=())
        self.search = Gtk.SearchEntry(hexpand=True, placeholder_text="Block height, block hash, "
                                                                     "transaction ID or address")
        self.search.connect("activate", lambda *_: self._search())
        for w in (self.back, self.home, self.search):
            bar.append(w)
        self.append(Adw.Clamp(child=bar, maximum_size=940))

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE, vexpand=True)
        self.status = Adw.StatusPage()
        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                               margin_top=6, margin_bottom=32, margin_start=24, margin_end=24)
        scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER,
                                    child=Adw.Clamp(child=self.content, maximum_size=940))
        self.stack.add_named(self.status, "status")
        self.stack.add_named(scroll, "view")
        self.append(self.stack)
        self._show_status("system-search-symbolic", "Explorer",
                          "Opens as soon as the blockchain is synced and Mempool is running.")
        self._nav_state()

    # ---------------------------------------------------------- navigation --
    def update(self, snap):
        up = bool(snap.get("demo")) or snap["mempool"]["state"] == "running"
        came_up = up and not self.backend_up
        self.backend_up = up
        on_home = not self.history or self.history[-1][0] == "home"
        if not self.get_mapped() or self.busy:
            return
        if came_up or (up and on_home and time.time() - self.loaded_at > REFRESH_SECONDS):
            self.open("home", push=not self.history)

    def refresh(self):               # called when the page is selected in the sidebar
        if self.backend_up and not self.history:
            self.open("home")

    def _nav_state(self):
        self.back.set_sensitive(len(self.history) > 1)
        self.home.set_sensitive(bool(self.history) and self.history[-1][0] != "home")

    def _go_back(self):
        if len(self.history) > 1:
            self.history.pop()
            kind, value = self.history[-1]
            self.open(kind, value, push=False)

    def open(self, kind, value=None, push=True):
        if self.demo and kind != "home":
            return toast(self, "Demo mode — sample data only")
        fetch = {
            "home": lambda: api.demo_overview() if self.demo else api.overview(),
            "block": lambda: (api.block(value), api.block_txs(value)),
            "tx": lambda: api.tx(value),
            "address": lambda: (api.address(value), api.address_txs(value)),
        }[kind]
        self.busy = True

        def done(data):
            self.busy = False
            self.loaded_at = time.time()
            if push and (not self.history or self.history[-1] != (kind, value)):
                self.history.append((kind, value))
            self._nav_state()
            self._clear()
            getattr(self, f"_render_{kind}")(data)
            self.stack.set_visible_child_name("view")

        def failed(e):
            self.busy = False
            if kind == "home" or not self.history:
                self._show_status("network-offline-symbolic", "Explorer unavailable", str(e))
            else:
                toast(self, str(e))
        run_async(fetch, done, failed)

    def _search(self):
        query = self.search.get_text().strip()
        if not query:
            return
        if self.demo:
            return toast(self, "Demo mode — sample data only")
        run_async(lambda: api.search(query), lambda r: self.open(*r), lambda e: toast(self, str(e)))

    # ------------------------------------------------------------- helpers --
    def _show_status(self, icon, title, text):
        self.status.set_icon_name(icon)
        self.status.set_title(title)
        self.status.set_description(text)
        self.stack.set_visible_child_name("status")

    def _clear(self):
        child = self.content.get_first_child()
        while child:
            self.content.remove(child)
            child = self.content.get_first_child()

    def _heading(self, text, subtitle=""):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.append(label(text, "title-1"))
        if subtitle:
            box.append(label(subtitle, ["dim-label", "bf-mono"], selectable=True, wrap=True))
        self.content.append(box)

    def _group(self, title="", description=""):
        g = Adw.PreferencesGroup(title=title, description=description)
        self.content.append(g)
        return g

    def _prop(self, group, title, value, copy=None, target=None):
        """A property row; `target` = (kind, value) makes it a link."""
        row = Adw.ActionRow(title=title, subtitle=str(value), subtitle_selectable=target is None)
        row.add_css_class("property")
        if copy:
            row.add_suffix(icon_button("edit-copy-symbolic", "Copy", lambda: copy_text(self, copy)))
        if target:
            row.set_activatable(True)
            row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            row.connect("activated", lambda *_: self.open(*target))
        group.add(row)
        return row

    def _tx_row(self, group, t, addr=None):
        info = api.tx_summary(t)
        if addr:
            delta = api.address_delta(t, addr)
            amount = label(("+" if delta >= 0 else "−") + api.btc(abs(delta)),
                           "bf-amount-in" if delta >= 0 else "bf-amount-out")
        else:
            amount = label(api.btc(info["out"]), "bf-num")
        detail = "Coinbase (new coins)" if info["coinbase"] else \
            f"{len(t['vin'])} in → {len(t['vout'])} out · {_rate(info['rate'])} sat/vB"
        if addr:
            st = t.get("status", {})
            detail = (f"Block {st['block_height']:,} · " if st.get("confirmed") else "Unconfirmed · ") + detail
        row = Adw.ActionRow(title=_short(t["txid"], 14, 14), subtitle=detail, activatable=True)
        row.add_css_class("bf-mono-title")
        row.add_suffix(amount)
        row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
        row.connect("activated", lambda *_: self.open("tx", t["txid"]))
        group.add(row)

    def _more_button(self, group, fetch, add_rows):
        """'Load more' row: fetch() -> list; add_rows(list) -> bool (more to come?)."""
        row = Adw.ButtonRow(title="Load more", start_icon_name="view-more-symbolic")

        def clicked(*_):
            row.set_sensitive(False)

            def done(items):
                row.set_sensitive(True)
                group.remove(row)
                if add_rows(items):
                    group.add(row)
            run_async(fetch, done, lambda e: (row.set_sensitive(True), toast(self, str(e))))
        row.connect("activated", clicked)
        group.add(row)

    # ---------------------------------------------------------------- home --
    def _tile(self, caption, value, unit):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        box.add_css_class("bf-tile")
        box.append(label(caption.upper(), "bf-stat-caption"))
        line = Gtk.Box(spacing=6)
        line.append(label(value, "bf-tile-value"))
        line.append(label(unit, "bf-tile-unit"))
        line.get_last_child().set_valign(Gtk.Align.BASELINE_CENTER)
        box.append(line)
        return box

    def _flow(self, children, per_line):
        flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True,
                           min_children_per_line=2, max_children_per_line=per_line,
                           column_spacing=12, row_spacing=12)
        for c in children:
            flow.append(c)
            c.get_parent().set_focusable(False)
        return flow

    def _block_button(self, top, fee, lines, pending=False, target=None):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        box.append(label(top, "bf-cube-height"))
        box.append(label(fee, "bf-cube-fee"))
        for text in lines:
            box.append(label(text, "bf-cube-meta", ellipsize=True))
        b = Gtk.Button(child=box)
        b.add_css_class("bf-block")
        if pending:
            b.add_css_class("pending")
        if target:
            b.connect("clicked", lambda *_: self.open("block", target))
        else:
            b.set_can_target(False)
        return b

    def _render_home(self, d):
        fees, mp, diff = d["fees"], d["mempool"], d["difficulty"]
        self.content.append(label("TRANSACTION FEES", "bf-section"))
        self.content.append(self._flow([
            self._tile("No priority", str(fees["economyFee"]), "sat/vB"),
            self._tile("Low · ~1 hour", str(fees["hourFee"]), "sat/vB"),
            self._tile("Medium · ~30 min", str(fees["halfHourFee"]), "sat/vB"),
            self._tile("High · next block", str(fees["fastestFee"]), "sat/vB"),
        ], 4))

        self.content.append(label("BLOCKS", "bf-section"))
        strip = Gtk.Box(spacing=10, margin_top=4, margin_bottom=10, margin_start=2, margin_end=2)
        for i, nb in reversed(list(enumerate(d["next"][:3]))):
            strip.append(self._block_button(
                "Next" if i == 0 else f"In ~{(i + 1) * 10} min", f"~{_rate(nb['medianFee'])} sat/vB",
                [f"{nb['nTx']:,} transactions", f"{nb['totalFees'] / 1e8:.3f} BTC fees"], pending=True))
        strip.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL, margin_start=4, margin_end=4))
        for b in d["blocks"][:12]:
            ex = b.get("extras", {})
            strip.append(self._block_button(
                f"{b['height']:,}", f"~{_rate(ex.get('medianFee', 0))} sat/vB",
                [f"{b['tx_count']:,} transactions", fmt_ago(b["timestamp"]),
                 (ex.get("pool") or {}).get("name", "")], target=b["id"]))
        self.content.append(Gtk.ScrolledWindow(child=strip, vscrollbar_policy=Gtk.PolicyType.NEVER,
                                               hscrollbar_policy=Gtk.PolicyType.AUTOMATIC))

        self.content.append(label("NETWORK", "bf-section"))
        change = diff.get("difficultyChange", 0)
        self.content.append(self._flow([
            self._tile("Unconfirmed", f"{mp['count']:,}", "transactions"),
            self._tile("Mempool size", f"{mp['vsize'] / 1e6:.1f}", "MvB"),
            self._tile("Waiting fees", f"{mp['total_fee'] / 1e8:.3f}", "BTC"),
            self._tile(f"Difficulty in {diff.get('remainingBlocks', 0):,} blocks", f"{change:+.2f}", "%"),
        ], 4))

        g = self._group("Latest blocks")
        for b in d["blocks"][:10]:
            ex = b.get("extras", {})
            row = Adw.ActionRow(
                title=f"{b['height']:,}", activatable=True,
                subtitle=f"{fmt_ago(b['timestamp'])} · {b['tx_count']:,} transactions · "
                         f"{fmt_bytes(b['size'])} · {(ex.get('pool') or {}).get('name', 'Unknown')}")
            row.add_suffix(label(f"{ex.get('totalFees', 0) / 1e8:.3f} BTC fees", ["dim-label", "bf-num"]))
            row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            row.connect("activated", lambda *_a, h=b["id"]: self.open("block", h))
            g.add(row)

    # --------------------------------------------------------------- block --
    def _render_block(self, data):
        b, txs = data
        ex = b.get("extras", {})
        self._heading(f"Block {b['height']:,}")
        g = self._group()
        self._prop(g, "Hash", b["id"], copy=b["id"])
        self._prop(g, "Mined", _when(b["timestamp"]))
        self._prop(g, "Miner", (ex.get("pool") or {}).get("name", "Unknown"))
        self._prop(g, "Transactions", f"{b['tx_count']:,}")
        self._prop(g, "Size", f"{fmt_bytes(b['size'])} · {b['weight'] / 1e6:.2f} MWU")
        if "medianFee" in ex:
            rng = ex.get("feeRange") or []
            self._prop(g, "Fees", f"median {_rate(ex['medianFee'])} sat/vB"
                       + (f" · range {_rate(rng[0])} – {_rate(rng[-1])} sat/vB" if rng else "")
                       + f" · total {api.btc(ex.get('totalFees'))}")
            self._prop(g, "Miner reward (subsidy + fees)", api.btc(ex.get("reward")))
        self._prop(g, "Difficulty", f"{b.get('difficulty', 0):,.0f}")
        if b.get("previousblockhash"):
            self._prop(g, "Previous block", _short(b["previousblockhash"], 16, 16),
                       target=("block", b["previousblockhash"]))

        tg = self._group("Transactions")
        shown = {"n": 0}

        def add(items):
            for t in items:
                self._tx_row(tg, t)
            shown["n"] += len(items)
            return shown["n"] < b["tx_count"] and bool(items)
        if add(txs):
            self._more_button(tg, lambda: api.block_txs(b["id"], shown["n"]), add)

    # ---------------------------------------------------------- transaction --
    def _render_tx(self, t):
        info, st = api.tx_summary(t), t.get("status", {})
        self._heading("Transaction")
        g = self._group()
        self._prop(g, "Transaction ID", t["txid"], copy=t["txid"])
        if st.get("confirmed"):
            self._prop(g, "Status", f"Confirmed in block {st['block_height']:,} · {_when(st['block_time'])}",
                       target=("block", st["block_hash"]))
        else:
            self._prop(g, "Status", "Unconfirmed — waiting in the mempool")
        if not info["coinbase"]:
            self._prop(g, "Fee", f"{info['fee']:,} sat · {info['rate']:.2f} sat/vB")
        self._prop(g, "Size", f"{info['vsize']:,.0f} vB · {t.get('weight', 0):,} WU · {t.get('size', 0):,} bytes")
        self._prop(g, "Total output", api.btc(info["out"]))

        ins = self._group(f"Inputs ({len(t['vin'])})")
        for i in t["vin"][:200]:
            prev = i.get("prevout") or {}
            addr = prev.get("scriptpubkey_address")
            if i.get("is_coinbase"):
                row = Adw.ActionRow(title="Coinbase", subtitle="Newly created coins and collected fees")
            else:
                row = Adw.ActionRow(title=addr or prev.get("scriptpubkey_type", "Non-standard script"),
                                    subtitle=f"{_short(i['txid'], 12, 12)}:{i['vout']}")
                row.add_suffix(label(api.btc(prev.get("value")), "bf-num"))
                if addr:
                    row.set_activatable(True)
                    row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
                    row.connect("activated", lambda *_a, a=addr: self.open("address", a))
            ins.add(row)

        outs = self._group(f"Outputs ({len(t['vout'])})")
        for n, o in enumerate(t["vout"][:200]):
            addr = o.get("scriptpubkey_address")
            kind = o.get("scriptpubkey_type", "")
            row = Adw.ActionRow(title=addr or ("Data (OP_RETURN)" if kind == "op_return" else kind or "Script"),
                                subtitle=f"Output #{n} · {kind}")
            row.add_suffix(label(api.btc(o.get("value")), "bf-num"))
            if addr:
                row.set_activatable(True)
                row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
                row.connect("activated", lambda *_a, a=addr: self.open("address", a))
            outs.add(row)

    # -------------------------------------------------------------- address --
    def _render_address(self, data):
        a, txs = data
        addr, chain, pend = a["address"], a["chain_stats"], a["mempool_stats"]
        self._heading("Address")
        g = self._group()
        self._prop(g, "Address", addr, copy=addr)
        balance = chain["funded_txo_sum"] - chain["spent_txo_sum"]
        self._prop(g, "Confirmed balance", api.btc(balance))
        pending = pend["funded_txo_sum"] - pend["spent_txo_sum"]
        if pend["tx_count"]:
            self._prop(g, "Unconfirmed", f"{'+' if pending >= 0 else '−'}{api.btc(abs(pending))} "
                                         f"in {pend['tx_count']} transaction(s)")
        self._prop(g, "Total received", api.btc(chain["funded_txo_sum"]))
        self._prop(g, "Total sent", api.btc(chain["spent_txo_sum"]))
        self._prop(g, "Transactions", f"{chain['tx_count']:,}")

        tg = self._group("History")
        last = {"txid": ""}

        def add(items):
            for t in items:
                self._tx_row(tg, t, addr)
            confirmed = [t for t in items if t.get("status", {}).get("confirmed")]
            if confirmed:
                last["txid"] = confirmed[-1]["txid"]
            return len(confirmed) >= api.PAGE
        if not txs:
            tg.add(Adw.ActionRow(title="No transactions yet"))
        elif add(txs):
            self._more_button(tg, lambda: api.address_txs(addr, last["txid"]), add)
