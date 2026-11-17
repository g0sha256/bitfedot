"""Client for the block explorer, backed by this node's own Mempool instance.

Every lookup goes to http://127.0.0.1:<MEMPOOL_PORT>/api — the addresses and
transactions you look up never leave the machine. (Developers can point
BITFEDOT_EXPLORER_API at another Mempool instance to work on the UI without a
synced node; that is never done implicitly.)

The REST API is Mempool's: https://mempool.space/docs/api/rest
"""
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import paths

BASE = os.environ.get("BITFEDOT_EXPLORER_API", f"http://127.0.0.1:{paths.MEMPOOL_PORT}").rstrip("/")
PAGE = 25          # transactions per page, fixed by the API

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_ADDRESS = re.compile(r"^(bc1[02-9ac-hj-np-z]{11,87}|[13][1-9A-HJ-NP-Za-km-z]{25,39})$")


class ExplorerError(Exception):
    pass


class NotFound(ExplorerError):
    pass


def _get(path, raw=False):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "bitfedot"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            raise NotFound("Not found")
        raise ExplorerError(f"The explorer backend answered with HTTP {e.code}")
    except (OSError, ValueError, http.client.HTTPException):
        raise ExplorerError("The explorer backend is not reachable. It starts once the "
                            "blockchain is synced and Mempool is running.")
    if raw:
        return body.strip()
    try:
        return json.loads(body)
    except ValueError:
        raise ExplorerError("Unexpected answer from the explorer backend")


def available() -> bool:
    try:
        _get("/api/v1/backend-info")
        return True
    except ExplorerError:
        return False


# ---------------------------------------------------------------- queries --
def overview() -> dict:
    """Everything the explorer's home view shows, in one call."""
    return {
        "fees": _get("/api/v1/fees/recommended"),
        "mempool": _get("/api/mempool"),
        "next": _get("/api/v1/fees/mempool-blocks"),
        "blocks": _get("/api/v1/blocks"),
        "difficulty": _get("/api/v1/difficulty-adjustment"),
    }


def block(block_hash: str) -> dict:
    return _get(f"/api/v1/block/{block_hash}")


def block_hash_at(height: int) -> str:
    return _get(f"/api/block-height/{int(height)}", raw=True)


def block_txs(block_hash: str, start=0) -> list:
    return _get(f"/api/block/{block_hash}/txs/{int(start)}")


def tx(txid: str) -> dict:
    return _get(f"/api/tx/{txid}")


def address(addr: str) -> dict:
    return _get(f"/api/address/{urllib.parse.quote(addr, safe='')}")


def address_txs(addr: str, after_txid="") -> list:
    """Newest first; pass the last txid of the previous page to continue."""
    q = f"?after_txid={after_txid}" if after_txid else ""
    return _get(f"/api/address/{urllib.parse.quote(addr, safe='')}/txs{q}")


def classify(query: str):
    """Decide what a search string is, without asking the network.
    -> ('height', int) | ('hash', str) | ('address', str) | (None, None)"""
    q = query.strip()
    if q.isdigit() and len(q) <= 8:
        return "height", int(q)
    if _HEX64.match(q):
        return "hash", q.lower()
    if _ADDRESS.match(q):
        return "address", q
    return None, None


def search(query: str):
    """Resolve a search to ('block', hash) | ('tx', txid) | ('address', addr)."""
    kind, value = classify(query)
    if kind == "height":
        return "block", block_hash_at(value)
    if kind == "address":
        return "address", value
    if kind == "hash":
        # Block hashes start with a long run of zeros; try the likelier kind first.
        order = (("block", block), ("tx", tx)) if value.startswith("00000000") else \
                (("tx", tx), ("block", block))
        for what, fetch in order:
            try:
                fetch(value)
                return what, value
            except NotFound:
                continue
        raise NotFound("No block or transaction with that hash")
    raise NotFound("Enter a block height, block hash, transaction ID or address")


# ------------------------------------------------------------- pool logos --
_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
LOGO_MAX = 256 * 1024       # bytes; the largest that Mempool 3.3 ships is about 21 kB
_logos = {}                 # name -> SVG bytes, or None where this Mempool has no logo of that name


def _fetch_logo(name: str):
    """-> the SVG, or None if this Mempool has no logo of that name.
    Raises ExplorerError when it cannot be asked at all."""
    req = urllib.request.Request(f"{BASE}/resources/mining-pools/{name}.svg", headers={"User-Agent": "bitfedot"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            kind = resp.headers.get("Content-Type") or ""
            data = resp.read(LOGO_MAX + 1)
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            return None
        raise ExplorerError(f"The explorer backend answered with HTTP {e.code}")
    except (OSError, ValueError, http.client.HTTPException):
        raise ExplorerError("The explorer backend is not reachable.")
    # Mempool's web server answers a name it does not know with its start page, not an error.
    if not kind.startswith("image/svg") or len(data) > LOGO_MAX or b"<svg" not in data[:4096]:
        return None
    return data


def pool_logo(pool):
    """Logo of the mining pool that found a block — `pool` is the block's extras.pool —
    as SVG bytes, or None if none can be had right now.

    Like every other lookup here it is answered by this node's own Mempool, which carries
    the logos itself: nothing is fetched from outside, and a pool's name only goes into a
    URL after it has been checked. A pool Mempool has no logo for gets Mempool's generic
    one. Answers are remembered while the app runs; a failure to ask is not."""
    slug = (pool or {}).get("slug")
    names = ([slug] if isinstance(slug, str) and _SLUG.match(slug) else []) + ["default"]
    for name in names:
        if name not in _logos:
            try:
                _logos[name] = _fetch_logo(name)
            except ExplorerError:
                return None
        if _logos[name]:
            return _logos[name]
    return None


# ------------------------------------------------------------- formatting --
def btc(sats) -> str:
    return f"{(sats or 0) / 1e8:,.8f} BTC"


def tx_summary(t: dict) -> dict:
    """Numbers the UI needs for one transaction."""
    vsize = (t.get("weight") or 0) / 4
    out = sum(o.get("value", 0) for o in t.get("vout", []))
    coinbase = bool(t.get("vin")) and t["vin"][0].get("is_coinbase", False)
    fee = t.get("fee") or 0
    return {"vsize": vsize, "out": out, "fee": fee, "coinbase": coinbase,
            "rate": fee / vsize if vsize and not coinbase else 0.0}


def address_delta(t: dict, addr: str) -> int:
    """Net effect of transaction `t` on `addr`, in satoshis."""
    received = sum(o.get("value", 0) for o in t.get("vout", [])
                   if o.get("scriptpubkey_address") == addr)
    spent = sum((i.get("prevout") or {}).get("value", 0) for i in t.get("vin", [])
                if (i.get("prevout") or {}).get("scriptpubkey_address") == addr)
    return received - spent


# ------------------------------------------------------------------- demo --
def demo_overview() -> dict:
    """Sample data for `--demo` (shape identical to the live API)."""
    now, tip = int(time.time()), 975_312
    pools = [{"name": name, "slug": slug} for name, slug in (
        ("Foundry USA", "foundryusa"), ("AntPool", "antpool"), ("ViaBTC", "viabtc"), ("F2Pool", "f2pool"),
        ("OCEAN", "ocean"), ("MARA Pool", "marapool"), ("SpiderPool", "spiderpool"), ("Braiins Pool", "braiinspool"))]
    blocks = [{
        "id": f"00000000000000000001{(tip - i) * 7919:016x}{i:028x}", "height": tip - i,
        "timestamp": now - 410 - i * 590, "tx_count": 3811 - i * 173 % 900, "size": 1_540_000 + i * 9000,
        "weight": 3_993_000, "difficulty": 1.42e14,
        "extras": {"medianFee": 3.1 + (i * 1.7) % 6, "totalFees": 1_840_000 + i * 91_000,
                   "reward": 312_500_000 + 1_840_000 + i * 91_000, "pool": pools[i % len(pools)],
                   "feeRange": [1, 2, 3, 5, 9, 20, 140]},
    } for i in range(12)]
    return {
        "fees": {"fastestFee": 9, "halfHourFee": 6, "hourFee": 4, "economyFee": 2, "minimumFee": 1},
        "mempool": {"count": 48_211, "vsize": 61_400_000, "total_fee": 41_300_000},
        "next": [{"blockVSize": 997_900, "nTx": 2900 + i * 400, "totalFees": 2_100_000 - i * 400_000,
                  "medianFee": 8.2 - i * 1.9, "feeRange": [4 - i, 9 - i, 60]} for i in range(3)],
        "blocks": blocks,
        "difficulty": {"progressPercent": 61.4, "difficultyChange": 2.31, "remainingBlocks": 778,
                       "remainingTime": 778 * 590_000},
    }
