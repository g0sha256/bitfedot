"""How long will the initial sync still take?

A naive "blocks left ÷ blocks per second" is badly wrong for Bitcoin: early
blocks are almost empty and fly by, recent blocks carry thousands of
transactions each. So the estimate here is made in *transactions*, which is
what the node actually has to process:

  1. Progress `p` is Bitcoin Core's `verificationprogress` — the fraction of all
     transactions verified so far, not the fraction of blocks.
  2. The current speed is measured from recent progress samples (the agent
     records one a minute, so the estimate survives closing the window).
  3. Transactions do not all cost the same. Two things make later ones slower,
     and both are modelled as a relative cost per transaction:
       * once the set of unspent coins no longer fits in the database cache
         (`dbcache`), the node has to read and write the disk constantly;
       * for the newest blocks (after the release's "assumevalid" checkpoint)
         every signature is verified, which is far more work.

The result is an estimate, and it corrects itself as the measured speed changes.
All tunable numbers are in this file. Pure functions — see tests/test_core.py.
"""
import json
import time

from . import paths

# Approximate memory needed to hold the whole unspent-coin set in Bitcoin Core's
# cache, by sync progress: (fraction of transactions verified, GiB).
UTXO_CACHE_GIB = [(0.00, 0.0), (0.07, 4.5), (0.20, 7.8), (0.33, 8.5), (0.47, 10.0),
                  (0.53, 11.0), (0.63, 19.5), (0.76, 24.0), (1.00, 23.0)]
DISK_BOUND_COST = {False: 2.0, True: 6.0}   # cost factor once the cache overflows: SSD, HDD
SIGNATURE_COST = 5.0                         # cost factor while signatures are verified
SIGNATURE_TAIL = 0.02                        # share of all transactions after "assumevalid"

SAMPLE_FILE = paths.CONFIG_DIR / "sync-samples.json"
SAMPLE_EVERY = 60        # seconds between recorded samples
SAMPLE_KEEP = 180        # … i.e. three hours of history
RATE_WINDOW = 1800       # measure speed over at most the last 30 minutes
MAX_GAP = 300            # a longer pause between samples means the node was restarted
MIN_SPAN = 120           # need at least this much history for a meaningful speed


def utxo_cache_gib(p: float) -> float:
    """Interpolated cache size needed at progress `p`."""
    pts = UTXO_CACHE_GIB
    for (p0, g0), (p1, g1) in zip(pts, pts[1:]):
        if p <= p1:
            return g0 + (g1 - g0) * (p - p0) / (p1 - p0)
    return pts[-1][1]


def cache_overflow_progress(dbcache_mb: float) -> float:
    """Progress at which the unspent-coin set stops fitting in `dbcache`; 1.0 if never."""
    for step in range(0, 1001):
        if utxo_cache_gib(step / 1000) * 1024 > dbcache_mb:
            return step / 1000
    return 1.0


def cost(p: float, overflow_at: float, rotational=False, signature_tail=SIGNATURE_TAIL) -> float:
    """Relative cost of verifying one transaction at progress `p` (1.0 = cheapest)."""
    c = DISK_BOUND_COST[bool(rotational)] if p >= overflow_at else 1.0
    if p >= 1.0 - signature_tail:
        c *= SIGNATURE_COST
    return c


def measured_rate(samples, now=None):
    """Progress per second from recent `samples` [(unix time, progress), …];
    None until there is enough continuous history."""
    now = now or time.time()
    recent = [s for s in samples if now - s[0] <= RATE_WINDOW]
    run = recent[-1:]
    for older, newer in zip(reversed(recent[:-1]), reversed(recent)):
        if newer[0] - older[0] > MAX_GAP or newer[1] < older[1]:
            break                                  # restart or re-index: older samples don't count
        run.insert(0, older)
    if len(run) < 2:
        return None
    dt, dp = run[-1][0] - run[0][0], run[-1][1] - run[0][1]
    return dp / dt if dt >= MIN_SPAN and dp > 0 else None


def remaining_seconds(p: float, rate: float, dbcache_mb: float, rotational=False,
                      signature_tail=SIGNATURE_TAIL, steps=400):
    """Seconds until fully synced, given current progress `p` and measured `rate`
    (progress per second at the current cost level)."""
    if rate is None or rate <= 0 or p >= 1.0:
        return None
    overflow_at = cache_overflow_progress(dbcache_mb)
    now_cost = cost(p, overflow_at, rotational, signature_tail)
    dp = (1.0 - p) / steps
    work = sum(cost(p + (i + 0.5) * dp, overflow_at, rotational, signature_tail) for i in range(steps)) * dp
    # speed at cost c is rate × now_cost / c, so time = ∫ c dp / (rate × now_cost)
    return work / (rate * now_cost)


# ---------------------------------------------------------------- samples --
def load_samples() -> list:
    try:
        data = json.loads(SAMPLE_FILE.read_text())
        return [(float(t), float(p)) for t, p in data]
    except (OSError, ValueError, TypeError):
        return []


def record_sample(progress: float, now=None) -> list:
    """Append a sample if the last one is old enough; -> current samples."""
    now = now or time.time()
    samples = load_samples()
    if samples and now - samples[-1][0] < SAMPLE_EVERY:
        return samples
    samples = (samples + [(now, progress)])[-SAMPLE_KEEP:]
    try:
        SAMPLE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SAMPLE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(samples))
        tmp.replace(SAMPLE_FILE)
    except OSError:
        pass
    return samples


def estimate(progress: float, dbcache_mb: float, rotational=False, extra_samples=()):
    """Remaining seconds from recorded history (plus the caller's own fresh
    samples), or None while the speed is still being measured."""
    samples = sorted(set(load_samples()) | set(extra_samples))
    return remaining_seconds(progress, measured_rate(samples), dbcache_mb, rotational)
