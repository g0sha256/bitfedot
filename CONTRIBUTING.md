# Contributing to BitFedot

Thanks for looking. BitFedot is small on purpose, and the goal is to keep it that way while
making it more trustworthy. Bug reports from real installs are as valuable as code.

## Get going in a minute

```sh
git clone https://github.com/G0SHA256/bitfedot && cd bitfedot
python3 -m bitfedot --demo synced          # the whole UI with sample data
python3 -m unittest discover tests         # offline, under a second
```

You need Fedora with `python3-gobject gtk4 libadwaita gnupg2 curl` — nothing from PyPI.

Useful switches while developing:

| | |
|---|---|
| `--demo syncing` / `--demo synced` | sample data; no node, no changes |
| `--theme light` / `dark` | force a theme for one run |
| `BITFEDOT_ROOT=/some/dir` | relocate *all* state into one directory and never call systemd — safe for experiments and what the tests use |
| `BITFEDOT_EXPLORER_API=https://mempool.space` | work on the explorer without a synced node |

New here (human or coding assistant)? [`AGENTS.md`](AGENTS.md) is the map of the code and its
invariants; [`docs/EXTENDING.md`](docs/EXTENDING.md) has recipes for the common changes.

## House rules

1. **No new runtime dependencies.** Python standard library + PyGObject. Tools already on
   Fedora (`curl`, `gpg`, `podman`, `systemctl`, `firewall-cmd`, `nft`) are called as
   subprocesses with argument lists, never through a shell string — except the root batches
   in `hardening.as_root()`, where every interpolated value must be validated first.
2. **Verify, then run.** Nothing downloaded is executed or installed before `verify.py`
   accepts it. Changes under `bitfedot/keys/` need a provenance note in `keys/README.md` and
   get extra review.
3. **Root is opt-in.** Nothing runs as root unless the user flipped a switch for exactly that.
   Prefer a solution that works in the user session.
4. **One way to change the system.** Change settings, call `services.apply()`. Do not start,
   stop or write units from UI code.
5. **UI modules contain no logic.** A page reads the snapshot in `update()` and calls a function
   in a backend module from a worker thread (`run_async`). If you need a decision, put it in
   the backend where it can be unit-tested.
6. **Explain choices to the user.** Every option that affects privacy or security says, in the
   UI, what it does and what it costs.
7. **Be honest in docs.** If something is untested or weaker than it looks, the README says so.

## Tests

Tests are offline and must stay that way: no network, no systemd, no root. Anything that renders
a config, orders operations, parses tool output or validates input should have one. Run them
with `python3 -m unittest discover tests`; CI runs the same on Fedora.

If your change affects generated configs, also try them against the real program when you can
(`bitcoind -conf=… -datadir=/tmp/x` for a few seconds, `nft -c`, `systemd-analyze --user verify`,
`/usr/libexec/podman/quadlet --user --dryrun`).

## Good first issues

- I2P (`i2pd`) and CJDNS network modes
- More verified apps: one entry in `bitfedot/catalog.py` each (see `docs/EXTENDING.md`)
- Build Mempool from the signed git tag (verifiable supply chain)
- Tray icon testing on KDE Plasma and other StatusNotifier hosts
- Translations (strings are plain literals today; help set up gettext)
- polkit policy + `/usr/libexec` helper for the RPM build
- Screenshots and UI polish at narrow widths
- aarch64 testing

## Pull requests

Keep them focused, describe what you tested and on which Fedora release, and include a
screenshot for UI changes (`python3 -m bitfedot --demo synced` is fine). Commit messages:
imperative mood, what and why.

By contributing you dedicate your contribution to the public domain under
[The Unlicense](LICENSE), like the rest of the project.
