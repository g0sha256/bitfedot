# Working on BitFedot — guide for contributors and coding assistants

Read this first; it is written to get a human or an LLM productive in a few minutes.
`CLAUDE.md` points here. User-facing documentation is `README.md`; design background is
`docs/ARCHITECTURE.md`; step-by-step recipes are `docs/EXTENDING.md`.

## What this is

A GTK 4 / libadwaita desktop app for Fedora that installs and supervises a Bitcoin node stack
(Bitcoin Core, Fulcrum, Mempool, Tor) plus optional privacy apps, as **systemd user services**.
Python standard library + PyGObject only. No build step: `python3 -m bitfedot`.

## Commands

```sh
python3 -m unittest discover tests            # all tests; offline; about a second. Run after every change.
python3 -m bitfedot --demo synced             # full UI with sample data; changes nothing
python3 -m bitfedot --demo syncing --theme light --page apps
BITFEDOT_ROOT=/tmp/bf python3 -m bitfedot     # real code paths, all state under /tmp/bf, systemd never called
ruff check bitfedot tests                     # lint (errors only); CI runs it
```

> **Safety while developing.** Without `BITFEDOT_ROOT`, code that calls `settings.update()` or
> `services.apply()` acts on the real node of whoever is logged in. Tests set `BITFEDOT_ROOT`
> themselves. When experimenting from a shell or REPL, always export it. Never bind 8332/8333 or
> stop `bitfedot-*` units on a machine with a live node unless asked to.

## Map of the code

Backend (no GTK imports; unit-testable):

| Module | Responsibility | Start here when… |
|---|---|---|
| `paths.py` | every path, port and unit name | you need a location or a port |
| `settings.py` | the settings file: defaults, locked read-modify-write | adding a setting |
| `services.py` | render configs/units from settings; ordered `apply()` | anything about what runs and how |
| `installer.py` | verified install of the 4 core components; update checks | core component versions |
| `verify.py` | GnuPG + SHA-256 checks against pinned keys | any verification question |
| `selfupdate.py` | BitFedot updating itself from signed releases; rollback | the app's own update path |
| `pins.py` | **data only**: container image digests we vouch for | a new Mempool release |
| `catalog.py` | **data only**: the optional apps | adding/changing an optional app |
| `apps.py` | install/update/remove/launch for each catalog `kind` | a new delivery method |
| `hardening.py` | security check-up, firewall, kill switch, Fedora updates, `as_root()` | anything needing root |
| `eta.py` | sync time estimate (pure functions + sample file) | tuning the estimate |
| `hardware_keys.py` | YubiKey setup: generates staged shell scripts, tracks gates. **Experimental**; can lock users out — change with great care | anything about LUKS/PAM/YubiKey |
| `keyring_unlock.py`, `ykpins.py` | stand-alone helpers the hardware-key scripts run in a terminal (keyring re-keying; YubiKey PINs). Must not import from the package, and must not be named like a library (`keyring`!) | those two steps |
| `explorer.py` | Mempool REST client | explorer data |
| `node.py` | `snapshot()` (status for the UI) and user actions | a new status field or action |
| `agent.py` | headless loop: post-sync hand-over, VPN watch, daily checks | background behaviour |
| `migrate.py` | adopt an install made under the pre-release name | (rarely) |
| `about.py` | author, licence, thanks, whitepaper | credits |
| `rpc.py`, `net.py`, `system.py` | small clients/wrappers: Bitcoin RPC, Tor control, curl, systemd, hardware | |

Frontend (`ui/`, one module per sidebar page; **no logic**):
`window.py` (navigation, banner) · `overview.py` · `explorer.py` · `apps.py` · `connectivity.py` ·
`security.py` · `updates.py` · `pages.py` (Logs, Settings) · `about.py` · `wizard.py` (first run,
migration) · `widgets.py` (helpers: `run_async`, `toast`, formatting). `app.py` is the
`Adw.Application` (polling, tray, quit flow, theme); `tray.py` is the D-Bus tray icon.

## Invariants — do not break these

1. **Verify, then run.** Nothing downloaded is unpacked, installed or executed before
   `verify.py` accepts it against a key pinned in this repository. This includes BitFedot's own
   updates: never add an unsigned or "TLS is enough" path to `selfupdate.py`.
2. **One way to change the system:** update settings, then `services.apply()`.
   `apply()` is idempotent, ordered (stop consumers first, wait, start in reverse) and locked.
   It reads the stored settings itself, under its lock — never hand it a copy. It replaces a
   file only after stopping what reads it, and raises when systemd refuses something; an
   apply that did not complete stays `services.unfinished()` and is finished by the agent or
   at the next launch. Never start/stop/write units elsewhere (a plain restart is
   `services.restart_unit()`).
3. **Root only on request,** only through `hardening.as_root()`, with every interpolated value
   validated (see `_IFACE`, `_ZONE`, `parse_endpoints`). No new privileged code paths without a
   test for hostile input.
4. **Loopback only.** Services bind to 127.0.0.1. The sole exception is P2P port 8333 when the
   user enables inbound clearnet peers.
5. **No private keys, no user data.** The node runs with `disablewallet=1`. BitFedot never
   deletes or rewrites data that optional apps create (it may *extend* their config, with a backup).
6. **No new runtime dependencies.** Standard library + PyGObject; system tools via argument lists.
7. **UI modules hold no logic.** They render `snapshot` in `update(snap)` and call backend
   functions through `run_async`. Decisions live in backend modules with tests.
8. **Say what it costs.** Every privacy/security option explains itself in the UI; docs state
   plainly what is untested or weaker than it looks.

## Conventions

- Module docstring first: what the module is for and its rules. Comments explain *why*.
- Backend functions that can take long accept `report(message, fraction=None)`.
- UI pages are classes with `title`, `icon`, `update(snap)` and optional `refresh()`
  (called when the page is selected). Demo mode: guard actions with `if self.demo`.
- Settings keys are flat, documented inline in `settings.DEFAULTS`. Dict-valued keys merge
  (the two that are replaced whole instead are listed in `settings.REPLACED`).
- Tests live in `tests/test_core.py`, grouped by area; they must stay offline and rootless.
- Generated files carry `services.HEADER`; never hand-edit them in a running install.

## How to…

| Task | Where |
|---|---|
| Add an optional app | one `App(...)` entry in `catalog.py` + key in `keys/` → `docs/EXTENDING.md` §1 |
| Add a setting / switch | `settings.DEFAULTS` → render it in `services.py` → switch in a `ui/` page → §2 |
| Add a hardening option | `hardening.py` (+ `as_root` batch) → `ui/security.py` → §3 |
| Add a page | new `ui/<name>.py` class → list it in `ui/window.py` → §4 |
| Add a service | unit + config renderer in `services.py`, add to `STOP_ORDER`/`DEPENDENTS` → §5 |
| Change the sync estimate | constants at the top of `eta.py` → §6 |
| Cut a release / pin a new Mempool version | `docs/RELEASING.md`, `tools/release.sh`, `pins.py` |
| Check a change to the keyring stage for real | `python3 -P tools/keyring-rehearsal.py` — the real keyring service and `systemd-creds`, on throw-away keyrings; never the login keyring. The unit tests only know a fake service |
| Check that installed copies can update to a change | `python3 -P tools/update-rehearsal.py --unsigned` — every earlier version (the `v*` tags) installs the tree as it is now with its own updater code, as the app and as its background agent, in a scratch folder. CI runs it; `tools/release.sh` runs it on the signed files too |
| Check a change to `services.apply()` for real | `python3 -P tools/apply-rehearsal.py` — the real `systemctl --user`, with throw-away units that only sleep in place of the services; never a `bitfedot-*` unit, so it is safe beside a running node. The unit tests only know a fake systemd |

## Known gaps (good places to help)

See "What has been tested" in the README. In short: firewall zone, kill switch and dnf-based
installs have never run against a live system from development (no root there); post-sync
hand-over and Fulcrum's initial index have limited mileage; tray rendering is untested on KDE.
