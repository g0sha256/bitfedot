# Extending BitFedot — recipes

Short, concrete, and kept in sync with the code. Run `python3 -m unittest discover tests` and
`python3 -m bitfedot --demo synced` after each change.

## 1. Add an optional app

Everything is driven by one entry in [`bitfedot/catalog.py`](../bitfedot/catalog.py). The Apps
page, the Updates page, install, update, removal and the verification text all follow from it.

1. **Find a signature you can pin.** No verifiable signature → the app does not go in.
2. **Ship the key**: `bitfedot/keys/<key_dir>/<name>.asc` (ASCII-armored), and add a row with
   fingerprint and where you got it to [`bitfedot/keys/README.md`](../bitfedot/keys/README.md).
3. **Add the entry.** Pick the `kind` that matches how upstream ships:

```python
# archive — a release tarball with a detached signature (per user, no root)
App(id="example", title="Example", category="wallet", summary="One line on what it is.",
    homepage="https://example.org", license="MIT",
    kind="archive", key_dir="example",
    fingerprints=("0123456789ABCDEF0123456789ABCDEF01234567",), signer="Jane Maintainer",
    spec={"latest": ("github", "owner/repo"),              # or ("json", url, "key")
          "base": "https://github.com/owner/repo/releases/download/v{version}/",
          "artifact": "example-{version}-{arch}.tar.gz",
          "checksums": ("SHA256SUMS", "SHA256SUMS.asc"),   # or "signature": "<artifact>.asc"
          "marker": "bin/example",                         # locates the root folder in the archive
          "exec": "bin/example", "icon": "share/example.png"})

# dnf — the vendor's RPM repository (system-wide, asks for the password)
App(..., kind="dnf", key_dir="vendor", fingerprints=(...), signer="Vendor",
    spec={"repo_id": "vendor", "name": "Vendor", "baseurl": "https://rpm.vendor.example/$basearch",
          "packages": ("vendor-app",)})                    # "repo_gpgcheck": True if upstream signs metadata

# apt — a signed Debian repository, unpacked per user (no root)
App(..., kind="apt", key_dir="vendor", fingerprints=(...), signer="Vendor",
    arch={"x86_64": "amd64", "aarch64": "arm64"},
    spec={"repo": "https://deb.vendor.example", "dist": "stable", "component": "main",
          "package": "vendor-app", "exec": "opt/Vendor/vendor-app", "icon": "usr/share/…/app.png"})

# flatpak — from Flathub with its pinned repository key (per user, no root)
App(..., kind="flatpak", key_dir="flathub",
    fingerprints=("6E5C05D979C76DAF93C081354184DD4D907A7CAE",), signer="Flathub (…)",
    spec={"ref": "org.example.App"})
```

4. **Optional — wire it to the node.** Write a function in `apps.py`, register it in
   `apps.CONFIGURE`, reference it as `spec["configure"]`, and describe it in `setup=`. Extend the
   app's own config; never replace it (see `configure_sparrow`).
5. **Thank them**: add the project to `about.THANKS` and `THANKS.md`.
6. `tests/test_core.py::Apps` checks every entry automatically (key shipped, fingerprints match
   the key file, fields present). Then try a real install in a sandbox:

```sh
BITFEDOT_ROOT=/tmp/bf python3 -c "from bitfedot import apps; print(apps.install('example', print))"
```

A new *delivery method* means a new `kind`: add `_<kind>_latest/_install` to `apps.py`, register
them in `_LATEST`/`_INSTALL`, add texts to `KIND_TEXT`/`VERIFY_TEXT` in `ui/apps.py`.

## 2. Add a setting or switch

1. Default + one-line comment in `settings.DEFAULTS`.
2. If it affects a service, render it in `services.py` (`bitcoin_conf`, `torrc`, a unit…).
   `apply()` will notice the changed file and restart exactly what is needed, safely.
3. Add an `Adw.SwitchRow` to the right page with a subtitle that says what it does *and what it
   costs*; on change call `node.apply_settings(key=value)` via `run_async`.
4. Test the rendering in `tests/test_core.py`.

## 3. Add a hardening option that needs root

1. In `hardening.py`: a function that returns the shell lines, a function that runs them through
   `as_root()`, and a cheap unprivileged status check. Validate every interpolated value with a
   strict pattern *before* building the script.
2. Add a row to `checkup()` if it is something worth showing as ✓ / ⚠.
3. UI in `ui/security.py`: confirmation dialog for anything that can cut connectivity, and
   `self._failed` on error so the switch snaps back.
4. Tests: the generated script for normal input, and rejection of hostile input.

## 4. Add a page

```python
# bitfedot/ui/mypage.py
class MyPage(Gtk.Box):
    title = "My page"                 # sidebar label
    icon = "emblem-default-symbolic"

    def __init__(self, demo=False): ...
    def update(self, snap): ...       # called every few seconds with node.snapshot()
    def refresh(self): ...            # optional: called when the page is selected
```

Add it to `self.pages` in `ui/window.py`. Need new data? Add it to `node.snapshot()` (and to
`node.demo_snapshot()` so `--demo` keeps working).

## 5. Add a managed service

1. `paths.py`: unit name, ports. 2. `services.py`: config + unit renderer (use `sandbox()`),
   add both files to `write_configs()`, the unit to `desired_units()`, `LABELS`, `STOP_ORDER`
   (consumers first), `STOP_TIMEOUT`, and `DEPENDENTS` if something must restart with it.
3. Status in `node.snapshot()`, a card in `ui/overview.py`, a log entry in `ui/pages.py`.
4. Extend `tests/test_core.py::SafeOrdering`.

## 6. Tune the sync time estimate

Everything is at the top of [`bitfedot/eta.py`](../bitfedot/eta.py): the cache-size curve
(`UTXO_CACHE_GIB`), the cost of working from disk (`DISK_BOUND_COST`), the cost and share of
signature verification (`SIGNATURE_COST`, `SIGNATURE_TAIL`). If you have a full sync log, compare
`journalctl --user -u bitfedot-bitcoind | grep UpdateTip` (progress vs. time) with the model and
send the numbers — real traces from different hardware are the best contribution here.
