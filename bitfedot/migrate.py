"""Adopt an installation made under the project's pre-release name, "Nodestead".

Nothing is copied or re-downloaded: the old services are stopped cleanly, the
configuration and data directories are renamed (instant on the same
filesystem, so sync progress, indexes and onion keys are all kept), the old
units are removed, and the node is started again under the new names.

Runs only when the user confirms it in the app.

It can be cut short at any point — a folder that cannot be moved, the app closed,
the power gone — and simply be run again; `pending()` stays true until it is done:

  * Both destinations are checked before anything is stopped or moved.
  * Nothing is moved unless the old services are really down.
  * The data moves first and the configuration last. The old configuration is what
    says "there is an install to adopt", so until that last rename the install is
    still found, wherever the data is by then; the rename is the point of no return.
  * Before it, the settings that go across are completed (new data location, and
    `adopting`): a half-moved install is never mistaken for a working one, and what
    is left to do after it — units, start — is done when adopt() runs again.
"""
import errno
import json
import os
import shutil
from pathlib import Path

from . import paths, services, settings, system

OLD = paths.LEGACY_NAME
# Same shutdown order as services.STOP_ORDER, under the old unit names.
OLD_UNITS = [(f"{OLD}-agent.service", 60, "background agent"),
             (f"{OLD}-mempool-pod.service", 240, "Mempool"),
             (f"{OLD}-fulcrum.service", 700, "Fulcrum"),
             (f"{OLD}-bitcoind.service", 1900, "Bitcoin Core"),
             (f"{OLD}-tor.service", 90, "Tor")]
# Files BitFedot itself may have created before the user decided to migrate.
_SCRATCH = {".lock", ".apply.lock", ".activity", "settings.json", "settings.tmp"}
# …and, in its data folder, what is left of downloads: they are fetched again when needed.
_SCRATCH_DIRS = {paths.DOWNLOADS_DIR.name}


def legacy_settings():
    """Settings of an old install that has not been adopted yet, else None."""
    try:
        old = json.loads((paths.LEGACY_CONFIG_DIR / "settings.json").read_text())
    except (OSError, ValueError):
        return None
    return old if isinstance(old, dict) and old.get("installed") else None


def pending() -> bool:
    """Is there an old install to adopt, or an adoption to finish?"""
    try:
        s = settings.load()
    except RuntimeError:
        return False
    return bool(s["adopting"]) or (legacy_settings() is not None and not s["installed"])


def _in_the_way(src: Path, dst: Path) -> str:
    """Why `src` cannot be renamed to `dst` — '' if it can, or if `src` is not there
    any more because an earlier attempt already moved it."""
    if not os.path.lexists(src) or not os.path.lexists(dst):
        return ""
    if dst.is_symlink() or not dst.is_dir():
        return f"{dst} is in the way and is not a folder BitFedot made. Move it away, then try again."
    real = sorted(p for p in dst.rglob("*") if p.is_file() and p.name not in _SCRATCH
                  and p.relative_to(dst).parts[0] not in _SCRATCH_DIRS)
    if real:
        return (f"{dst} already contains data (for example {real[0].relative_to(dst)}); refusing to "
                "overwrite it. Move that folder away, then try again.")
    return ""


def _takeover(src: Path, dst: Path):
    """Rename directory `src` to `dst`, replacing a `dst` that holds nothing of value.
    Does nothing if `src` is gone: an earlier attempt moved it. Never copies — if the
    rename is not possible, nothing has changed and the error says why."""
    if not os.path.lexists(src):
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    for last in (False, False, True):
        why = _in_the_way(src, dst)
        if why:
            raise RuntimeError(why)
        try:
            if os.path.lexists(dst):
                shutil.rmtree(dst)
            os.rename(src, dst)
            break
        except OSError as e:
            # A lock file of this very app may have reappeared between the two calls.
            if last or e.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                raise RuntimeError(f"{src} could not be renamed to {dst} ({e.strerror or e}). "
                                   "It is unchanged.") from None
    services.sync_dir(dst.parent)       # this rename must not be lost to a power cut after the next one


def _stop_old_services(report):
    """Stop the old install's services in a safe order and make sure they are down:
    their folders must not be renamed under a running Bitcoin Core or Fulcrum."""
    report("Closing the old app…")
    if not system.DRY_RUN:
        system.run(["gapplication", "action", paths.LEGACY_APP_ID, "quit"], timeout=10)
    for unit, timeout, label in OLD_UNITS:
        report(f"Stopping {label} safely…" + (" (flushing to disk, this can take a few minutes)"
                                              if "bitcoind" in unit else ""))
        system.systemctl("stop", unit, timeout=timeout)      # a unit that never existed is fine
    states = system.unit_states([unit for unit, _timeout, _label in OLD_UNITS])
    up = [label for unit, _timeout, label in OLD_UNITS if states[unit] not in ("inactive", "failed")]
    if up:
        raise RuntimeError(f"{' and '.join(up)} of the old installation did not stop. Nothing was moved.")
    for unit, _timeout, _label in OLD_UNITS:
        system.systemctl("disable", unit)
        (paths.UNIT_DIR / unit).unlink(missing_ok=True)
    for f in paths.QUADLET_DIR.glob(f"{OLD}-mempool*"):
        f.unlink()
    (paths.AUTOSTART_DIR / f"{paths.LEGACY_APP_ID}.desktop").unlink(missing_ok=True)
    system.systemctl("daemon-reload")


def _complete_settings(old: dict, theme: str):
    """Write into the old configuration, while it still has its old name, what makes it
    BitFedot's: where the data is now, and that the adoption is under way. Once only: an
    earlier attempt that got this far has already taken the theme from settings of
    BitFedot's own that are gone by now."""
    if old.get("adopting"):
        return
    # Paths inside the old default location moved with it; custom locations stay put.
    data_dir = old.get("data_dir") or str(paths.LEGACY_DATA_DIR / paths.DEFAULT_CHAIN_DIR.name)
    prefix = str(paths.LEGACY_DATA_DIR)
    if data_dir == prefix or data_dir.startswith(prefix + os.sep):
        data_dir = str(paths.DATA_DIR) + data_dir[len(prefix):]
    services.write_file(paths.LEGACY_CONFIG_DIR / "settings.json", json.dumps(
        {**old, "data_dir": data_dir, "theme": theme, "adopting": True}, indent=2, sort_keys=True))


def _remove_old_app():
    home = paths.HOME
    for leftover in (home / ".local/lib" / OLD, home / ".local/bin" / OLD,
                     paths.DESKTOP_DIR / f"{paths.LEGACY_APP_ID}.desktop",
                     home / ".local/share/icons/hicolor/scalable/apps" / f"{paths.LEGACY_APP_ID}.svg",
                     home / ".local/share/icons/hicolor/symbolic/apps" / f"{paths.LEGACY_APP_ID}-symbolic.svg"):
        if leftover.is_dir():
            shutil.rmtree(leftover, ignore_errors=True)
        else:
            leftover.unlink(missing_ok=True)


def adopt(report=lambda msg: None):
    """Move the old install over and start it under the new name. Blocking.
    Run again after a failure or an interruption, it carries on from where things stand."""
    current = settings.load()
    if not current["adopting"]:
        old = legacy_settings()
        if old is None:
            raise RuntimeError("No earlier installation found.")
        if current["installed"]:
            raise RuntimeError("BitFedot is already installed; nothing to adopt.")
        moves = ((paths.LEGACY_DATA_DIR, paths.DATA_DIR), (paths.LEGACY_CONFIG_DIR, paths.CONFIG_DIR))
        for src, dst in moves:                      # before anything is stopped or moved
            why = _in_the_way(src, dst)
            if why:
                raise RuntimeError(why)
        _stop_old_services(report)

        report("Moving configuration and data…")
        _takeover(*moves[0])
        _complete_settings(old, current["theme"])
        _takeover(*moves[1])                        # from here on the node is BitFedot's

    settings.ensure_secrets()
    report("Removing the old app…")
    _remove_old_app()
    services.apply(report=report)
    return settings.update(adopting=False)
