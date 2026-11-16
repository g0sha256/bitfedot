"""Adopt an installation made under the project's pre-release name, "Nodestead".

Nothing is copied or re-downloaded: the old services are stopped cleanly, the
configuration and data directories are renamed (instant on the same
filesystem, so sync progress, indexes and onion keys are all kept), the old
units are removed, and the node is started again under the new names.

Runs only when the user confirms it in the app.
"""
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


def legacy_settings():
    """Settings of an old install that has not been adopted yet, else None."""
    try:
        old = json.loads((paths.LEGACY_CONFIG_DIR / "settings.json").read_text())
    except (OSError, ValueError):
        return None
    return old if isinstance(old, dict) and old.get("installed") else None


def pending() -> bool:
    try:
        return legacy_settings() is not None and not settings.load()["installed"]
    except RuntimeError:
        return False


def _takeover(src: Path, dst: Path):
    """Rename directory `src` to `dst`, replacing an empty-ish `dst`."""
    if not src.exists():
        return
    if dst.exists():
        real = [p for p in dst.rglob("*") if p.is_file() and p.name not in _SCRATCH]
        if real:
            raise RuntimeError(f"{dst} already contains data; refusing to overwrite it.")
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(src, dst)
    except OSError:                    # different filesystems: fall back to a real move
        shutil.move(str(src), str(dst))


def adopt(report=lambda msg: None):
    """Move the old install over and start it under the new name. Blocking."""
    old = legacy_settings()
    if old is None:
        raise RuntimeError("No earlier installation found.")
    current = settings.load()
    if current["installed"]:
        raise RuntimeError("BitFedot is already installed; nothing to adopt.")

    report("Closing the old app…")
    if not system.DRY_RUN:
        system.run(["gapplication", "action", paths.LEGACY_APP_ID, "quit"], timeout=10)
    for unit, timeout, label in OLD_UNITS:
        report(f"Stopping {label} safely…" + (" (flushing to disk, this can take a few minutes)"
                                              if "bitcoind" in unit else ""))
        system.systemctl("stop", unit, timeout=timeout)
        system.systemctl("disable", unit)
        (paths.UNIT_DIR / unit).unlink(missing_ok=True)
    for f in paths.QUADLET_DIR.glob(f"{OLD}-mempool*"):
        f.unlink()
    (paths.AUTOSTART_DIR / f"{paths.LEGACY_APP_ID}.desktop").unlink(missing_ok=True)
    system.systemctl("daemon-reload")

    report("Moving configuration and data…")
    _takeover(paths.LEGACY_CONFIG_DIR, paths.CONFIG_DIR)
    _takeover(paths.LEGACY_DATA_DIR, paths.DATA_DIR)
    # Paths inside the old default location moved with it; custom locations stay put.
    data_dir = old.get("data_dir", "")
    prefix = str(paths.LEGACY_DATA_DIR)
    if data_dir == prefix or data_dir.startswith(prefix + os.sep):
        data_dir = str(paths.DATA_DIR) + data_dir[len(prefix):]
    s = settings.update(data_dir=data_dir, theme=current["theme"])
    settings.ensure_secrets()

    report("Removing the old app…")
    home = paths.HOME
    for leftover in (home / ".local/lib" / OLD, home / ".local/bin" / OLD,
                     paths.DESKTOP_DIR / f"{paths.LEGACY_APP_ID}.desktop",
                     home / ".local/share/icons/hicolor/scalable/apps" / f"{paths.LEGACY_APP_ID}.svg",
                     home / ".local/share/icons/hicolor/symbolic/apps" / f"{paths.LEGACY_APP_ID}-symbolic.svg"):
        if leftover.is_dir():
            shutil.rmtree(leftover, ignore_errors=True)
        else:
            leftover.unlink(missing_ok=True)

    services.apply(settings.load(), report=report)
    return s
