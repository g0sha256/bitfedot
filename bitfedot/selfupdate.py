"""BitFedot updating itself from its GitHub releases — signed releases only.

The app carries every trust anchor (the pinned keys, the image digests), so its
own update channel must be at least as strong as anything it verifies:

  * a release is installed only if its SHA256SUMS is signed by a key in
    `keys/bitfedot/` and the archive matches that checksum;
  * while no release key is shipped, nothing is ever installed — the app only
    reports that a newer version exists;
  * only a *newer* version is accepted (no downgrades), and the archive must
    really contain the version it claims;
  * the new tree is unpacked next to the live one, has to import and pass its
    own test suite, and is then swapped in by rename; the old tree is kept as
    `bitfedot.previous` for `rollback()`.

Only per-user installs made by `install.sh` update themselves. An RPM install
is updated by dnf; a git checkout by `git pull`.
"""
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from . import __version__, net, paths, settings, system, verify

REPO = "G0SHA256/bitfedot"
RELEASE_KEY_DIR = paths.KEYS_DIR / "bitfedot"
DOWNLOAD = "https://github.com/" + REPO + "/releases/download/v{version}/"


def live_dir() -> Path:
    """The folder that holds the running `bitfedot` package."""
    return paths.PKG_DIR.parent


def user_install_dir() -> Path:
    return paths.HOME / ".local" / "lib" / "bitfedot"


def install_kind() -> str:
    """'user' (install.sh, self-updating) | 'system' (RPM) | 'source' (git checkout)."""
    live = live_dir().resolve()
    if live == user_install_dir().resolve():
        return "user"
    return "system" if str(live).startswith("/usr/") else "source"


def release_keys() -> list:
    return sorted(RELEASE_KEY_DIR.glob("*.asc"))


def latest_version(use_tor=False) -> str:
    return net.latest_tag(REPO, use_tor).lstrip("v")


def status(s=None) -> dict:
    """What the Updates page shows about BitFedot itself."""
    s = s or settings.load()
    latest = s.get("available", {}).get("bitfedot", "")
    info = {"current": __version__, "latest": latest, "newer": net.is_newer(latest, __version__),
            "kind": install_kind(), "can_install": False, "note": "",
            "can_rollback": install_kind() == "user" and previous_dir().exists()}
    if info["kind"] == "system":
        info["note"] = "Installed as a system package — it is updated together with Fedora."
    elif info["kind"] == "source":
        info["note"] = f"Running from a source folder ({live_dir()}) — update it with git."
    elif not release_keys():
        info["note"] = ("This build ships no release key, so it cannot verify a download and will "
                        "not install one. Update manually from the project page.")
    else:
        info["can_install"] = True
        info["note"] = "Installed only if signed by the BitFedot release key shipped with this version."
    return info


def previous_dir() -> Path:
    return live_dir().with_name("bitfedot.previous")


def _stage_dir() -> Path:
    return live_dir().with_name("bitfedot.stage")


def _tree_version(tree: Path) -> str:
    """__version__ of the package in `tree`, read without importing it."""
    for line in (tree / "bitfedot" / "__init__.py").read_text().splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip("\"'")
    return ""


def _preflight(tree: Path):
    """The new version must import and pass its own tests before it replaces anything."""
    env = {**os.environ, "PYTHONPATH": str(tree), "PYTHONDONTWRITEBYTECODE": "1",
           "BITFEDOT_ROOT": tempfile.mkdtemp(prefix="bitfedot-preflight-")}
    try:
        checks = [[sys.executable, "-c", "import bitfedot.services, bitfedot.apps, bitfedot.agent"]]
        if (tree / "tests").is_dir():
            checks.append([sys.executable, "-m", "unittest", "discover", "-s", str(tree / "tests")])
        for cmd in checks:
            p = system.run(cmd, timeout=300, env=env)
            if p.returncode != 0:
                raise RuntimeError("The new version failed its self-test and was not installed:\n"
                                   + (p.stderr or p.stdout).strip()[-400:])
    finally:
        shutil.rmtree(env["BITFEDOT_ROOT"], ignore_errors=True)


def install_release(folder: Path, version: str, report=lambda m, f=None: None) -> str:
    """Verify and install the release files in `folder` (already downloaded):
    bitfedot-<version>.tar.gz, SHA256SUMS, SHA256SUMS.asc."""
    if install_kind() != "user":
        raise RuntimeError(status()["note"])
    keys = release_keys()
    if not keys:
        raise verify.VerificationError("No BitFedot release key is shipped with this version; "
                                       "refusing to install an update that cannot be verified.")
    if not net.is_newer(version, __version__):
        raise RuntimeError(f"Version {version} is not newer than the installed {__version__}.")
    archive = folder / f"bitfedot-{version}.tar.gz"
    report("Verifying the release signature…")
    result = verify.signed_checksums(keys, verify.primary_fingerprints(keys), folder / "SHA256SUMS",
                                     folder / "SHA256SUMS.asc", archive)

    report("Unpacking…")
    stage = _stage_dir()
    shutil.rmtree(stage, ignore_errors=True)
    unpack = stage.with_name("bitfedot.unpack")
    shutil.rmtree(unpack, ignore_errors=True)
    unpack.mkdir(parents=True)
    try:
        with tarfile.open(archive) as tar:
            tar.extractall(unpack, filter="data")
        roots = [d for d in unpack.iterdir() if (d / "bitfedot" / "__init__.py").exists()]
        if len(roots) != 1:
            raise RuntimeError("Unexpected layout in the release archive.")
        if _tree_version(roots[0]) != version:
            raise verify.VerificationError("The archive does not contain the version it claims to be.")
        os.rename(roots[0], stage)
    finally:
        shutil.rmtree(unpack, ignore_errors=True)

    report("Testing the new version…")
    try:
        _preflight(stage)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise

    report("Switching over…")
    live, prev = live_dir(), previous_dir()
    shutil.rmtree(prev, ignore_errors=True)
    os.rename(live, prev)
    try:
        os.rename(stage, live)
    except OSError:
        os.rename(prev, live)                      # put the old version back
        raise
    system.systemctl("restart", paths.U_AGENT)     # the agent runs the new code from now on
    result["version"] = version
    return result


def update(report=lambda m, f=None: None) -> dict:
    """Download the latest release and install it. -> {'version', 'signers', 'sha256'}"""
    s = settings.load()
    from .installer import _use_tor               # same Tor policy as every other download
    tor = _use_tor(s)
    version = latest_version(tor)
    if not net.is_newer(version, __version__):
        raise RuntimeError("BitFedot is already up to date.")
    base = DOWNLOAD.format(version=version)
    dl = paths.DOWNLOADS_DIR / f"bitfedot-{version}"
    dl.mkdir(parents=True, exist_ok=True)
    try:
        report(f"Downloading BitFedot {version}…")
        for name in ("SHA256SUMS", "SHA256SUMS.asc"):
            net.download(base + name, dl / name, use_tor=tor)
        archive = f"bitfedot-{version}.tar.gz"
        net.download(base + archive, dl / archive, use_tor=tor,
                     progress=lambda f: report(f"Downloading BitFedot {version}…", f))
        return install_release(dl, version, report)
    finally:
        shutil.rmtree(dl, ignore_errors=True)


def rollback() -> str:
    """Swap the previous version back in. -> its version."""
    live, prev = live_dir(), previous_dir()
    if install_kind() != "user" or not prev.exists():
        raise RuntimeError("There is no previous version to go back to.")
    aside = live.with_name("bitfedot.rolledback")
    shutil.rmtree(aside, ignore_errors=True)
    os.rename(live, aside)
    os.rename(prev, live)
    os.rename(aside, prev)                         # so the step can be undone again
    system.systemctl("restart", paths.U_AGENT)
    return _tree_version(live)


def relaunch():
    """Start the app again shortly after this process has quit."""
    env = {**os.environ, "PYTHONPATH": str(live_dir())}
    subprocess.Popen(["/bin/sh", "-c", f'sleep 1.5; exec "{sys.executable}" -m bitfedot'],
                     env=env, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
