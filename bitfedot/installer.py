"""Download → verify → install for each component, the first-run install
pipeline, and updates.

All functions block; the GUI runs them in a worker thread and passes
`report(message, fraction | None)` to show progress. Nothing is ever executed
before `verify.py` has accepted it."""
import os
import shutil
import tarfile
import time
from pathlib import Path

from . import net, paths, pins, services, settings, system, verify
from .catalog import BY_ID, CATALOG
from .paths import U_BITCOIND, U_FULCRUM, U_MEMPOOL, U_TOR

COMPONENTS = ("bitcoin", "fulcrum", "mempool", "tor")      # the node itself: always installed
TITLES = {"bitcoin": "Bitcoin Core", "fulcrum": "Fulcrum", "mempool": "Mempool", "tor": "Tor",
          "bitfedot": "BitFedot",
          **{app.id: app.title for app in CATALOG}}


def components(s) -> tuple:
    """Everything BitFedot keeps up to date on this machine: the node plus the
    installed optional apps (except those that update themselves)."""
    return COMPONENTS + tuple(app.id for app in CATALOG
                              if s["versions"].get(app.id) and not app.self_updates)
TRAY_EXTENSION_PKG = "gnome-shell-extension-appindicator"
TRAY_EXTENSION_ID = "appindicatorsupport@rgcjonas.gmail.com"

_BTC_PLATFORM = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}
_FULCRUM_PLATFORM = {"x86_64": "x86_64-linux", "aarch64": "arm64-linux"}


def _noop(msg, frac=None):
    pass


def _platform(table):
    try:
        return table[system.arch()]
    except KeyError:
        raise RuntimeError(f"Unsupported CPU architecture: {system.arch()}")


def _use_tor(s) -> bool:
    """Downloads go through Tor whenever Tor is up and the user wants that."""
    return bool(s.get("updates_via_tor")) and services.tor_wanted(s) and net.tor_usable()


def extract_archive(tarball: Path, dest: Path, marker: str):
    """Extract `tarball` so that `dest/marker` exists, then atomically point
    apps/<name>/current at it."""
    tmp = dest.with_name(dest.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    with tarfile.open(tarball) as tf:
        tf.extractall(tmp, filter="data")      # refuses paths escaping tmp, device nodes, etc.
    hits = [p for p in tmp.rglob(Path(marker).name) if str(p).endswith(marker) and p.is_file()]
    if not hits:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"{marker} not found in {tarball.name}")
    root = hits[0]
    for _ in Path(marker).parts:
        root = root.parent
    shutil.rmtree(dest, ignore_errors=True)
    os.replace(root, dest)
    shutil.rmtree(tmp, ignore_errors=True)
    link = dest.parent / "current"
    tmp_link = dest.parent / ".current.tmp"
    tmp_link.unlink(missing_ok=True)
    os.symlink(dest.name, tmp_link)
    os.replace(tmp_link, link)


def _fetch_verified(name, version, base_url, tarball, sums, sums_asc, verifier, marker,
                    report, use_tor):
    dl = paths.DOWNLOADS_DIR / f"{name}-{version}"
    dl.mkdir(parents=True, exist_ok=True)
    title = TITLES[name]
    report(f"Downloading {title} {version} checksums and signatures…")
    net.download(base_url + sums, dl / sums, use_tor=use_tor)
    net.download(base_url + sums_asc, dl / sums_asc, use_tor=use_tor)
    report(f"Downloading {title} {version}…", 0.0)
    net.download(base_url + tarball, dl / tarball, use_tor=use_tor,
                 progress=lambda f: report(f"Downloading {title} {version}…", f))
    report(f"Verifying {title} signatures…")
    try:
        result = verifier(dl / sums, dl / sums_asc, dl / tarball)
    except verify.VerificationError:
        (dl / tarball).unlink(missing_ok=True)   # never leave an unverified binary around
        raise
    report(f"Installing {title} {version}…")
    extract_archive(dl / tarball, paths.APPS_DIR / name / version, marker)
    shutil.rmtree(dl, ignore_errors=True)
    settings.update(versions={name: version})
    result["version"] = version
    return result


# -------------------------------------------------------------- components --
def latest_version(name: str, use_tor=False) -> str:
    if name == "bitcoin":
        return net.latest_tag("bitcoin/bitcoin", use_tor).lstrip("v")
    if name == "fulcrum":
        return net.latest_tag("cculianu/Fulcrum", use_tor).lstrip("v")
    if name == "mempool":
        upstream = net.latest_tag("mempool/mempool", use_tor).lstrip("v")
        if not settings.load()["pinned_images_only"]:
            return upstream
        # Strict: only offer what BitFedot vouches for. A newer upstream release
        # arrives with the BitFedot update that pins its digests.
        vouched = pins.pinned_mempool_versions()
        return upstream if upstream in vouched else (vouched[-1] if vouched else "")
    if name in BY_ID:
        from . import apps               # apps builds on this module
        return apps.latest_version(name, use_tor)
    if name == "tor":
        # dnf metadata comes from the Fedora mirrors the system already uses
        out = system.run(["dnf", "-q", "repoquery", "--latest-limit=1", "--qf", "%{version}\n", "tor"],
                         timeout=180).stdout.split()
        return out[-1] if out else ""
    raise ValueError(name)


def installed_tor_version() -> str:
    p = system.run(["rpm", "-q", "--qf", "%{VERSION}", "tor"])
    return p.stdout.strip() if p.returncode == 0 else ""


def install_bitcoin(version=None, report=_noop, use_tor=False) -> dict:
    version = version or latest_version("bitcoin", use_tor)
    return _fetch_verified(
        "bitcoin", version, f"https://bitcoincore.org/bin/bitcoin-core-{version}/",
        f"bitcoin-{version}-{_platform(_BTC_PLATFORM)}.tar.gz", "SHA256SUMS", "SHA256SUMS.asc",
        lambda sums, sig, tarball: verify.verify_bitcoin(
            sums, sig, tarball, settings.load()["core_min_signers"]),
        "bin/bitcoind", report, use_tor)


def install_fulcrum(version=None, report=_noop, use_tor=False) -> dict:
    version = version or latest_version("fulcrum", use_tor)
    return _fetch_verified(
        "fulcrum", version, f"https://github.com/cculianu/Fulcrum/releases/download/v{version}/",
        f"Fulcrum-{version}-{_platform(_FULCRUM_PLATFORM)}.tar.gz",
        f"Fulcrum-{version}-shasums.txt", f"Fulcrum-{version}-shasums.txt.asc",
        verify.verify_fulcrum, "Fulcrum", report, use_tor)


def install_mempool(version=None, report=_noop, use_tor=False) -> dict:
    """Mempool ships as container images, which upstream does not sign.

    Images whose digest is listed in pins.py are pulled *by digest*: the content
    is exactly what a signed BitFedot release vouches for. Other versions are
    refused in strict mode; with strict mode off they are pulled by tag over TLS
    and their digest is remembered, so a tag that later changes is caught."""
    s = settings.load()
    version = version or latest_version("mempool", use_tor)
    if not version:
        raise RuntimeError("No Mempool version is available.")
    known = dict(s["digests"])
    digests, notes = {}, []
    for i, (part, image) in enumerate(services.mempool_images(version).items()):
        ref = pins.pinned_ref(image)
        if not ref and s["pinned_images_only"]:
            raise verify.VerificationError(
                f"{image} is not among the images BitFedot vouches for. Update BitFedot, or "
                "switch off “Only run vouched-for container images” under Security.")
        report(f"Pulling {image}…", i / 3)
        system.run(["podman", "pull", "-q", ref or image], timeout=3600, check=True,
                   env=net.proxy_env(use_tor))
        digest = system.run(["podman", "image", "inspect", "--format", "{{.Digest}}", ref or image],
                            check=True).stdout.strip()
        if not ref and known.get(image) not in (None, digest):
            raise verify.VerificationError(
                f"{image} changed on the registry since it was first pulled "
                f"({known[image][:19]}… → {digest[:19]}…). Refusing to use it.")
        digests[image] = digest
        notes.append(f"{part}: {'pinned ' + pins.IMAGE_DIGESTS[image][:19] + '…' if ref else 'by tag, ' + digest[:19] + '…'}")
    settings.update(versions={"mempool": version}, digests=digests)
    return {"version": version, "digests": digests, "signers": notes}


def missing_packages(want_tray=False) -> list:
    need = {"tor": "tor", "podman": "podman", "curl": "curl", "gpg": "gnupg2"}
    pkgs = [pkg for binary, pkg in need.items() if not system.have(binary)]
    if want_tray and system.run(["rpm", "-q", TRAY_EXTENSION_PKG]).returncode != 0:
        pkgs.append(TRAY_EXTENSION_PKG)
    return pkgs


def pkexec_dnf(*args, report=_noop):
    """One authenticated dnf transaction. dnf itself verifies RPM signatures
    against the Fedora keys before installing anything."""
    p = system.run(["pkexec", "dnf", *args], timeout=1800)
    if p.returncode in (126, 127):
        raise RuntimeError("Administrator authentication was cancelled.")
    if p.returncode != 0:
        raise RuntimeError("dnf failed:\n" + (p.stderr or p.stdout).strip()[-800:])


def install_system_packages(want_tray=False, report=_noop):
    pkgs = missing_packages(want_tray)
    if pkgs:
        report("Installing " + ", ".join(pkgs) + " (authentication required)…")
        pkexec_dnf("install", "-y", *pkgs)
    if want_tray:
        system.run(["gnome-extensions", "enable", TRAY_EXTENSION_ID])  # effective after re-login
    v = installed_tor_version()
    if v:
        settings.update(versions={"tor": v})


# ----------------------------------------------------------- first install --
INSTALL_STEPS = [
    ("system", "System packages", "Tor and container tooling from the Fedora repositories"),
    ("bitcoin", "Bitcoin Core", "Download, verify builder signatures, install"),
    ("fulcrum", "Fulcrum", "Download, verify release signature, install"),
    ("mempool", "Mempool", "Pull container images"),
    ("configure", "Configure and start", "Write optimized configuration and start syncing"),
]


def preflight(data_dir) -> list:
    """-> list of (severity, message); severity 'error' blocks installation."""
    issues = []
    release = system.fedora_release()
    if release is None:
        issues.append(("warning", "This does not look like Fedora. BitFedot is built for Fedora "
                                  f"{system.MIN_FEDORA} or newer and is untested elsewhere."))
    elif release < system.MIN_FEDORA:
        issues.append(("warning", f"This is Fedora {release}. BitFedot is built and tested for Fedora "
                                  f"{system.MIN_FEDORA} or newer; upgrade Fedora first for current "
                                  "security fixes and the features BitFedot relies on."))
    if system.arch() not in _BTC_PLATFORM:
        issues.append(("error", f"Unsupported CPU architecture: {system.arch()}"))
    free = system.disk_free_gb(data_dir)
    if free < system.REQUIRED_GB:
        issues.append(("error" if free < 50 else "warning",
                       f"Only {free:.0f} GB free at this location; a full node with Fulcrum "
                       f"and Mempool needs about {system.REQUIRED_GB} GB."))
    if system.is_rotational(data_dir):
        issues.append(("warning", "This is a spinning disk. Syncing will work but takes several "
                                  "times longer than on an SSD."))
    if system.ram_mb() < 7000:
        issues.append(("warning", "Less than 8 GB of RAM: initial sync will be slow."))
    if not os.access(system.existing_parent(data_dir), os.W_OK):
        issues.append(("error", "The chosen data location is not writable."))
    return issues


def run_install(options: dict, step) -> dict:
    """options: wizard choices merged into settings.
    step(key, status, message, fraction) with status running|done."""
    paths.ensure_dirs()
    options = dict(options)
    want_tray = options.pop("_want_tray", False)
    s = settings.update(**options)
    s = settings.ensure_secrets()
    results = {}

    def stage(key, fn):
        step(key, "running", "", None)
        results[key] = fn(lambda m, f=None: step(key, "running", m, f))
        step(key, "done", "", 1.0)

    stage("system", lambda r: install_system_packages(want_tray, r))
    stage("bitcoin", lambda r: install_bitcoin(report=r))
    stage("fulcrum", lambda r: install_fulcrum(report=r))
    stage("mempool", lambda r: install_mempool(report=r))

    def configure(report):
        report("Writing configuration…")
        if s["linger"]:
            try:
                system.set_linger(True)
            except RuntimeError:
                pass   # not fatal: node simply stops at logout
        settings.update(installed=True, phase="ibd", all_stopped=False)
        services.apply(report=report)
    stage("configure", configure)
    return results


# ----------------------------------------------------------------- updates --
def check_updates() -> dict:
    """-> {component: latest version} and remember it in settings."""
    from . import apps
    s = apps.sync_versions()             # notice apps installed or removed outside BitFedot
    tor = _use_tor(s)
    latest, errors = {}, {}
    for name in components(s):
        try:
            latest[name] = latest_version(name, tor)
        except Exception as e:           # one unreachable upstream must not hide the others
            errors[name] = str(e).strip().splitlines()[-1] if str(e).strip() else "failed"
    try:
        from . import selfupdate
        latest["bitfedot"] = selfupdate.latest_version(tor)
    except Exception as e:
        errors["bitfedot"] = str(e).strip().splitlines()[-1] if str(e).strip() else "failed"
    settings.update(available=latest, last_update_check=int(time.time()))
    return {"latest": latest, "errors": errors, "via_tor": tor}


def pending_updates(s) -> dict:
    return {n: v for n, v in s.get("available", {}).items()
            if n in components(s) and net.is_newer(v, s["versions"].get(n, ""))}


def update_component(name: str, report=_noop) -> dict:
    """Download, verify and switch to the latest release of one component."""
    s = settings.load()
    tor = _use_tor(s)
    if name == "bitcoin":
        res = install_bitcoin(report=report, use_tor=tor)
        services.apply(restart=[U_BITCOIND], report=report)
    elif name == "fulcrum":
        res = install_fulcrum(report=report, use_tor=tor)
        services.apply(restart=[U_FULCRUM], report=report)
    elif name == "mempool":
        res = install_mempool(report=report, use_tor=tor)
        services.apply(restart=[U_MEMPOOL], report=report)
    elif name == "tor":
        report("Updating Tor (authentication required)…")
        pkexec_dnf("upgrade", "-y", "tor")
        v = installed_tor_version()
        settings.update(versions={"tor": v})
        services.apply(restart=[U_TOR], report=report)
        res = {"version": v, "signers": ["RPM signature verified by dnf (Fedora key)"]}
    elif name in BY_ID:
        from . import apps
        res = apps.install(name, report)
    else:
        raise ValueError(name)
    return res
