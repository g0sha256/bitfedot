"""Optional apps: verified install, update, removal and launch.

`catalog.py` says *what* can be installed; this module knows *how*, once per
delivery kind. The public functions take an app id:

    status(id, s)            what the Apps page shows
    latest_version(id)       newest upstream version
    install(id, report)      download → verify against the pinned key → install
                             (also used for updates)
    remove(id)               remove the program, never the user's data
    launch(id)

Nothing is unpacked or executed before its signature has been checked against
the key pinned in the catalog entry. Kinds that need root ("dnf") go through
`hardening.as_root()` with a repository set up from the pinned key.
"""
import gzip
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from . import hardening, net, paths, services, settings, system, verify
from .catalog import BY_ID, CATALOG, App

SPARROW_HOME = paths.HOME / ".sparrow"
FLATPAK_REMOTE = "flathub"
FLATPAK_URL = "https://dl.flathub.org/repo/"


def _noop(msg, frac=None):
    pass


def get(app_id) -> App:
    return BY_ID[app_id]


def supported(app: App) -> bool:
    return system.arch() in app.arch


def _arch(app: App) -> str:
    try:
        return app.arch[system.arch()]
    except KeyError:
        raise RuntimeError(f"{app.title} has no build for {system.arch()}.")


def _keys(app: App) -> list:
    return sorted((paths.KEYS_DIR / app.key_dir).iterdir())


def _use_tor() -> bool:
    s = settings.load()
    return bool(s.get("updates_via_tor")) and services.tor_wanted(s) and net.tor_usable()


def _desktop_file(app: App) -> Path:
    return paths.DESKTOP_DIR / f"bitfedot-{app.id}.desktop"


def _write_desktop_entry(app: App, root: Path):
    """Menu entry for a per-user install, so the app is found like any other."""
    exe = root / app.spec["exec"]
    args = " ".join(app.spec.get("exec_args", ()))
    services._write(_desktop_file(app), f"""[Desktop Entry]
Type=Application
Name={app.title}
Comment={app.summary}
Exec="{exe}" {args}
Icon={root / app.spec.get('icon', '')}
Terminal=false
Categories=Network;
""", 0o644)


def _activate(dest: Path):
    """Point apps/<id>/current at `dest` atomically."""
    link, tmp = dest.parent / "current", dest.parent / ".current.tmp"
    tmp.unlink(missing_ok=True)
    os.symlink(dest.name, tmp)
    os.replace(tmp, link)


# ====================================================================== archive
# A release archive with a detached signature, unpacked under apps/<id>/.

def _archive_latest(app: App, use_tor=False) -> str:
    how = app.spec["latest"]
    if how[0] == "github":
        return net.latest_tag(how[1], use_tor).lstrip("v")
    if how[0] == "json":
        return str(json.loads(net.fetch_text(how[1], use_tor))[how[2]])
    raise ValueError(how)


def _archive_install(app: App, report, use_tor) -> dict:
    spec = app.spec
    version = _archive_latest(app, use_tor)
    fmt = {"version": version, "arch": _arch(app)}
    base, artifact = spec["base"].format(**fmt), spec["artifact"].format(**fmt)
    dl = paths.DOWNLOADS_DIR / f"{app.id}-{version}"
    dl.mkdir(parents=True, exist_ok=True)

    report(f"Downloading {app.title} {version} signature…")
    if "checksums" in spec:
        sums, sig = (name.format(**fmt) for name in spec["checksums"])
        net.download(base + sums, dl / sums, use_tor=use_tor)
    else:
        sums, sig = None, spec["signature"].format(**fmt)
    net.download(base + sig, dl / sig, use_tor=use_tor)
    net.download(base + artifact, dl / artifact, use_tor=use_tor,
                 progress=lambda f: report(f"Downloading {app.title} {version}…", f))

    report(f"Verifying {app.title} against the pinned key…")
    try:
        if sums:
            result = verify.signed_checksums(_keys(app), app.fingerprints, dl / sums, dl / sig, dl / artifact)
        else:
            result = verify.signed_file(_keys(app), app.fingerprints, dl / sig, dl / artifact)
    except verify.VerificationError:
        (dl / artifact).unlink(missing_ok=True)       # never keep an unverified download
        raise

    report(f"Installing {app.title} {version}…")
    # Apps that keep their profile inside their own folder get one fixed folder
    # (and update themselves afterwards); everything else is installed per version.
    dest = paths.APPS_DIR / app.id / ("app" if spec.get("fixed_dir") else version)
    if spec.get("fixed_dir") and dest.exists():
        raise RuntimeError(f"{app.title} is already installed and keeps itself up to date.")
    from .installer import extract_archive            # shared with the core components
    extract_archive(dl / artifact, dest, spec["marker"])
    shutil.rmtree(dl, ignore_errors=True)
    _write_desktop_entry(app, paths.app_current(app.id))
    result["version"] = version
    return result


# ========================================================================== apt
# A package from a signed Debian repository, unpacked per user (no dpkg, no root).
# The chain is the one apt itself relies on:
#   InRelease (clear-signed) → SHA-256 of Packages → SHA-256 of the .deb

def _apt_index(app: App, use_tor=False) -> dict:
    """Verified repository metadata for the package: version, filename, sha256."""
    spec, arch = app.spec, _arch(app)
    work = paths.DOWNLOADS_DIR / f"{app.id}-index"
    work.mkdir(parents=True, exist_ok=True)
    try:
        dist = f"{spec['repo']}/dists/{spec['dist']}"
        net.download(f"{dist}/InRelease", work / "InRelease", use_tor=use_tor)
        release = verify.clearsigned_text(_keys(app), app.fingerprints, work / "InRelease")
        rel_path = f"{spec['component']}/binary-{arch}/Packages.gz"
        want = _release_sha256(release, rel_path)
        net.download(f"{dist}/{rel_path}", work / "Packages.gz", use_tor=use_tor)
        if verify.sha256_file(work / "Packages.gz") != want:
            raise verify.VerificationError(f"{app.title}: package index does not match the signed release file")
        index = gzip.decompress((work / "Packages.gz").read_bytes()).decode()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    stanzas = [dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
               for block in index.split("\n\n")]
    mine = [st for st in stanzas if st.get("Package") == spec["package"]]
    if not mine:
        raise RuntimeError(f"{spec['package']} is not in the {app.title} repository")
    best = max(mine, key=lambda st: net.version_tuple(st["Version"]))
    return {"version": best["Version"], "url": f"{spec['repo']}/{best['Filename']}",
            "sha256": best["SHA256"].lower(), "name": os.path.basename(best["Filename"])}


def _release_sha256(release_text: str, rel_path: str) -> str:
    """SHA-256 of `rel_path` as listed in a Debian Release file."""
    in_sha256 = False
    for line in release_text.splitlines():
        if not line.startswith(" "):
            in_sha256 = line.strip() == "SHA256:"
        elif in_sha256:
            digest, _size, name = line.split()
            if name == rel_path:
                return digest.lower()
    raise verify.VerificationError(f"{rel_path} is not listed in the signed release file")


def deb_data_member(deb: Path):
    """(offset, size, name) of the data.tar.* member inside a .deb (an `ar` archive)."""
    with open(deb, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise RuntimeError("Not a Debian package")
        while True:
            header = f.read(60)
            if len(header) < 60:
                raise RuntimeError("Debian package has no data archive")
            name = header[:16].decode().strip().rstrip("/")
            size = int(header[48:58].decode().strip())
            if name.startswith("data.tar"):
                return f.tell(), size, name
            f.seek(size + size % 2, os.SEEK_CUR)       # members are 2-byte aligned


def _apt_install(app: App, report, use_tor) -> dict:
    spec = app.spec
    report(f"Checking the signed {app.title} repository…")
    pkg = _apt_index(app, use_tor)
    version = pkg["version"]
    dl = paths.DOWNLOADS_DIR / f"{app.id}-{version}"
    dl.mkdir(parents=True, exist_ok=True)
    deb = dl / pkg["name"]
    net.download(pkg["url"], deb, use_tor=use_tor,
                 progress=lambda f: report(f"Downloading {app.title} {version}…", f))
    report(f"Verifying {app.title}…")
    if verify.sha256_file(deb) != pkg["sha256"]:
        deb.unlink(missing_ok=True)
        raise verify.VerificationError(f"{app.title}: download does not match the signed package index")

    report(f"Installing {app.title} {version}…")
    dest = paths.APPS_DIR / app.id / version
    tmp = dest.with_name(dest.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    offset, size, _name = deb_data_member(deb)
    with open(deb, "rb") as f:
        f.seek(offset)
        with tarfile.open(fileobj=_Window(f, size), mode="r|*") as tar:
            tar.extractall(tmp, filter="data")          # refuses paths escaping tmp, devices, setuid
    for rel in spec.get("delete", ()):
        (tmp / rel).unlink(missing_ok=True)
    if not (tmp / spec["exec"]).exists():
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"{spec['exec']} not found in the {app.title} package")
    shutil.rmtree(dest, ignore_errors=True)
    os.replace(tmp, dest)
    _activate(dest)
    shutil.rmtree(dl, ignore_errors=True)
    _write_desktop_entry(app, paths.app_current(app.id))
    return {"version": version, "sha256": pkg["sha256"], "signers": [app.signer]}


class _Window:
    """Read-only view of `size` bytes of an open file (one member of an archive)."""

    def __init__(self, f, size):
        self.f, self.left = f, size

    def read(self, n=-1):
        n = self.left if n is None or n < 0 else min(n, self.left)
        data = self.f.read(n)
        self.left -= len(data)
        return data


# ====================================================================== flatpak
# From Flathub, through a per-user remote that trusts only the pinned Flathub key.

def _flatpak(*args, timeout=120, check=False):
    if not system.have("flatpak"):
        raise RuntimeError("Flatpak is not installed. Install it with: sudo dnf install flatpak")
    return system.run(["flatpak", "--user", *args], timeout=timeout, check=check,
                      env=net.proxy_env(_use_tor()))


def _flatpak_field(output: str, name: str) -> str:
    for line in output.splitlines():
        key, _, value = line.strip().partition(":")
        if key.strip() == name:
            return value.strip()
    return ""


def _flatpak_remote(app: App):
    key = next(iter(_keys(app)))
    _flatpak("remote-add", "--if-not-exists", f"--gpg-import={key}", FLATPAK_REMOTE, FLATPAK_URL, check=True)


def _flatpak_installed(app: App) -> str:
    if not system.have("flatpak"):
        return ""
    p = system.run(["flatpak", "--user", "info", app.spec["ref"]], timeout=30)
    return (_flatpak_field(p.stdout, "Version") or "installed") if p.returncode == 0 else ""


def _flatpak_latest(app: App, use_tor=False) -> str:
    _flatpak_remote(app)
    out = _flatpak("remote-info", FLATPAK_REMOTE, app.spec["ref"], check=True).stdout
    return _flatpak_field(out, "Version")


def _flatpak_install(app: App, report, use_tor) -> dict:
    report("Adding Flathub with its pinned signing key…")
    _flatpak_remote(app)
    report(f"Installing {app.title} from Flathub (this downloads its runtime too)…")
    verb = ("update",) if _flatpak_installed(app) else ("install", FLATPAK_REMOTE)
    _flatpak(*verb, "-y", "--noninteractive", app.spec["ref"], timeout=3600, check=True)
    return {"version": _flatpak_installed(app), "signers": [app.signer]}


# ========================================================================== dnf
# RPMs from the vendor's repository. The repository is set up with gpgcheck=1
# and gpgkey pointing at our pinned copy of the vendor key, so no key is ever
# trusted on first use; dnf then checks signatures on install and every update.
# (dnf accepts any key in the system RPM keyring — see SECURITY.md.)

def _dnf_key_path(app: App) -> str:
    return f"/etc/pki/rpm-gpg/RPM-GPG-KEY-bitfedot-{app.spec['repo_id']}"


def _dnf_repo_path(app: App) -> str:
    return f"/etc/yum.repos.d/bitfedot-{app.spec['repo_id']}.repo"


def dnf_repo_text(app: App) -> str:
    spec = app.spec
    return f"""# Managed by BitFedot. Packages must be signed by the key pinned in BitFedot:
#   {' / '.join(app.fingerprints)}
[bitfedot-{spec['repo_id']}]
name={spec['name']} (via BitFedot)
baseurl={spec['baseurl']}
enabled=1
gpgcheck=1
repo_gpgcheck={1 if spec.get('repo_gpgcheck') else 0}
gpgkey=file://{_dnf_key_path(app)}
"""


def _dnf_version_pkg(app: App) -> str:
    return app.spec.get("version_of", app.spec["packages"][-1])


def _dnf_installed(app: App) -> str:
    p = system.run(["rpm", "-q", "--qf", "%{VERSION}", _dnf_version_pkg(app)], timeout=30)
    return p.stdout.strip() if p.returncode == 0 else ""


def _dnf_latest(app: App, use_tor=False) -> str:
    """Ask the vendor repository directly (works whether or not it is configured)."""
    rid = f"bf-query-{app.spec['repo_id']}"
    url = app.spec["baseurl"].replace("$basearch", system.arch())
    cmd = ["dnf", "-q", f"--repofrompath={rid},{url}", f"--repo={rid}", f"--setopt={rid}.gpgcheck=0",
           "repoquery", "--latest-limit=1", f"--arch={system.arch()},noarch", "--qf", "%{version}\n",
           _dnf_version_pkg(app)]
    if use_tor:
        cmd.insert(2, f"--setopt=proxy=socks5h://127.0.0.1:{paths.TOR_SOCKS}")
    out = system.run(cmd, timeout=300, check=True).stdout.split()
    if not out:
        raise RuntimeError(f"{app.title} was not found in its repository")
    return out[-1]


def _dnf_vendor_repo_present(app: App) -> bool:
    vendor = app.spec.get("vendor_repo")
    return bool(vendor) and os.path.exists(vendor)


def dnf_install_script(app: App, upgrade: bool) -> list:
    """Root shell lines for installing (or upgrading) the app's packages."""
    pkgs = " ".join(app.spec["packages"])
    if upgrade:
        return [f"dnf upgrade -y --refresh {pkgs}"]
    lines = []
    if not _dnf_vendor_repo_present(app):
        key = (paths.KEYS_DIR / app.key_dir).glob("*.asc")
        key_text = "\n".join(k.read_text().strip() for k in sorted(key))
        lines += hardening._install_file(_dnf_key_path(app), key_text)
        lines += hardening._install_file(_dnf_repo_path(app), dnf_repo_text(app))
    lines.append(f"dnf install -y --refresh {pkgs}")
    if app.spec.get("vendor_repo"):
        # The vendor's own repository package now maintains the repo and its keys.
        lines.append(f"if [ -e {app.spec['vendor_repo']} ]; then rm -f {_dnf_repo_path(app)}; fi")
    return lines


def _dnf_install(app: App, report, use_tor) -> dict:
    upgrade = bool(_dnf_installed(app))
    report(f"{'Updating' if upgrade else 'Installing'} {app.title} with dnf (authentication required)…")
    hardening.as_root(dnf_install_script(app, upgrade), timeout=3600)
    version = _dnf_installed(app)
    if not version:
        raise RuntimeError(f"{app.title} was not installed.")
    return {"version": version, "signers": [f"{app.signer} — RPM signatures checked by dnf"]}


def _dnf_remove(app: App):
    shared = any(o.id != app.id and o.kind == "dnf" and o.spec["repo_id"] == app.spec["repo_id"]
                 and _dnf_installed(o) for o in CATALOG)
    lines = [f"dnf remove -y {' '.join(reversed(app.spec['packages']))}"]
    if not shared:
        lines.append(f"rm -f {_dnf_repo_path(app)} {_dnf_key_path(app)}")
    hardening.as_root(lines)


def _dnf_desktop_file(app: App) -> str:
    pkg = app.spec.get("desktop_of", _dnf_version_pkg(app))
    files = system.run(["rpm", "-ql", pkg], timeout=30).stdout.splitlines()
    return next((f for f in files if f.startswith("/usr/share/applications/") and f.endswith(".desktop")), "")


# ================================================================== dispatch
_LATEST = {"archive": _archive_latest, "apt": lambda a, t=False: _apt_index(a, t)["version"],
           "flatpak": _flatpak_latest, "dnf": _dnf_latest}
_INSTALL = {"archive": _archive_install, "apt": _apt_install, "flatpak": _flatpak_install,
            "dnf": _dnf_install}
_SYSTEM_KINDS = ("dnf", "flatpak")       # installed state lives in the system, not in our folder


def latest_version(app_id, use_tor=False) -> str:
    app = get(app_id)
    return _LATEST[app.kind](app, use_tor)


def installed_version(app_id, s=None) -> str:
    """Version as recorded in settings (kept current by sync_versions())."""
    return (s or settings.load())["versions"].get(app_id, "")


def sync_versions() -> dict:
    """Record what is really installed for apps the system manages (dnf, flatpak),
    so installs or removals made outside BitFedot are picked up."""
    found = {}
    for app in CATALOG:
        if app.kind in _SYSTEM_KINDS:
            detect = _dnf_installed if app.kind == "dnf" else _flatpak_installed
            found[app.id] = detect(app) or None
    return settings.update(versions=found)


def install(app_id, report=_noop) -> dict:
    """Install the app, or update it if it is installed. -> {'version', 'signers', …}"""
    app = get(app_id)
    _arch(app)
    result = _INSTALL[app.kind](app, report, _use_tor())
    settings.update(versions={app.id: result["version"]})
    hook = CONFIGURE.get(app.spec.get("configure", ""))
    if hook:
        report(f"Connecting {app.title} to your node…")
        hook()
    result.setdefault("signers", [app.signer])
    return result


def remove(app_id):
    """Remove the program. The app's own data (profiles, wallets, chats) stays."""
    app = get(app_id)
    if app.kind == "dnf":
        _dnf_remove(app)
    elif app.kind == "flatpak":
        _flatpak("uninstall", "-y", "--noninteractive", app.spec["ref"], timeout=600, check=True)
    else:
        shutil.rmtree(paths.APPS_DIR / app.id, ignore_errors=True)
        _desktop_file(app).unlink(missing_ok=True)
    settings.update(versions={app.id: None})


def launch(app_id):
    app = get(app_id)
    if app.kind == "dnf":
        desktop = _dnf_desktop_file(app)
        cmd = ["gio", "launch", desktop] if desktop else [app.spec["packages"][-1]]
    elif app.kind == "flatpak":
        cmd = ["flatpak", "run", "--user", app.spec["ref"]]
    else:
        cmd = [str(paths.app_current(app.id) / app.spec["exec"]), *app.spec.get("exec_args", ())]
    subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def reconfigure(app_id):
    hook = CONFIGURE.get(get(app_id).spec.get("configure", ""))
    if hook:
        hook()


def _waiting_for_fulcrum(fulcrum) -> str:
    """Why an app that talks to Fulcrum cannot reach the node right now ('' when it can, or
    when the caller has no status at hand). Fulcrum opens its port only once its index is
    complete — until then a wallet just reports "connection refused"."""
    state = (fulcrum or {}).get("state", "running")
    if state == "running":
        return ""
    if state == "syncing":
        done = fulcrum.get("progress")
        return ("opens, but cannot connect to your node yet: Fulcrum is still building its index"
                + (f" ({int(done * 100)}%)" if done is not None else ""))
    if state == "error":
        return "opens, but cannot connect to your node: Fulcrum has failed — see Logs"
    return "opens, but cannot connect to your node yet: Fulcrum is starting"


def status(app_id, s, fulcrum=None) -> dict:
    """-> {'installed': version | '', 'ready': can it be opened now?, 'note': what to know first}
    `fulcrum` is Fulcrum's card from node.snapshot(), where the caller has one."""
    app = get(app_id)
    info = {"installed": installed_version(app_id, s), "ready": False, "note": ""}
    if not info["installed"]:
        return info
    if app.needs == "fulcrum":
        if s["phase"] != "ready":
            info["note"] = "usable once the initial sync has finished"
        elif s["all_stopped"] or not (s["bitcoind_enabled"] and s["fulcrum_enabled"]):
            info["note"] = "start Fulcrum to use it"
        else:                       # it can be opened — to set up a wallet, say — but say what to expect
            info.update(ready=True, note=_waiting_for_fulcrum(fulcrum))
            return info
    info["ready"] = not info["note"]
    return info


# ============================================================ configure hooks
def sparrow_settings() -> dict:
    """The keys BitFedot manages in ~/.sparrow/config (names from Sparrow's io/Config.java)."""
    server = f"tcp://127.0.0.1:{paths.FULCRUM_PORT}|BitFedot node"
    return {
        "mode": "ONLINE",
        "serverType": "ELECTRUM_SERVER",
        "electrumServer": server,
        "recentElectrumServers": [server],
        "useProxy": False,                       # the server is local; no Tor hop needed
        "blockExplorer": f"http://127.0.0.1:{paths.MEMPOOL_PORT}",
        "feeRatesSource": "ELECTRUM_SERVER",     # fee estimates from our own node
        "exchangeSource": "NONE",                # no fiat-rate requests to third parties
        "checkNewVersions": False,               # BitFedot verifies and installs updates
    }


def configure_sparrow():
    """Point Sparrow at this node. An existing config is extended, never replaced,
    and backed up once as config.before-bitfedot."""
    SPARROW_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    cfg_file = SPARROW_HOME / "config"
    config = {}
    if cfg_file.exists():
        try:
            config = json.loads(cfg_file.read_text())
        except ValueError:
            config = {}
        backup = SPARROW_HOME / "config.before-bitfedot"
        if not backup.exists():
            shutil.copy2(cfg_file, backup)
    config.update(sparrow_settings())
    services._write(cfg_file, json.dumps(config, indent=2) + "\n")


CONFIGURE = {"sparrow": configure_sparrow}      # catalog spec["configure"] -> function
