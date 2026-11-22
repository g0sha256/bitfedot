#!/usr/bin/env python3
"""Rehearse a self-update: versions that are already out install the files of this one.

An installed copy updates itself with its OWN code (bitfedot/selfupdate.py): it checks
the signature with the key it was shipped with, unpacks the archive, runs the NEW
version's tests, and only then switches over. Whether a release can be installed is
therefore decided by the versions people already run — this lets them try, in a
temporary folder:

    python3 -P tools/update-rehearsal.py              the release files in dist/ (tools/release.sh runs this)
    python3 -P tools/update-rehearsal.py --unsigned   the tree as it is now, signed with a throw-away key:
                                                      before a release exists, and in CI
    python3 -P tools/update-rehearsal.py --from v0.2.0 --from v0.3.1

Each earlier version (every older `v*` tag, or the ones named with --from) is unpacked the
way an install lies on disk and asked to install the release twice: as the app does, and
as its background agent does for an automatic update — with the agent's environment,
which is what 0.3.2 could not be installed under. Then it is asked to roll back.

Never touched: the installed app, its settings, any unit, the network. Everything happens
under a temporary folder with BITFEDOT_ROOT set, where systemd is never called. With
--unsigned the earlier version's release key is replaced, in that folder, by the
throw-away one; the real signature is checked whenever the files come from dist/.
"""
import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# What the earlier version is asked to do. It runs with that version's code only.
DRIVER = """
import json, sys
from pathlib import Path
from bitfedot import __version__, selfupdate
out = {"from": __version__, "kind": selfupdate.install_kind()}
result = selfupdate.install_release(Path(sys.argv[1]), sys.argv[2])
out["signers"] = result["signers"]
out["live"] = selfupdate._tree_version(selfupdate.live_dir())
out["previous"] = selfupdate._tree_version(selfupdate.previous_dir())
out["rolled_back_to"] = selfupdate.rollback()
print(json.dumps(out))
"""


def git(*args, binary=False):
    p = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=not binary)
    if p.returncode != 0:
        raise SystemExit(f"git {' '.join(args)}: {(p.stderr if not binary else p.stderr.decode()).strip()}")
    return p.stdout


def key(version: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", version))


def this_version() -> str:
    return re.search(r'^__version__ = "(.*)"$', (REPO / "bitfedot/__init__.py").read_text(), re.M).group(1)


def older_tags(version: str) -> list:
    tags = [t for t in git("tag", "--list", "v*").split() if re.fullmatch(r"v\d+(\.\d+)*", t)]
    return sorted((t for t in tags if key(t) < key(version)), key=key)


def throwaway_release(version: str, folder: Path) -> Path:
    """An archive of the tree as it is now (what is tracked, and what is new and not
    ignored), with SHA256SUMS signed by a key made for the occasion. -> its public key."""
    import hashlib
    archive = folder / f"bitfedot-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name in git("ls-files", "-co", "--exclude-standard", "-z").split("\0"):
            if name and (REPO / name).is_file():
                tar.add(REPO / name, arcname=f"bitfedot-{version}/{name}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (folder / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
    home = folder / "gnupg"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--homedir", str(home), "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""]
    try:
        for cmd in (["--quick-generate-key", "BitFedot update rehearsal", "ed25519", "sign", "1d"],
                    ["--armor", "--detach-sign", "-o", str(folder / "SHA256SUMS.asc"), str(folder / "SHA256SUMS")],
                    ["--armor", "--output", str(folder / "throwaway.asc"), "--export"]):
            p = subprocess.run(gpg + cmd, capture_output=True, text=True)
            if p.returncode != 0:
                raise SystemExit(f"gpg {cmd[0]}: {p.stderr.strip()}")
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)
        shutil.rmtree(home, ignore_errors=True)
    return folder / "throwaway.asc"


def rehearse(tag: str, release: Path, version: str, as_agent: bool, own_key, work: Path) -> tuple:
    """Let the version tagged `tag` install the files in `release`. -> (ok, what happened)"""
    root = work / f"{tag}-{'agent' if as_agent else 'app'}"
    lib = root / "home" / ".local" / "lib" / "bitfedot"         # where install.sh puts it, under BITFEDOT_ROOT
    lib.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(git("archive", "--format=tar", tag, binary=True))) as tar:
        tar.extractall(lib, filter="data")
    if own_key:
        keys = lib / "bitfedot" / "keys" / "bitfedot"
        for old in keys.glob("*.asc"):
            old.unlink()
        shutil.copy(own_key, keys / "release.asc")
    files = root / "release"
    files.mkdir()
    for name in (f"bitfedot-{version}.tar.gz", "SHA256SUMS", "SHA256SUMS.asc"):
        shutil.copy(release / name, files / name)
    env = {k: v for k, v in os.environ.items() if k not in ("BITFEDOT_AGENT", "PYTHONPATH")}
    env.update(BITFEDOT_ROOT=str(root), PYTHONPATH=str(lib), PYTHONDONTWRITEBYTECODE="1")
    if as_agent:
        env["BITFEDOT_AGENT"] = "1"                               # what services.agent_unit() gives it
    p = subprocess.run([sys.executable, "-P", "-c", DRIVER, str(files), version],
                       capture_output=True, text=True, env=env, cwd=root / "home", timeout=900)
    if p.returncode != 0:
        said = (p.stderr or p.stdout).strip().splitlines()
        return False, "\n        ".join(said[-12:])
    out = json.loads(p.stdout.strip().splitlines()[-1])
    old = tag.lstrip("v")
    ok = (out["kind"] == "user" and out["from"] == old and out["live"] == version
          and out["previous"] == old and out["rolled_back_to"] == old and bool(out["signers"]))
    return ok, f"signed by {', '.join(out['signers'])}; installed {out['live']}, kept {out['previous']}, rolled back"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from", dest="tags", action="append", metavar="TAG",
                    help="an earlier version to update from (default: every older v* tag); repeatable")
    ap.add_argument("--unsigned", action="store_true",
                    help="rehearse with the tree as it is now and a throw-away key instead of the files in dist/")
    ap.add_argument("--dist", type=Path, default=REPO / "dist", help="where the release files are (default: dist/)")
    args = ap.parse_args()

    version = this_version()
    tags = args.tags or older_tags(version)
    if not tags:
        print(f"No earlier version to update from: no v* tag older than {version} in this repository "
              "(a shallow clone? fetch the tags).")
        return 1
    results = []
    with tempfile.TemporaryDirectory(prefix="bitfedot-update-rehearsal-") as tmp:
        work = Path(tmp)
        if args.unsigned:
            release = work / "release"
            release.mkdir()
            own_key = throwaway_release(version, release)
            print(f"BitFedot {version} as the tree is now, signed with a throw-away key")
        else:
            release, own_key = args.dist, None
            missing = [n for n in (f"bitfedot-{version}.tar.gz", "SHA256SUMS", "SHA256SUMS.asc")
                       if not (release / n).is_file()]
            if missing:
                print(f"{release} has no {', '.join(missing)} — build the release first (tools/release.sh), "
                      "or use --unsigned.")
                return 1
            print(f"BitFedot {version}: the release files in {release}")
        for tag in tags:
            for as_agent in (False, True):
                who = "its background agent" if as_agent else "the app"
                ok, said = rehearse(tag, release, version, as_agent, own_key, work)
                results.append(ok)
                print(f"  {'ok  ' if ok else 'FAIL'}  {tag.lstrip('v')} → {version}, installed by {who}"
                      + (f": {said}" if ok else f"\n        {said}"))
    print(f"\n{sum(results)} of {len(results)} updates went through.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
