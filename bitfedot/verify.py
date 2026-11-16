"""Signature and checksum verification.

Trust anchors are the public keys shipped inside this package (keys/), which
were taken from the upstream projects and are reviewable in git. Verification
runs in a throw-away GnuPG home so the user's own keyring is never touched and
only the pinned keys can produce a valid result."""
import hashlib
import shutil
import tempfile
from pathlib import Path

from . import paths
from .system import run

# Bitcoin Core releases are signed by many independent builders; demand
# agreement from several of them rather than trusting any single key.
BITCOIN_MIN_SIGNERS = 3
# Fulcrum releases are signed by its author, Calin Culianu.
FULCRUM_FPR = "D465135F97D0047E18E99DC321810A542031C02C"
# Keys for the optional apps are pinned in catalog.py, next to each app.


class VerificationError(Exception):
    pass


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _gpg_statuses(key_files, *gpg_args) -> list:
    """Run gpg against a throw-away keyring holding only `key_files`.
    -> the machine-readable status lines, each split into fields."""
    key_files = [str(k) for k in key_files]
    if not key_files:
        raise VerificationError("No pinned keys found")
    paths.DATA_DIR.mkdir(parents=True, exist_ok=True)
    home = tempfile.mkdtemp(prefix="gpg-", dir=paths.DATA_DIR)
    try:
        base = ["gpg", "--homedir", home, "--batch", "--no-tty", "--no-autostart",
                "--trust-model", "always"]
        run(base + ["--import", *key_files], timeout=120)
        out = run(base + ["--status-fd", "1", *(str(a) for a in gpg_args)], timeout=300).stdout
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return [line.split()[1:] for line in out.splitlines() if line.startswith("[GNUPG:] ")]


def _good(statuses) -> list:
    """[{'fpr': primary key fingerprint, 'uid': signer}] for each *good* signature
    made by a non-expired, non-revoked key."""
    good, current = {}, None
    for f in statuses:
        tag = f[0]
        if tag == "NEWSIG":
            current = None
        elif tag == "GOODSIG":
            current = " ".join(f[2:])
        elif tag in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"):
            current = None
        elif tag == "VALIDSIG" and current is not None:
            good[f[-1].upper()] = current   # last field = primary key fingerprint
            current = None
    return [{"fpr": k, "uid": v} for k, v in good.items()]


def good_signatures(sig_file, data_file, key_files) -> list:
    """Verify a detached signature file (possibly holding many signatures)
    against the pinned `key_files` only."""
    return _good(_gpg_statuses(key_files, "--verify", sig_file, data_file))


def _require(sigs, fingerprints, what):
    wanted = {f.upper() for f in fingerprints}
    if not any(s["fpr"] in wanted for s in sigs):
        raise VerificationError(f"{what} is not signed by the pinned key "
                                f"({' / '.join(sorted(wanted))}). Refusing to install.")
    return sorted(s["uid"] for s in sigs if s["fpr"] in wanted)


def signed_checksums(key_files, fingerprints, sums, sig, artifact) -> dict:
    """`sig` signs the checksum file `sums`, which lists `artifact`."""
    signers = _require(good_signatures(sig, sums, key_files), fingerprints, Path(sums).name)
    return {"signers": signers, "sha256": check_hash(sums, artifact)}


def signed_file(key_files, fingerprints, sig, artifact) -> dict:
    """`sig` is a detached signature directly over `artifact`."""
    signers = _require(good_signatures(sig, artifact, key_files), fingerprints, Path(artifact).name)
    return {"signers": signers, "sha256": sha256_file(artifact)}


def clearsigned_text(key_files, fingerprints, signed_file_path) -> str:
    """Verify a clear-signed text file and return exactly the text that was signed."""
    out = Path(str(signed_file_path) + ".verified")
    out.unlink(missing_ok=True)
    try:
        statuses = _gpg_statuses(key_files, "--output", out, "--decrypt", signed_file_path)
        _require(_good(statuses), fingerprints, Path(signed_file_path).name)
        return out.read_text()
    finally:
        out.unlink(missing_ok=True)


def primary_fingerprints(key_files) -> tuple:
    """Fingerprints of the primary keys contained in `key_files`."""
    found = []
    for key in key_files:
        out = run(["gpg", "--batch", "--no-tty", "--with-colons", "--show-keys", str(key)], timeout=60).stdout
        primary = False
        for line in out.splitlines():
            f = line.split(":")
            primary = {"pub": True, "sub": False}.get(f[0], primary)
            if f[0] == "fpr" and primary:
                found.append(f[9].upper())
                primary = False
    return tuple(found)


def expected_hash(sums_file, filename: str) -> str:
    for line in Path(sums_file).read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename:
            return parts[0].lower()
    raise VerificationError(f"{filename} is not listed in {Path(sums_file).name}")


def check_hash(sums_file, artifact):
    want = expected_hash(sums_file, Path(artifact).name)
    got = sha256_file(artifact)
    if want != got:
        raise VerificationError(
            f"SHA-256 mismatch for {Path(artifact).name}\n expected {want}\n got      {got}")
    return got


def verify_bitcoin(sums, sums_asc, tarball, min_signers=BITCOIN_MIN_SIGNERS) -> dict:
    """`min_signers` independent builders must have signed the same checksums
    (never fewer than BITCOIN_MIN_SIGNERS, whatever the caller asks for)."""
    need = max(int(min_signers), BITCOIN_MIN_SIGNERS)
    sigs = good_signatures(sums_asc, sums, sorted((paths.KEYS_DIR / "bitcoin").glob("*.gpg")))
    if len(sigs) < need:
        raise VerificationError(
            f"Only {len(sigs)} valid builder signature(s) on SHA256SUMS; "
            f"{need} are required. Refusing to install.")
    return {"signers": sorted(s["uid"] for s in sigs), "sha256": check_hash(sums, tarball)}


def verify_fulcrum(sums, sums_asc, tarball) -> dict:
    return signed_checksums((paths.KEYS_DIR / "fulcrum").glob("*.asc"), (FULCRUM_FPR,),
                            sums, sums_asc, tarball)
