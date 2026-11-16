#!/usr/bin/env python3
"""Rehearse the keyring stage (bitfedot/keyring_unlock.py) on this computer.

Runs the real switch-over, its repeat, its undo and its failure cases against the REAL
keyring service and the REAL systemd-creds — on throw-away keyrings and a scratch
credential file. It tells you whether the keyring service here behaves the way the
stage relies on, before the stage is trusted with your login keyring.

    python3 -P tools/keyring-rehearsal.py        (from a checkout, inside a desktop session)

Never touched: the `login` keyring, ~/.config/credstore.encrypted, and the keyring
service's lifetime (it is not restarted — a restart is simulated by locking the
throw-away keyring and opening it from the stored credential, which is what the service
does at a login with a key). A guard refuses any call that names the login keyring.
The throw-away keyrings and the scratch folder are removed at the end.
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from bitfedot import keyring_unlock as ku  # noqa: E402


class Scoped:
    """The stage's client, pointed at one throw-away keyring instead of `login`."""

    def __init__(self, ring, path):
        self.ring, self.path = ring, path

    def locked(self):
        return self.ring.locked(self.path)

    def lock(self):
        self.ring.lock(self.path)

    def unlock(self, password):
        self.ring.unlock(password, self.path)

    def change_password(self, old, new):
        self.ring.change_password(old, new, self.path)


def main() -> int:
    ok, reason = ku.supported()
    if not ok:
        print(reason)
        return 1
    real_credential = ku.credential_file()
    before = real_credential.read_bytes() if real_credential.exists() else None

    # What the rehearsal stores goes to a scratch folder — through the stage's own functions.
    scratch = Path(tempfile.mkdtemp(prefix="bitfedot-rehearsal-"))
    cred = scratch / "credstore.encrypted" / ku.CREDENTIAL
    ku.credential_file = lambda: cred

    def forbidden(*a, **kw):
        raise AssertionError("the rehearsal must not restart or reconnect the keyring service")
    ku.restart_daemon = ku.connect = forbidden

    class Guarded(ku.Keyring):
        def _call(self, path, iface, method, params, timeout=60000):
            text = repr(params.unpack()) if params is not None else ""
            if path == ku.LOGIN or "/collection/login" in text:
                raise AssertionError(f"refused: {method} would touch the login keyring")
            return super()._call(path, iface, method, params, timeout)

    real = Guarded()
    G = real.GLib
    made, results = {}, []

    def fresh(label, password):
        """A throw-away keyring holding one item (an empty one accepts any password)."""
        path = real.create(label, password)
        made[path] = password
        props = {"org.freedesktop.Secret.Item.Label": G.Variant("s", "rehearsal"),
                 "org.freedesktop.Secret.Item.Attributes": G.Variant("a{ss}", {"app": "bitfedot-rehearsal"})}
        real._call(path, "org.freedesktop.Secret.Collection", "CreateItem",
                   G.Variant("(a{sv}(oayays)b)", (props, real._secret("x"), True)))
        return Scoped(real, path)

    def opens(ring, password) -> bool:
        ring.lock()
        try:
            ring.unlock(password)
        except Exception:
            return False
        return not ring.locked()

    def login_like(ring, reads_credential=True):
        """What a login with a key does: the service has only the stored credential."""
        def restart():
            ring.lock()
            stored = ku.stored_password() if reads_credential else None
            if stored:
                try:
                    ring.unlock(stored)
                except Exception:
                    pass
            return ring
        return restart

    def run(ring, typed, restart=None):
        log = []
        try:
            ku.setup(typed, say=log.append, ring=ring, store=ku.store_credential,
                     restart=restart or login_like(ring), remove=ku.remove_credential, read=ku.stored_password)
            return None, log
        except Exception as e:
            return e, log

    def check(name, passed, detail=""):
        results.append(bool(passed))
        print(("PASS  " if passed else "FAIL  ") + name + (f"   [{detail}]" if detail and not passed else ""))

    try:
        a = fresh("bitfedot-rehearsal-a", "login-pw")
        err, log = run(a, "login-pw")
        stored = ku.stored_password()
        check("1  switch-over completes", err is None and any(line.startswith("Done") for line in log), repr(err))
        check("1  stored password: 64 url-safe characters, read back exactly",
              bool(stored) and len(stored) == 64 and stored.replace("-", "").replace("_", "").isalnum())
        check("1  credential file is private (0600 in a 0700 folder), no temporary file left",
              cred.stat().st_mode & 0o777 == 0o600 and cred.parent.stat().st_mode & 0o777 == 0o700
              and [p.name for p in cred.parent.iterdir()] == [cred.name])
        check("1  the old password no longer opens it, the stored one does",
              not opens(a, "login-pw") and opens(a, stored))
        made[a.path] = stored
        print("      (stored credential is bound to a TPM chip: " + str(ku.bound_to_tpm(cred.read_bytes())) + ")")

        blob = cred.read_bytes()
        err, log = run(a, "login-pw")
        check("2  second run: recognised as done, nothing changed, keyring left open",
              err is None and any("Already done" in line for line in log) and cred.read_bytes() == blob
              and not a.locked() and opens(a, stored), repr(err))

        a.lock()        # as after a login with a typed password: shut, though the credential fits
        check("3  a shut keyring is opened from the stored credential by running the stage again",
              ku.switched_over(a) and not a.locked())

        try:
            ku.undo("chosen-pw", say=lambda m: None, ring=a, read=ku.read_credential, remove=ku.remove_credential)
            undone = None
        except Exception as e:
            undone = e
        check("4  undo: the chosen password opens it, the stored one no longer does, credential gone",
              undone is None and not cred.exists() and not opens(a, stored) and opens(a, "chosen-pw"), repr(undone))
        made[a.path] = "chosen-pw"

        b = fresh("bitfedot-rehearsal-b", "login-pw")
        err, _ = run(b, "typo")
        check("5  mistyped password: refused, no credential written",
              isinstance(err, ku.WrongPassword) and not cred.exists(), repr(err))
        check("5  ... and the keyring still has its password", opens(b, "login-pw"))

        ku.store_credential("leftover-that-was-never-applied")      # an interrupted run's leftover
        check("6  leftover credential: not mistaken for 'done'", ku.switched_over(b) is False)
        try:
            ku.undo("x", say=lambda m: None, ring=b, read=ku.read_credential, remove=ku.remove_credential)
            refused = False
        except RuntimeError as e:
            refused = "does not open the keyring" in str(e)
        check("6  undo with a leftover on a shut keyring: refuses, keeps everything",
              refused and cred.exists() and opens(b, "login-pw"))
        err, log = run(b, "login-pw")
        stored = ku.stored_password()
        check("6  the next run replaces the leftover and completes",
              err is None and stored != "leftover-that-was-never-applied" and opens(b, stored), repr(err))
        made[b.path] = stored

        c = fresh("bitfedot-rehearsal-c", "login-pw")
        ku.remove_credential()
        err, log = run(c, "login-pw", restart=login_like(c, reads_credential=False))
        check("7  keyring does not open by itself: reported, old password restored, credential removed",
              isinstance(err, RuntimeError) and any("Restored" in line for line in log) and not cred.exists()
              and not c.locked() and opens(c, "login-pw"), repr(err))

        c.change_password("NOT-the-old-password", "second-pw")
        check("8  (service) changing an open keyring's password does not check the old one", opens(c, "second-pw"))
        made[c.path] = "second-pw"
        c.lock()
        try:
            c.change_password("wrong", "third-pw")
            took = True
        except Exception:
            took = False
        check("8  (service) a shut keyring refuses a change made with the wrong password",
              not took and opens(c, "second-pw"))
    finally:
        for path, password in made.items():
            try:
                if real.locked(path):
                    real.unlock(password, path)
            except Exception:
                pass
            try:
                real.delete(path)
            except Exception as e:
                print(f"cleanup: could not delete {path}: {e}")
        shutil.rmtree(scratch, ignore_errors=True)

    left = real._call(ku.ROOT, "org.freedesktop.DBus.Properties", "Get",
                      G.Variant("(ss)", ("org.freedesktop.Secret.Service", "Collections"))).unpack()[0]
    check("cleanup: no rehearsal keyring left behind", not [p for p in left if "rehearsal" in p], str(left))
    after = real_credential.read_bytes() if real_credential.exists() else None
    check("your real stored credential is untouched", before == after)
    print(f"\n{sum(results)} of {len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
