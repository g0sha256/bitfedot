"""Open the desktop keyring without a typed password, after a hardware-key login.

The login keyring (saved Wi-Fi and app passwords) is normally encrypted with
the login password and opened by typing that password at login. Log in with a
YubiKey instead and there is nothing typed — the desktop would ask for the old
password after every login.

Fedora's keyring daemon (oo7) has a mechanism for exactly this: it opens the
keyring with a systemd *credential* named `oo7.keyring-encryption-password`,
kept as an encrypted file in `~/.config/credstore.encrypted/`. systemd
encrypts it so that only this user on this installation can read it (plus the
TPM, where there is one), and the installation itself sits on the disk that
only your hardware keys unlock:

    YubiKey → encrypted disk → this installation's credential key → keyring

`setup()` therefore
  1. checks the password you type really is the keyring's,
  2. replaces it by a long random one nobody has to know, and checks it took,
  3. stores that as the encrypted credential,
  4. restarts the daemon and checks the keyring really opens by itself —
     and puts your old password back if any step fails.

Consequence to know: the random password exists only in that encrypted file.
Reinstalling the system (or losing `/var/lib/systemd/credential.secret`)
makes the saved keyring unreadable; the passwords in it then have to be
entered again. `undo()` gives the keyring an ordinary password back.

Run in a terminal:   python3 -P keyring_unlock.py setup | undo | status
The login password is read with getpass and goes only to the keyring daemon.
"""
import getpass
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

SERVICE = "org.freedesktop.secrets"
ROOT = "/org/freedesktop/secrets"
LOGIN = ROOT + "/collection/login"
INTERNAL = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
CREDENTIAL = "oo7.keyring-encryption-password"
UNIT = "oo7-daemon.service"


def credential_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "credstore.encrypted" / CREDENTIAL


class Keyring:
    """Minimal Secret Service client (plain transport on the local session bus)."""

    def __init__(self):
        import gi
        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib
        self.Gio, self.GLib = Gio, GLib
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.session = self._call(ROOT, "org.freedesktop.Secret.Service", "OpenSession",
                                  GLib.Variant("(sv)", ("plain", GLib.Variant("s", "")))).unpack()[1]

    def _call(self, path, iface, method, params, timeout=60000):
        return self.bus.call_sync(SERVICE, path, iface, method, params, None,
                                  self.Gio.DBusCallFlags.NONE, timeout, None)

    def _secret(self, text: str):
        return (self.session, b"", text.encode(), "text/plain")

    def locked(self, collection=LOGIN) -> bool:
        v = self._call(collection, "org.freedesktop.DBus.Properties", "Get",
                       self.GLib.Variant("(ss)", ("org.freedesktop.Secret.Collection", "Locked")))
        return bool(v.unpack()[0])

    def change_password(self, old: str, new: str, collection=LOGIN):
        self._call(ROOT, INTERNAL, "ChangeWithMasterPassword",
                   self.GLib.Variant("(o(oayays)(oayays))", (collection, self._secret(old), self._secret(new))))

    def unlock(self, password: str, collection=LOGIN):
        self._call(ROOT, INTERNAL, "UnlockWithMasterPassword",
                   self.GLib.Variant("(o(oayays))", (collection, self._secret(password))))

    def lock(self, collection=LOGIN):
        self._call(ROOT, "org.freedesktop.Secret.Service", "Lock", self.GLib.Variant("(ao)", ([collection],)))

    def create(self, label: str, password: str) -> str:
        props = {"org.freedesktop.Secret.Collection.Label": self.GLib.Variant("s", label)}
        return self._call(ROOT, INTERNAL, "CreateWithMasterPassword",
                          self.GLib.Variant("(a{sv}(oayays))", (props, self._secret(password)))).unpack()[0]

    def delete(self, collection: str):
        self._call(collection, "org.freedesktop.Secret.Collection", "Delete", None)


# ------------------------------------------------------------- credential --
def supported():
    """-> (ok, reason). Needs the oo7 daemon with credential support and systemd ≥ 258."""
    unit = subprocess.run(["systemctl", "--user", "show", UNIT, "-p", "ImportCredential", "-p", "LoadState"],
                          capture_output=True, text=True).stdout
    if "LoadState=loaded" not in unit or CREDENTIAL not in unit:
        return False, ("This desktop's keyring service cannot open the keyring from a stored credential "
                       "(needs Fedora's oo7 keyring daemon).")
    version = subprocess.run(["systemctl", "--version"], capture_output=True, text=True).stdout.split()
    if len(version) < 2 or not version[1].isdigit() or int(version[1]) < 258:
        return False, "systemd 258 or newer is needed to load the keyring credential."
    return True, ""


def store_credential(password: str):
    """Encrypt `password` for this user on this installation and put it where the daemon looks."""
    target = credential_file()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    p = subprocess.run(["systemd-creds", "encrypt", "--user", f"--name={CREDENTIAL}", "-", "-"],
                       input=password.encode(), capture_output=True)
    if p.returncode != 0 or not p.stdout.strip():
        raise RuntimeError("Could not encrypt the credential: " + p.stderr.decode().strip()[-200:])
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(p.stdout)
    os.replace(tmp, target)


def read_credential() -> str:
    p = subprocess.run(["systemd-creds", "decrypt", "--user", f"--name={CREDENTIAL}", str(credential_file()), "-"],
                       capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("Could not decrypt the stored credential: " + p.stderr.decode().strip()[-200:])
    return p.stdout.decode()


def restart_daemon(wait=20) -> "Keyring":
    """Restart the keyring daemon (as happens at every login) and reconnect."""
    subprocess.run(["systemctl", "--user", "restart", UNIT], check=True)
    last = None
    for _ in range(wait * 2):
        time.sleep(0.5)
        try:
            return Keyring()
        except Exception as e:           # the daemon is still coming up
            last = e
    raise RuntimeError(f"The keyring service did not come back: {last}")


def status() -> dict:
    ok, reason = supported()
    info = {"supported": ok, "reason": reason, "configured": credential_file().exists(), "locked": None}
    try:
        info["locked"] = Keyring().locked()
    except Exception:
        pass
    return info


# ------------------------------------------------------------------ steps --
class WrongPassword(Exception):
    pass


def _opens_with(ring, password: str) -> bool:
    """Does `password` really open the login keyring? (Lock it, then try.)

    Needed because the daemon does not check the *old* password when asked to
    change the password of a keyring that is already open — only unlocking
    verifies a password. So every claim about "the password is now X" is
    checked this way."""
    ring.lock()
    try:
        ring.unlock(password)
    except Exception:
        return False
    return not ring.locked()


def setup(current_password: str, say=print, ring=None, store=None, restart=None, remove=None) -> None:
    """Switch the login keyring to open by itself. Each step is verified, and
    the old password is put back if any of them fails.
    (`ring`, `store`, `restart`, `remove` are injectable for tests.)"""
    ok, reason = (True, "") if ring is not None else supported()
    if not ok:
        raise RuntimeError(reason)
    ring = ring or Keyring()
    store, restart = store or store_credential, restart or restart_daemon
    remove = remove or (lambda: credential_file().unlink(missing_ok=True))

    if not _opens_with(ring, current_password):
        raise WrongPassword("That is not the keyring's current password. Nothing was changed; the desktop "
                            "will ask for the password the next time the keyring is needed.")
    new = secrets.token_urlsafe(48)

    def put_back(active_ring):
        try:
            if active_ring.locked():
                active_ring.unlock(new)
            active_ring.change_password(new, current_password)
            remove()
            if _opens_with(active_ring, current_password):
                say("Restored: the keyring opens with your login password as before.")
                return
        except Exception:
            pass
        # Last resort: never leave the user without a password that works.
        say("COULD NOT RESTORE AUTOMATICALLY. One of these now opens your keyring when the desktop asks:")
        say("    your login password, or:  " + new)
        say("Write the second one down before closing this window.")

    say("Giving the keyring a long random password…")
    ring.change_password(current_password, new)
    if not _opens_with(ring, new):
        put_back(ring)
        raise RuntimeError("The keyring did not take the new password. It was not switched over.")
    try:
        say("Storing it encrypted for this user on this installation…")
        store(new)
        say("Restarting the keyring service to check that it now opens by itself…")
        ring = restart()
        if ring.locked():
            raise RuntimeError("the keyring stayed locked after the restart")
    except Exception as e:
        say(f"That did not work ({e}). Putting your old password back…")
        try:
            ring = ring if ring is not None else Keyring()
        except Exception:
            pass
        put_back(ring)
        raise RuntimeError("The keyring was not switched over.")
    say("Done: the keyring opens automatically after login, without a password.")


def undo(new_password: str, say=print, ring=None, read=None, remove=None) -> None:
    """Give the keyring an ordinary password again and remove the stored credential."""
    ring = ring or Keyring()
    stored = (read or read_credential)()
    if ring.locked():
        ring.unlock(stored)
    ring.change_password(stored, new_password)
    if not _opens_with(ring, new_password):
        raise RuntimeError("The keyring did not take the new password; the stored credential was kept.")
    (remove or (lambda: credential_file().unlink(missing_ok=True)))()
    say("Done: the keyring is protected by the password you just chose, and the stored credential is gone.")


def selftest(say=print) -> bool:
    """Exercise the calls `setup` relies on, on a throw-away keyring holding one
    item (an empty keyring accepts any password). Touches nothing else."""
    ring = Keyring()
    G = ring.GLib
    path = ring.create("bitfedot-selftest", "first-password")
    final = "first-password"
    try:
        props = {"org.freedesktop.Secret.Item.Label": G.Variant("s", "selftest"),
                 "org.freedesktop.Secret.Item.Attributes": G.Variant("a{ss}", {"app": "bitfedot-selftest"})}
        ring._call(path, "org.freedesktop.Secret.Collection", "CreateItem",
                   G.Variant("(a{sv}(oayays)b)", (props, ring._secret("x"), True)))

        def opens(pw):
            ring.lock(path)
            try:
                ring.unlock(pw, path)
            except Exception:
                return False
            return not ring.locked(path)
        wrong_rejected = not opens("wrong-password")
        right_accepted = opens("first-password")
        ring.change_password("first-password", "second-password", path)
        final = "second-password"
        changed = opens("second-password") and (ring.lock(path) or True) and not opens("first-password")
        ring.unlock(final, path)
    finally:
        try:
            if ring.locked(path):
                ring.unlock(final, path)
            ring.delete(path)
        except Exception:
            pass
    say(f"wrong password rejected: {wrong_rejected} · right accepted: {right_accepted} · change took effect: {changed}")
    return wrong_rejected and right_accepted and changed


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    command = argv[0] if argv else ""
    try:
        if command == "status":
            print(status())
        elif command == "selftest":
            return 0 if selftest() else 1
        elif command == "setup":
            ok, reason = supported()
            if not ok:
                print(reason)
                return 1
            print("    The keyring is currently opened by your login password.")
            for attempt in range(3):
                try:
                    setup(getpass.getpass("    Current login password (used once, to re-key the keyring): "))
                    break
                except WrongPassword as e:
                    print(f"    {e}" if attempt == 2 else "    That password does not open the keyring — try again.")
                    if attempt == 2:
                        return 1
        elif command == "undo":
            first = getpass.getpass("    New keyring password: ")
            if first != getpass.getpass("    Repeat it: ") or not first:
                print("    The two entries differ or are empty.")
                return 1
            undo(first)
        else:
            print(__doc__.strip().splitlines()[-2].strip(), file=sys.stderr)
            return 2
    except RuntimeError as e:
        print(f"    {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
