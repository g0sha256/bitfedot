"""Open the desktop keyring without a typed password, after a hardware-key login.

The login keyring (saved Wi-Fi and app passwords) is normally encrypted with
the login password and opened by typing that password at login. Log in with a
YubiKey instead and there is nothing typed — the desktop would ask for the old
password after every login.

Fedora's keyring daemon (oo7) has a mechanism for exactly this: it opens the
keyring with a systemd *credential* named `oo7.keyring-encryption-password`,
kept as an encrypted file in `~/.config/credstore.encrypted/`. systemd
encrypts it so that only this user on this installation can read it (and binds
it to the TPM chip as well, where there is one), and the installation itself is
meant to sit on the disk that only your hardware keys unlock:

    YubiKey → encrypted disk → this installation's credential key → keyring

`setup()` therefore
  1. checks the password you type really is the keyring's,
  2. stores a long random password nobody has to know as the encrypted
     credential — first, flushed to disk and read back, so that the keyring's
     password never exists only inside this program,
  3. gives the keyring that password and checks it took,
  4. restarts the daemon and checks the keyring really opens by itself —
     and puts your old password back if a step fails.
It can be interrupted and run again: a keyring that is already switched over
is recognised and left alone, and a credential left by an interrupted run is
replaced.

What it costs — know this before running it:
  * The random password exists only in that encrypted file. Reinstalling the
    system (or losing `/var/lib/systemd/credential.secret`) — and, on a
    computer with a TPM chip, clearing or replacing that chip — makes the saved
    keyring unreadable; the passwords in it then have to be entered again.
  * A login at which you TYPE your password no longer opens the keyring: the
    daemon then tries the typed password and does not fall back to the
    credential. Log in with a key, or run `undo`.
  * The saved passwords are from then on protected by the disk, not by your
    login password. On a disk that is not encrypted, whoever gets hold of it
    can read them.
`undo()` gives the keyring an ordinary password back.

Run in a terminal:   python3 -P keyring_unlock.py setup | undo | status | selftest
The login password is read with getpass and goes only to the keyring daemon.
"""
import base64
import getpass
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

USAGE = "usage: python3 -P keyring_unlock.py setup | undo | status | selftest"
SERVICE = "org.freedesktop.secrets"
ROOT = "/org/freedesktop/secrets"
LOGIN = ROOT + "/collection/login"
INTERNAL = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
CREDENTIAL = "oo7.keyring-encryption-password"
UNIT = "oo7-daemon.service"

# How systemd marks what an encrypted credential is encrypted with (its first 16 bytes).
# These kinds need only this installation's own key; every other kind involves the TPM chip.
_HOST_ONLY = {"5a1c6a86df9d4096b1d5a65e0862f19a", "55b9ed1d38594d43a8319d2ebb332ac6",
              "058469daf6f54324800549da0f8ea2fb"}


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
    env = {**os.environ, "SYSTEMD_COLORS": "0"}         # a coloured version line would not parse
    try:
        unit = subprocess.run(["systemctl", "--user", "show", UNIT, "-p", "ImportCredential", "-p", "LoadState"],
                              capture_output=True, text=True, env=env).stdout
        version = re.search(r"systemd (\d+)", subprocess.run(["systemctl", "--version"], capture_output=True,
                                                              text=True, env=env).stdout)
    except OSError:
        return False, "systemd was not found on this system."
    if "LoadState=loaded" not in unit or CREDENTIAL not in unit:
        return False, ("This desktop's keyring service cannot open the keyring from a stored credential "
                       "(needs Fedora's oo7 keyring daemon).")
    if not version or int(version.group(1)) < 258:
        return False, "systemd 258 or newer is needed to load the keyring credential."
    return True, ""


def _write_durably(target: Path, data: bytes):
    """Write, flush to disk, then rename into place and flush the folder: once this
    returns, the file survives a power cut."""
    tmp = target.with_name(target.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    folder = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(folder)
    except OSError:
        pass                            # a file system that cannot do this for a folder: the file itself is safe
    finally:
        os.close(folder)


def store_credential(password: str):
    """Encrypt `password` for this user on this installation and put it where the daemon
    looks. That file is the only copy of the password, so it is forced to disk."""
    target = credential_file()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    p = subprocess.run(["systemd-creds", "encrypt", "--user", f"--name={CREDENTIAL}", "-", "-"],
                       input=password.encode(), capture_output=True)
    if p.returncode != 0 or not p.stdout.strip():
        raise RuntimeError("Could not encrypt the credential: " + p.stderr.decode().strip()[-200:])
    _write_durably(target, p.stdout)


def read_credential() -> str:
    # --newline=no: exactly the bytes that were stored, whatever the output is connected to.
    p = subprocess.run(["systemd-creds", "decrypt", "--user", "--newline=no", f"--name={CREDENTIAL}",
                        str(credential_file()), "-"], capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("Could not decrypt the stored credential: " + p.stderr.decode().strip()[-200:])
    return p.stdout.decode()


def remove_credential():
    credential_file().unlink(missing_ok=True)


def stored_password():
    """The password in the stored credential; None if there is none or it cannot be read."""
    if not credential_file().exists():
        return None
    try:
        return read_credential() or None
    except RuntimeError:
        return None


def bound_to_tpm(blob: bytes) -> bool:
    """Is this encrypted credential tied to the computer's TPM chip as well? (systemd does
    that by itself where there is one; the credential is then lost if the chip is cleared
    or replaced.)"""
    try:
        head = base64.b64decode(b"".join(blob.split())[:24])[:16]
    except ValueError:
        return False
    return len(head) == 16 and head.hex() not in _HOST_ONLY


def connect(wait=20) -> "Keyring":
    """A fresh connection to the keyring daemon, waiting while it is still coming up."""
    deadline = time.monotonic() + wait
    while True:
        try:
            return Keyring()
        except Exception as e:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"The keyring service did not come back: {e}")
        time.sleep(0.5)


def restart_daemon(wait=20) -> "Keyring":
    """Restart the keyring daemon and reconnect: what a login with a hardware key does —
    nothing typed, so the daemon has only the stored credential to open the keyring with."""
    subprocess.run(["systemctl", "--user", "restart", UNIT], check=True)
    time.sleep(0.5)                     # give it a moment to open the keyring before asking
    return connect(wait)


def status() -> dict:
    ok, reason = supported()
    info = {"supported": ok, "reason": reason, "configured": credential_file().exists(), "tpm": None,
            "locked": None}
    try:
        info["tpm"] = bound_to_tpm(credential_file().read_bytes())
    except OSError:
        pass
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


def switched_over(ring, read=None) -> bool:
    """Has the switch already happened — does the stored credential open the keyring?
    (Like every check here it locks the keyring and opens it again; with a credential
    that does not fit — the leftover of an interrupted run — it stays locked until the
    right password is given.)"""
    stored = (read or stored_password)()
    return bool(stored) and _opens_with(ring, stored)


def setup(current_password: str, say=print, ring=None, store=None, restart=None, remove=None,
          read=None, reconnect=None) -> None:
    """Switch the login keyring to open by itself. Safe to interrupt and to repeat:

      * the new password is stored, flushed to disk and read back BEFORE the
        keyring is given it — at no moment is the keyring's password something
        that exists only in this process;
      * a keyring that is already switched over is recognised and left alone;
      * each step is verified, and the typed password is put back if one fails.

    `ring` and the other collaborators are injectable for tests. A test double is
    never mixed with the real thing: with a `ring` given, `store`, `restart`,
    `remove` and `read` must be given too."""
    if ring is None:
        ok, reason = supported()
        if not ok:
            raise RuntimeError(reason)
        ring = Keyring()
        store, restart = store or store_credential, restart or restart_daemon
        remove, read = remove or remove_credential, read or stored_password
        reconnect = reconnect or (lambda: connect(10))
    else:
        if None in (store, restart, remove, read):
            raise TypeError("setup(ring=…) also needs store, restart, remove and read")
        given = ring
        reconnect = reconnect or (lambda: given)

    if switched_over(ring, read):
        say("Already done: the keyring opens by itself from the stored credential. Nothing was changed.")
        return
    if not _opens_with(ring, current_password):
        raise WrongPassword("That is not the keyring's current password. Nothing was changed; the desktop "
                            "will ask for the password the next time the keyring is needed.")
    new = secrets.token_urlsafe(48)

    def put_back(active):
        """Back to the typed password, from whatever state the switch-over reached."""
        try:
            if _opens_with(active, current_password):           # the change never took effect
                remove()
                say("Restored: the keyring opens with your login password as before.")
                return
            if _opens_with(active, new):
                active.change_password(new, current_password)
                if _opens_with(active, current_password):
                    remove()
                    say("Restored: the keyring opens with your login password as before.")
                    return
        except Exception:
            pass
        # Last resort: never leave the user without a password that works. The stored
        # credential — the durable copy of the new password — is deliberately kept.
        say("COULD NOT RESTORE AUTOMATICALLY. One of these now opens your keyring when the desktop asks:")
        say("    your login password, or:  " + new)
        say("Write the second one down before closing this window. It is also still stored as the")
        say("credential, so the keyring may open by itself; `undo` gives it an ordinary password again.")

    say("Storing a long random password, encrypted for this user on this installation…")
    try:
        store(new)
        if read() != new:               # soon the only copy: prove it can be read before relying on it
            raise RuntimeError("it could not be read back")
    except Exception as e:
        try:
            remove()                    # nothing half-written, and no leftover of an earlier attempt
        except Exception:
            pass
        raise RuntimeError(f"Could not store the credential ({e}). The keyring was not changed.")
    try:
        say("Giving the keyring that password…")
        ring.change_password(current_password, new)
        if not _opens_with(ring, new):
            raise RuntimeError("the keyring did not take the new password")
        say("Restarting the keyring service to check that it now opens by itself…")
        ring = restart()
        if ring.locked():
            raise RuntimeError("the keyring stayed locked after the restart")
    except Exception as e:
        say(f"That did not work ({e}). Putting your old password back…")
        try:
            ring = reconnect()          # a restart ends the session the old connection was using
        except Exception:
            pass                        # the daemon is not reachable: put_back ends in the last resort
        put_back(ring)
        raise RuntimeError("The keyring was not switched over.")
    say("Done: the keyring opens automatically after a login with your key, without a password.")


def undo(new_password: str, say=print, ring=None, read=None, remove=None) -> None:
    """Give the keyring an ordinary password again and remove the stored credential."""
    if ring is None:
        ring, read, remove = Keyring(), read or read_credential, remove or remove_credential
    elif None in (read, remove):
        raise TypeError("undo(ring=…) also needs read and remove")
    stored = read()
    if ring.locked():
        try:
            ring.unlock(stored)
        except Exception:
            pass
        if ring.locked():
            raise RuntimeError("The stored credential does not open the keyring — most likely it is the leftover "
                               "of an unfinished run, and the keyring still has the password it had before. "
                               "Nothing was changed. Open the keyring with that password when the desktop asks, "
                               "then run this again.")
    ring.change_password(stored, new_password)
    if not _opens_with(ring, new_password):
        try:
            ring.unlock(stored)         # do not leave it locked: the credential still opens it
        except Exception:
            pass
        raise RuntimeError("The keyring did not take the new password; the stored credential was kept.")
    remove()
    say("Done: the keyring is protected by the password you just chose, and the stored credential is gone.")


def selftest(say=print) -> bool:
    """Exercise the calls `setup` relies on, on a throw-away keyring holding one
    item (an empty keyring accepts any password). Touches nothing else."""
    ring = Keyring()
    G = ring.GLib
    path = ring.create("bitfedot-selftest", "first-password")
    wrong_rejected = right_accepted = changed = False
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
        changed = opens("second-password") and not opens("first-password")
    finally:
        for password in ("second-password", "first-password"):      # whichever it ended up with
            try:
                if ring.locked(path):
                    ring.unlock(password, path)
            except Exception:
                continue
        try:
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
            if switched_over(Keyring()):
                print("    Already set up: the stored credential opens the keyring (it is open now).")
                print("    Nothing was changed.")
                return 0
            if credential_file().exists():
                if stored_password() is None:
                    print("    Note: a stored keyring password exists, but this system cannot decrypt it. That is")
                    print("    what a reinstall, or a cleared or replaced TPM chip, leaves behind. If the keyring")
                    print("    was switched over with it, the passwords saved in it cannot be recovered; the")
                    print("    hardware-keys guide (docs/HARDWARE-KEYS.md) says how to start a new keyring.")
                else:
                    print("    Note: a stored keyring password exists, but it does not open the keyring — the")
                    print("    leftover of an unfinished run, or the keyring was given another password since.")
                    print("    It is replaced when this step completes.")
            print("    The keyring is currently opened by your login password.")
            for attempt in range(3):
                try:
                    setup(getpass.getpass("    Current login password (used once, to re-key the keyring): "))
                    break
                except WrongPassword as e:
                    print(f"    {e}" if attempt == 2 else "    That password does not open the keyring — try again.")
                    if attempt == 2:
                        return 1
            try:
                on_tpm = bound_to_tpm(credential_file().read_bytes())
            except OSError:
                on_tpm = False
            if on_tpm:
                print("    Note: this computer has a TPM chip, and the stored password is bound to it as well.")
                print("    If that chip is ever cleared or replaced (a firmware reset, a new mainboard, the disk")
                print("    moved to another computer), the keyring can no longer be opened and the passwords")
                print("    saved in it have to be entered again.")
        elif command == "undo":
            first = getpass.getpass("    New keyring password: ")
            if first != getpass.getpass("    Repeat it: ") or not first:
                print("    The two entries differ or are empty.")
                return 1
            undo(first)
        else:
            print(USAGE, file=sys.stderr)
            return 2
    except KeyboardInterrupt:
        print("\n    Interrupted. It is safe to run this step again: it picks up where it stopped.")
        return 130
    except EOFError:
        print("\n    No password was entered — stopped.")
        return 1
    except RuntimeError as e:
        print(f"    {e}")
        return 1
    except Exception as e:              # e.g. the keyring service not answering: say so, without a traceback
        print(f"    The keyring service could not be used ({type(e).__name__}: {e}).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
