"""Set a YubiKey's OpenPGP PIN, Admin PIN and touch policy in short sessions.

Why this exists: `ykman openpgp access change-pin` opens the key and *then*
waits for you to type. During that wait the desktop's smart-card service (or
any other program) may probe the key, which resets it or selects a different
function — and ykman fails with "Card was reset" or INVALID_INSTRUCTION. Here
all PINs are asked for first; each change then takes a fraction of a second on
a fresh connection and is simply repeated if it gets interrupted.

Run in a terminal:   python3 ykpins.py [--state FILE]
With --state, PINs this tool already set on the key are kept unless you ask to
change them again, so a repeated or interrupted setup does not make you choose
new PINs twice.
PINs are read with getpass (never echoed, never on a command line) and are
only ever sent to the key.

A wrong PIN is never retried blindly: the key allows 3 attempts before it
blocks, so on a rejected PIN this stops and says how many are left.
"""
import getpass
import sys
import time

DEFAULT_PIN, DEFAULT_ADMIN = "123456", "12345678"
RETRIES, PAUSE = 8, 1.5


class WrongPin(Exception):
    """The key rejected a PIN (as opposed to the session being interrupted)."""


def change(open_session, old, new, change_name, verify_name, is_wrong_pin, sleep=time.sleep):
    """Change one PIN from `old` to `new`, surviving interrupted sessions.

    `open_session()` is a context manager yielding a fresh session; it has
    methods named `change_name(old, new)` and `verify_name(pin)`.
    `is_wrong_pin(exc)` tells a rejected PIN from an interruption.

    If an attempt was interrupted we cannot know whether the key applied the
    change. So when a *later* attempt reports a wrong PIN, the new PIN is tried
    once: success means the earlier attempt had gone through."""
    interrupted = False
    for _ in range(RETRIES):
        try:
            with open_session() as session:
                getattr(session, change_name)(old, new)
            return
        except Exception as e:
            if not is_wrong_pin(e):
                interrupted = True
                sleep(PAUSE)
                continue
            if not interrupted:
                raise WrongPin(str(e))
            for _ in range(RETRIES):               # did the interrupted attempt succeed after all?
                try:
                    with open_session() as session:
                        getattr(session, verify_name)(new)
                    return
                except Exception as e2:
                    if is_wrong_pin(e2):
                        raise WrongPin(str(e2))
                    sleep(PAUSE)
            raise RuntimeError("The key kept being interrupted; unplug other smart-card programs and retry.")
    raise RuntimeError("The key kept being interrupted; close other programs using it and retry.")


def repeat(action, is_wrong_pin, sleep=time.sleep):
    """Run `action()` (which opens its own session), repeating on interruptions."""
    for _ in range(RETRIES):
        try:
            return action()
        except Exception as e:
            if is_wrong_pin(e):
                raise WrongPin(str(e))
            sleep(PAUSE)
    raise RuntimeError("The key kept being interrupted; close other programs using it and retry.")


def ask_new(label, minimum):
    while True:
        first = getpass.getpass(f"    New {label} ({minimum} or more characters): ")
        if len(first) < minimum or len(first) > 127:
            print(f"    Needs {minimum} to 127 characters.")
            continue
        if getpass.getpass(f"    Repeat the new {label}: ") == first:
            return first
        print("    The two entries differ — again.")


def plan(done: set, change_anyway) -> dict:
    """Which PINs to change. A PIN this tool has already set on this key is kept
    unless the user asks otherwise; one it has not set must be changed (it may
    still be the factory default that everybody knows).
    `change_anyway(label)` asks the user and returns True to change it again."""
    return {part: (part not in done) or change_anyway(label)
            for part, label in (("pin", "PIN"), ("admin", "Admin PIN"))}


def read_state(path) -> set:
    try:
        with open(path) as f:
            return {line.strip() for line in f if line.strip()}
    except (OSError, TypeError):
        return set()


def add_state(path, part):
    if path and part not in read_state(path):
        with open(path, "a") as f:
            f.write(part + "\n")


def main(argv=None) -> int:
    import argparse
    from contextlib import contextmanager

    from ykman.device import list_all_devices
    from yubikit.core import InvalidPinError
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.openpgp import KEY_REF, UIF, OpenPgpSession

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", help="file remembering which PINs were already set on this key")
    args = ap.parse_args(argv)
    done = read_state(args.state)

    @contextmanager
    def open_session():
        devices = list_all_devices()
        if len(devices) != 1:
            raise RuntimeError(f"Expected exactly one YubiKey, found {len(devices)}.")
        with devices[0][0].open_connection(SmartCardConnection) as connection:
            yield OpenPgpSession(connection)

    def wrong(e):
        return isinstance(e, InvalidPinError)

    def status():
        with open_session() as s:
            st = s.get_pin_status()
            return st.attempts_user, st.attempts_admin, s.get_uif(KEY_REF.SIG) != UIF.OFF

    try:
        user_left, admin_left, touch_on = repeat(status, wrong)
    except Exception as e:
        print(f"    Cannot read the key: {e}")
        return 1
    print(f"    Tries left — PIN: {user_left}, Admin PIN: {admin_left}")
    if min(user_left, admin_left) < 2:
        print("    Fewer than 2 tries left on one of them. Stopping so the key cannot get blocked;\n"
              "    reset its OpenPGP function first (ykman openpgp reset).")
        return 1

    def change_anyway(label):
        return input(f"    The {label} was already set on this key. Change it again? [y/N] ").strip().lower() == "y"

    todo = plan(done, change_anyway)
    if not any(todo.values()) and touch_on:
        print("    PIN, Admin PIN and touch policy are already set — nothing to do.")
        return 0

    # Ask for everything first, then talk to the key in short bursts.
    old_pin = new_pin = old_admin = new_admin = None
    if todo["pin"]:
        print(f"    PIN — current one: press Enter if it is still the factory default ({DEFAULT_PIN}).")
        old_pin = getpass.getpass("    Current PIN: ") or DEFAULT_PIN
        new_pin = ask_new("PIN", 6)
    if todo["admin"]:
        print(f"    Admin PIN — current one: press Enter if it is still the factory default ({DEFAULT_ADMIN}).")
        old_admin = getpass.getpass("    Current Admin PIN: ") or DEFAULT_ADMIN
        new_admin = ask_new("Admin PIN", 8)
    elif not touch_on:
        new_admin = getpass.getpass("    Admin PIN (needed once, to require a touch for signatures): ")

    def touch_policy():
        with open_session() as s:
            s.verify_admin(new_admin)
            s.set_uif(KEY_REF.SIG, UIF.ON)

    try:
        if todo["pin"]:
            change(open_session, old_pin, new_pin, "change_pin", "verify_pin", wrong)
            add_state(args.state, "pin")
            print("    PIN changed.")
        if todo["admin"]:
            change(open_session, old_admin, new_admin, "change_admin", "verify_admin", wrong)
            add_state(args.state, "admin")
            print("    Admin PIN changed.")
        if not touch_on:
            repeat(touch_policy, wrong)
            print("    A touch is now required for every signature.")
    except WrongPin:
        try:
            user_left, admin_left, _ = repeat(status, wrong)
            print(f"    The key rejected that PIN. Tries left — PIN: {user_left}, Admin PIN: {admin_left}.")
        except Exception:
            print("    The key rejected that PIN.")
        print("    Nothing further was changed. Run this step again with the right current PIN.")
        return 2
    except RuntimeError as e:
        print(f"    {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
