# Hardware keys (YubiKey) — experimental

> **Status: proven on one computer.** Every stage — tools, both keys' PINs, the signing key, disk
> encryption with boots from each key, login and sudo, the keyring, and removing the password —
> has been run for real on Fedora 45 with two YubiKey 5C NFC (firmware 5.7.4), on a system spread
> over two encrypted volumes, and the fixes from those runs are in. One machine is not many: other hardware, other disk
> layouts and other desktops are unproven. Read each script (*Show script*) before running it.

The **Hardware keys** page moves four things onto two YubiKeys — a main key and a backup:

| What | How | Tool |
|---|---|---|
| Disk encryption (LUKS) | FIDO2 `hmac-secret`, PIN + touch at boot | `systemd-cryptenroll` |
| Desktop keyring | opens by itself from a credential stored on that disk | `systemd-creds`, oo7 |
| Login, sudo, administrator dialogs | FIDO2 with PIN | `pam_u2f` through `authselect` |
| Release and git signing | OpenPGP key on the card, touch per signature | `gpg`, `ykman` |
| BitFedot's own updates | the public half of that key in `bitfedot/keys/bitfedot/` | `selfupdate.py` |

Nothing leaves the computer: no key server, no cloud, no network access in any script except the
`dnf install` of the tools.

## How it protects you from locking yourself out

1. **Visible scripts.** Each stage is a shell script run in a terminal window. The tools ask for
   touch, PIN and re-plugging themselves; BitFedot never sees a PIN or the disk password.
2. **Additive until the end.** Stages 1–5 only *add* the keys next to your password.
3. **Old kernels stay bootable.** The boot image is rebuilt for the running kernel only; the other
   entries in the boot menu keep their old image and still accept the password.
4. **Proof before removal.** *Remove the password* stays disabled until each key has (a) unlocked
   the disk at a real boot — checked in the system journal — and (b) been confirmed for `sudo`.
5. **Typed confirmations** in the final script, and an optional **paper recovery key**.
   Without it there is no text password of any kind: **if both keys are lost or broken, the data
   is lost forever.** The page says so in red and the script makes you type that you accept it.
6. There is deliberately no Undo button. The script that puts login and boot settings back can be
   printed with `python3 -m bitfedot.hardware_keys revert` and run by hand while a key works.

## What the first real runs taught (and what the scripts now do about it)

- **Never query a key in the background.** Any second program that opens a YubiKey resets its
  smart-card session; BitFedot's own status polling did exactly that and broke PIN changes. The
  page now only looks at the USB device list and reads a serial number when you press a button.
- **Do not hold the key open while a person types.** PINs are asked for first; the key is then
  updated in sub-second sessions that are repeated if another program interrupts them
  (`bitfedot/ykpins.py`). A rejected PIN is never retried.
- **One step at a time.** A lock stops a second step from starting while another terminal window
  is still open.
- **Each step installs its own tools**, including GnuPG's smart-card daemon, which Fedora does
  not install by default — and which `gpgconf` lists as present even when it is missing.
- **Steps can be repeated.** What was already done to a key is remembered by serial number: no
  second factory reset, and PINs that are already set are kept unless you ask to change them.
- **The boot prompt must be calm.** The first real boot showed the PIN question as plain text
  between boot messages (one of them an alarming-looking but harmless start-up race), asked for
  the PIN twice and wanted two touches, because the system disk spans two encrypted volumes that
  both asked at the same moment. Now: the graphical boot screen stays on, the volumes unlock one
  after another so the PIN is typed once and reused, and additional volumes are enrolled
  PIN-only so only the first needs a touch. *Tidy the boot prompt* applies this to a system
  enrolled with the earlier version.
- **Secrets are wiped on every way out** — error, Ctrl+C, or closing the window — and leftovers
  from an interrupted run are shredded at the start of the next one.

## The stages

1. **Prepare** — optional: installs `yubikey-manager pam-u2f pamu2fcfg fido2-tools gnupg2-scdaemon`
   and enables `pcscd`. Every later stage does this for itself if needed.
2. **The two keys** — optional factory reset (you type `RESET` per key), FIDO2 PIN, OpenPGP PIN
   and Admin PIN, touch required for signing. One key plugged in at a time.
3. **Signing key** — two ways:
   - *Same key on both* (what "clone" has to mean): a key generated **on** a YubiKey cannot be
     copied off it, by design. So the key is generated in a memory-only folder (`/dev/shm`),
     moved onto both YubiKeys, and the in-memory copy is shredded. The secret exists outside a
     YubiKey for those few minutes.
   - *A separate key on each* (stronger): each YubiKey generates its own key that never exists
     anywhere else. BitFedot's updater trusts every key in `keys/bitfedot/`, so either YubiKey
     can sign a release — you get the same redundancy without the exposure.
4. **Disk encryption** — enrolls both keys on every unlocked LUKS volume, adds
   `fido2-device=auto` to `/etc/crypttab` (backup kept), builds a boot image with the `fido2`
   module and **all** drivers (`hostonly="no"`: any keyboard, USB controller, display). The
   graphical boot screen asks for the PIN once; the first volume wants PIN + touch, any further
   volume of the same system unlocks with the PIN alone right after it. (Plain-text prompts are
   available as a fallback for displays where the graphical screen does not work.)
   Then: reboot with one key, confirm; reboot with the other, confirm.
5. **Login and administrator prompts** — registers both keys in a **root-owned** list
   (`/etc/u2f_mappings`, so a program running as you cannot add its own key), with a fixed origin
   (renaming the computer cannot break login) and PIN verification, and enables Fedora's
   `with-pam-u2f` feature. Test `sudo -k && sudo true` with each key and confirm.
6. **Keyring** — the desktop keyring (saved Wi-Fi and app passwords) is normally opened by the
   login password you type. After a key login nothing is typed, so the desktop would ask for that
   password every time. This step gives the keyring a long random password and stores it as an
   encrypted systemd credential that Fedora's keyring daemon (oo7) loads by itself:
   **YubiKey → encrypted disk → this installation's credential key → keyring.** Every part of the
   switch is verified, and the old password is put back if any part fails. Cost: after a
   reinstall of the system the saved passwords in the keyring have to be entered again.
   Undo: `python3 -P bitfedot/keyring_unlock.py undo`. Needs systemd 258+ and oo7 (Fedora 45).
7. **Remove the password** — optional paper recovery key (off by default), then `systemd-cryptenroll
   --wipe-slot=password` on every volume and `passwd -l` for your user: boot, login, sudo and
   polkit dialogs then accept only a key.

## Surviving updates

Kernel updates, package updates and Fedora release upgrades must not undo any of this — with the
password gone, a silently dropped setting would mean a locked computer. So each setting is put
where the system itself keeps it, and three guards watch the rest:

| Setting | Why it survives |
|---|---|
| Keys enrolled on the disk | Stored in the LUKS header; nothing in an update touches it |
| `fido2-device=auto` in `/etc/crypttab` | Administrator-owned file; copied into every new boot image |
| Boot image contents (`fido2`, all drivers) | `/etc/dracut.conf.d/90-bitfedot-fido2.conf` is read every time a kernel is installed |
| Graphical boot prompt, one PIN | `rhgb quiet` on existing entries *and* in `/etc/kernel/cmdline` and `/etc/default/grub`, which new kernels are built from; the unlock order lives in a systemd drop-in that is also copied into every boot image |
| Login/sudo with the key | An `authselect` feature (kept across PAM package updates); settings in `/etc/security/pam_u2f.conf`; keys in `/etc/u2f_mappings` |
| Locked password | Stored in `/etc/shadow` |

Guards installed by the disk and login steps (and removed by the revert script):

1. **Protected packages** — `/etc/dnf/protected.d/bitfedot-hwkeys.conf` makes dnf refuse to remove
   `libfido2`, `systemd-udev`, `dracut`, `pam-u2f` and `authselect`, including during cleanup and
   release upgrades.
2. **Kernel check** — `/etc/kernel/install.d/96-bitfedot-fido2-check.install` runs after every
   kernel installation, checks that the new boot image contains hardware-key support, rebuilds
   it if not, and leaves a warning if even that fails. It can never make a kernel update fail.
3. **Login guard** — a small system service runs at boot and whenever the PAM selection or the
   key files change. If hardware-key login has been switched off or its files are missing, it
   restores them from root-owned copies in `/etc/bitfedot/hwkeys/`.

BitFedot shows any remaining problem under **Security → check-up**, at the top of the Hardware
keys page, and right after installing Fedora updates — *before* you restart.

Before a **Fedora release upgrade** (45 → 46): keep the backup key and the recovery key at hand,
and afterwards confirm a boot with each key again.

## Things to know before you start

- **No password means no password.** After the last step there is no text password — not for
  the disk, not for login. Without the optional paper recovery key, losing or breaking both
  YubiKeys loses the data **forever**; nobody, including the authors of this software, can get
  it back. Keep the backup key in a different place from the main one.
- **Check `/etc/crypttab`** as printed by the disk script: every volume that is unlocked at boot
  must appear there with `fido2-device=auto`. Systems that list volumes only on the kernel
  command line need `rd.luks.options=fido2-device=auto` added by hand.
- **Remote and headless use.** With the password locked, anything that authenticates through PAM
  needs a key touch. SSH key logins are unaffected; unattended `sudo` is not possible.
- **FIDO2 PIN retries.** Eight wrong PINs in a row block the FIDO2 function of that key until it
  is reset — which also invalidates its disk and login enrollment. That is what the second key
  is for.

## Signing BitFedot releases with the key

After stage 3 the public key(s) are in `~/bitfedot-release-keys/`. Copy them into
`bitfedot/keys/bitfedot/` in your source checkout, commit, and from then on `tools/release.sh`
signs with whichever YubiKey is plugged in (touch required). Installed copies that already carry
the key verify each release and — with *Install BitFedot updates automatically* switched on under
Updates — install it by themselves. See [RELEASING.md](RELEASING.md).

## If something goes wrong

| Situation | What to do |
|---|---|
| Boot does not ask for the key, or the PIN prompt is unusable | Wait for / choose the password prompt (stages 1–5), or pick an older kernel in the boot menu |
| `sudo` no longer works after stage 5 | In the terminal you kept open: `sudo authselect disable-feature with-pam-u2f && sudo authselect apply-changes` |
| Password already removed, one key lost | Use the other key; enroll a replacement by repeating stages 2, 4 and 5 for it |
| Password already removed, both keys lost | The recovery key at the boot prompt, if you made one. Otherwise the data cannot be recovered |
| You want passwords back | `python3 -m bitfedot.hardware_keys revert > revert.sh`, read it, `bash revert.sh`; then `sudo systemd-cryptenroll --unlock-fido2-device=auto --password /dev/…` per volume. Only possible while a key still works |
