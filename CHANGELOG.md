# Changelog

## Unreleased

### Added
- Status updates: Fulcrum's index progress and Mempool's catch-up in the app and tray, and
  desktop notifications for sync milestones, services becoming ready, and failures.
- Hardware keys: the desktop keyring opens by itself after a key login (encrypted systemd
  credential for Fedora's oo7 keyring daemon), so no typed password is left anywhere.

### Fixed (after a review of the two additions above, before any release)
- Keyring step: the new password is stored, flushed to disk and read back before the keyring is
  re-keyed — an interrupted run can no longer leave the keyring on a password that exists nowhere.
  Running the step again recognises a keyring that is already switched over instead of locking it
  (and opens one that a typed-password login left shut), and a failed run is rolled back over a
  fresh connection.
- Keyring step: says what it costs (a typed-password login no longer opens the keyring; a TPM chip
  that is cleared or replaced loses the saved passwords, as a reinstall does), asks for a typed
  confirmation when the disk is not encrypted, and is skipped — without blocking password
  removal — on desktops whose keyring service cannot open from a stored credential. Its "done"
  state follows the stored credential and the last run of the step, so `undo` and an unfinished
  repeat are reflected; the revert script offers the undo. `undo` refuses, instead of guessing,
  when the stored password does not open a keyring that is shut.
- `tools/keyring-rehearsal.py` runs the keyring step's switch, repeat, undo and failure cases
  against the real keyring service on throw-away keyrings, without touching the login keyring.
- Notifications: a service that crashes and is restarted is announced (systemd never reports such
  a unit as failed), at most once an hour and only while it is meant to run; a notification
  nobody could see is kept for later; a
  synced node that is a few blocks behind is no longer a "sync 90 %" milestone; Fulcrum's index
  never shows 100 % before it serves; the explorer counts as ready only once Fulcrum serves; a new
  sync or index is announced afresh; the first run only takes stock.
- Agent: the VPN watch runs before the status check again and can no longer be skipped or delayed
  by it; a garbled reply from a local service no longer aborts a status poll.
- Explorer page: a short lag of Mempool behind Bitcoin Core no longer disables it or replaces the
  page being read with the home view.
- Tray menu: a click runs the item that was clicked (every click used to open "Quit…").
- `install.sh` restarts the background agent, so an update reaches it without a reboot.

## 0.2.0 — 2026-11-16

First version intended for public release. The project was called *Nodestead* during early
development; an install made under that name is detected and adopted in place.

### Added
- **Apps** page, driven by a declarative catalog (`bitfedot/catalog.py`): optional, signature-
  verified installs and updates of Sparrow (pre-wired to the node), Mullvad VPN, Obscura VPN,
  Tor Browser, Mullvad Browser, LibreWolf, Element and SimpleX.
- **Explorer** page: native block explorer on the node's own Mempool API (fees, mempool,
  blocks, transactions, addresses, search).
- **Security** page: system check-up, systemd sandboxing for all services, strict firewalld
  zone, system-wide VPN kill switch (nftables), private transaction broadcast.
- **Fedora updates**: check and install OS updates, optional automatic security updates,
  "restart safely".
- **Sync time estimate** based on transactions rather than blocks, allowing for cache overflow
  and the signature-checked final stretch (`bitfedot/eta.py`).
- **Stop all / Start all**, and dependency-ordered, blocking stop/start whenever a setting
  change requires a restart; a banner shows what is happening.
- **Quit** asks: run in background, or shut the node down safely (it starts again with the app).
- **Self-update** from signed GitHub releases only (`bitfedot/selfupdate.py`): verified, tested
  before the switch, with rollback. `tools/release.sh` and `docs/RELEASING.md` for maintainers.
- **Supply chain** controls: container images pinned and run by digest (`bitfedot/pins.py`), and
  a configurable number of required Bitcoin Core builder signatures.
- **Hardware keys** (experimental): staged YubiKey setup for LUKS, login,
  sudo and release signing, with the password removed only after both keys are proven.
- Hardware-key boot: graphical prompt, PIN asked once, one touch, also on systems whose disk
  spans several encrypted volumes.
- Optional automatic installation of signed BitFedot updates.
- **About** page with credits and the Bitcoin whitepaper (open, or save to Documents/Desktop).
- Light / dark / system theme.
- `AGENTS.md` and `docs/EXTENDING.md` for contributors and coding assistants.

### Fixed
- Fulcrum's upstream binary could not start on Fedora (`libbz2.so.1.0` not found); a private
  compatibility symlink to the system library is now provided.
- Errors from background operations were not shown in the UI.

### Changed
- **Fedora 45 is now the minimum** supported release; the wizard warns on anything older.
- Renamed to **BitFedot** (app ID `io.github.g0sha256.BitFedot`, units `bitfedot-*`).
- `services.apply()` is serialised with a lock and reports progress.

## 0.1.0

- Guided install of Bitcoin Core, Fulcrum, Mempool and Tor with signature verification
- Tuned clearnet initial sync with automatic hand-over to the full profile
- Connectivity modes, Tor control, Tor-via-VPN, onion services
- Update checks and verified updates, tray icon, background agent
