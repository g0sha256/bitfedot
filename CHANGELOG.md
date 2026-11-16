# Changelog

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
- **Hardware keys** (experimental, untested on hardware): staged YubiKey setup for LUKS, login,
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
