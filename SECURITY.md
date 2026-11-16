# Security policy

BitFedot installs and supervises software that people rely on for their money and their
privacy. Please treat security reports accordingly — and so will we.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting
("Security" tab → "Report a vulnerability") on this repository. Include what you found, how to
reproduce it, and the Fedora and BitFedot versions. You will get an acknowledgement within a
few days; please allow reasonable time for a fix before disclosing.

## In scope

- Anything that lets a download be installed or executed without passing verification —
  above all in the self-updater (`bitfedot/selfupdate.py`)
- Injection into the privileged `pkexec` batches (`bitfedot/hardening.py`, `installer.py`)
- A generated configuration that exposes a service beyond `127.0.0.1` unintentionally
- Leaks that defeat a privacy setting (Tor-only mode, VPN binding, kill switch, private broadcast)
- Sandbox, firewall or kill-switch rules that do not do what the UI says
- Mishandling of the secrets in `~/.config/bitfedot/settings.json`

Vulnerabilities in Bitcoin Core, Fulcrum, Mempool, Tor or any of the optional apps themselves
belong with those projects — but tell us if BitFedot's defaults make one worse.

## Trust model, briefly

- **Trust anchors** are the public keys in `bitfedot/keys/` (provenance in `keys/README.md`)
  and the Fedora package signing keys. If you install BitFedot from a git checkout, you are
  trusting that checkout: verify the commit you run.
- **Mempool's container images are not signed upstream.** BitFedot runs them by content digest
  from `bitfedot/pins.py`; those digests are the maintainer's statement of what the release
  contains, delivered inside signed BitFedot releases. The containers are rootless, drop all
  capabilities and publish only `127.0.0.1:4080`, but they do have outbound network access and
  can reach other services on the host's loopback.
- **BitFedot's own updates** are accepted only when signed by a release key already present in
  the installed copy (`bitfedot/keys/bitfedot/`). Whoever holds that key can ship code to every
  user who updates: it is the root of trust. Without a shipped key, nothing self-installs.
- **The user account is the security boundary.** All services run as you, sandboxed from the
  rest of your home directory but not from each other's network ports on loopback. Any program
  running as your user can talk to them.
- **Root is used only on request**, through short shell batches whose inputs are validated.
- **RPM-based apps** (Mullvad, Obscura, LibreWolf) are checked by `dnf` against the system RPM
  keyring. BitFedot adds its pinned copy of the vendor key rather than fetching one, but dnf
  accepts a package signed by *any* key you have already trusted system-wide.
- BitFedot holds **no private keys**. Bitcoin Core runs with its wallet disabled. Wallets are separate programs with their own storage,
  which BitFedot never reads or deletes.

## Known limitations

- The VPN kill switch filters this machine's own traffic (including rootless containers); it
  does not filter traffic forwarded for virtual machines or rootful containers.
- The kill switch recognises a VPN client's own tunnel packets by firewall mark. Clients that
  do not mark their packets need their server addresses listed explicitly.
- The post-sync hand-over, firewall zone and kill switch have had limited real-world testing;
  see "What has been tested" in the README.
