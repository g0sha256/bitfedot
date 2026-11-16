"""The catalog of optional apps — pure data, no logic.

ADDING AN APP = adding one `App(...)` entry here (plus its signing key under
`bitfedot/keys/<key_dir>/` and a line in `keys/README.md`). The machinery in
`apps.py` does the rest: the Apps page, verified install, updates and removal
all follow from the entry. See docs/EXTENDING.md for a walk-through.

Every app must come with a signature we can check against a *pinned* key.
`kind` says how it is delivered:

  archive   a release archive plus a detached signature (over the archive, or
            over a checksum file). Installed per user, no root.
  apt       a package from a signed Debian repository: InRelease → Packages →
            .deb hashes are checked, then the package is unpacked per user.
  flatpak   a Flatpak from a remote added with a pinned repository key. No root.
  dnf       RPMs from the vendor's repository, configured with gpgcheck=1 and
            our pinned copy of the vendor key (never one fetched at install
            time). Needs the administrator password.
"""
from dataclasses import dataclass, field

from . import paths

CATEGORIES = {            # id -> (title, description), in display order
    "wallet": ("Wallets", "Connected to your own node, so your addresses are never shown to "
                          "someone else's server."),
    "vpn": ("VPN", "Hides your IP address from peers and your traffic from your internet provider. "
                   "Combine with “Tor through a VPN” and the kill switch under Security."),
    "browser": ("Private browsers", "Browsers that resist tracking and fingerprinting out of the box."),
    "messenger": ("Private messengers", "End-to-end encrypted chat that does not depend on a phone number."),
}


@dataclass(frozen=True)
class App:
    id: str                 # also the key in settings["versions"] and the folder under apps/
    title: str
    category: str           # a key of CATEGORIES
    summary: str            # one line: what it is
    homepage: str
    license: str
    kind: str               # archive | apt | flatpak | dnf
    key_dir: str            # folder under bitfedot/keys/ holding the pinned key(s)
    fingerprints: tuple     # primary-key fingerprints a valid signature must come from
    signer: str             # who that key belongs to, shown to the user
    spec: dict              # kind-specific fields, see the entries below
    arch: dict = field(default_factory=lambda: {"x86_64": "x86_64", "aarch64": "aarch64"})
    setup: str = ""         # what BitFedot configures for you, shown to the user
    needs: str = ""         # "fulcrum": only usable while that service runs
    self_updates: bool = False   # the app updates itself (with its own signature checks)


CATALOG = [
    # ------------------------------------------------------------- wallets --
    App(
        id="sparrow", title="Sparrow Wallet", category="wallet",
        summary="Desktop wallet with first-class hardware-wallet, multisig and coin-control support.",
        homepage="https://sparrowwallet.com", license="Apache-2.0",
        kind="archive", key_dir="sparrow",
        fingerprints=("D4D0D3202FC06849A257B38DE94618334C674B40",), signer="Craig Raw",
        spec={
            "latest": ("github", "sparrowwallet/sparrow"),
            "base": "https://github.com/sparrowwallet/sparrow/releases/download/{version}/",
            "artifact": "sparrowwallet-{version}-{arch}.tar.gz",
            # signature is over a checksum file that lists the artifact
            "checksums": ("sparrow-{version}-manifest.txt", "sparrow-{version}-manifest.txt.asc"),
            "marker": "bin/Sparrow",          # identifies the root folder inside the archive
            "exec": "bin/Sparrow", "icon": "lib/Sparrow.png",
            "configure": "sparrow",           # hook in apps.CONFIGURE
        },
        setup=f"Uses only this node: wallet history from Fulcrum (127.0.0.1:{paths.FULCRUM_PORT}), "
              "fee estimates from Bitcoin Core, transactions open in your own explorer, and "
              "exchange-rate and update lookups are off — it makes no outside connection.",
        needs="fulcrum",
    ),
    # ----------------------------------------------------------------- VPN --
    App(
        id="mullvad", title="Mullvad VPN", category="vpn",
        summary="No-logs VPN you can pay for anonymously (cash, Bitcoin, Monero); WireGuard based.",
        homepage="https://mullvad.net", license="GPL-3.0",
        kind="dnf", key_dir="mullvad",
        fingerprints=("A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF",), signer="Mullvad (code signing)",
        spec={"repo_id": "mullvad", "name": "Mullvad",
              "baseurl": "https://repository.mullvad.net/rpm/stable/$basearch",
              "packages": ("mullvad-vpn",)},
    ),
    App(
        id="obscura", title="Obscura VPN", category="vpn",
        summary="Two-party VPN: Obscura never sees your traffic, its exit partner never sees who you are.",
        homepage="https://obscura.com", license="GPL-3.0",
        kind="dnf", key_dir="obscura",
        fingerprints=("952095FF926830EFE59875B7878908CE460572A7",
                      "2A5996C7C12D701E78ADC7A27FFA28C5B0D8256F"), signer="Obscura Repository Signer",
        spec={"repo_id": "obscura", "name": "Obscura VPN",
              "baseurl": "https://linux-pkgs.obscura.com/rpm/$basearch",
              # obscura-repository ships the vendor's own repo file and key rotation,
              # so our bootstrap repo is removed again once it is installed.
              "packages": ("obscura-repository", "obscura"), "version_of": "obscura",
              "desktop_of": "obscura-gui",
              "vendor_repo": "/etc/yum.repos.d/obscura.repo"},
        arch={"x86_64": "x86_64"},
    ),
    # ------------------------------------------------------------ browsers --
    App(
        id="torbrowser", title="Tor Browser", category="browser",
        summary="Routes all browsing through Tor and makes every user look alike to websites.",
        homepage="https://www.torproject.org", license="MPL-2.0 and others",
        kind="archive", key_dir="torbrowser",
        fingerprints=("EF6E286DDA85EA2A4BA7DE684E2C6E8793298290",), signer="Tor Browser Developers",
        spec={
            "latest": ("json", "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json",
                       "version"),
            "base": "https://dist.torproject.org/torbrowser/{version}/",
            "artifact": "tor-browser-linux-{arch}-{version}.tar.xz",
            "signature": "tor-browser-linux-{arch}-{version}.tar.xz.asc",   # directly over the archive
            "marker": "Browser/start-tor-browser",
            "exec": "Browser/start-tor-browser", "exec_args": ("--detach",),
            "icon": "Browser/browser/chrome/icons/default/default128.png",
            "fixed_dir": True,     # keeps its profile inside its folder: never replace it
        },
        setup="Open your explorer or wallets' onion addresses (see Connectivity) from anywhere.",
        self_updates=True,
    ),
    App(
        id="mullvadbrowser", title="Mullvad Browser", category="browser",
        summary="Tor Browser's anti-fingerprinting without the Tor network — made for use with a VPN.",
        homepage="https://mullvad.net/browser", license="MPL-2.0",
        kind="dnf", key_dir="mullvad",
        fingerprints=("A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF",), signer="Mullvad (code signing)",
        spec={"repo_id": "mullvad", "name": "Mullvad",
              "baseurl": "https://repository.mullvad.net/rpm/stable/$basearch",
              "packages": ("mullvad-browser",)},
    ),
    App(
        id="librewolf", title="LibreWolf", category="browser",
        summary="Firefox with telemetry removed and privacy settings hardened; good everyday browser.",
        homepage="https://librewolf.net", license="MPL-2.0",
        kind="dnf", key_dir="librewolf",
        fingerprints=("662E3CDD6FE329002D0CA5BB40339DD82B12EF16",), signer="LibreWolf Maintainers",
        spec={"repo_id": "librewolf", "name": "LibreWolf",
              "baseurl": "https://repo.librewolf.net", "repo_gpgcheck": True,
              "packages": ("librewolf",)},
    ),
    # ---------------------------------------------------------- messengers --
    App(
        id="element", title="Element", category="messenger",
        summary="Client for Matrix: decentralised, end-to-end encrypted chat and calls.",
        homepage="https://element.io", license="AGPL-3.0 or GPL-3.0",
        kind="apt", key_dir="element",
        fingerprints=("12D4CD600C2240A9F4A82071D7B0B66941D01538",), signer="Element (riot.im packages)",
        spec={"repo": "https://packages.element.io/debian", "dist": "default", "component": "main",
              "package": "element-desktop",
              "exec": "opt/Element/element-desktop",
              "icon": "usr/share/icons/hicolor/512x512/apps/element-desktop.png",
              # Chromium's setuid helper cannot work in a per-user install; without it
              # the namespace sandbox is used, which Fedora supports.
              "delete": ("opt/Element/chrome-sandbox",)},
        arch={"x86_64": "amd64", "aarch64": "arm64"},
    ),
    App(
        id="simplex", title="SimpleX Chat", category="messenger",
        summary="Messenger with no user identifiers at all — not even random ones.",
        homepage="https://simplex.chat", license="AGPL-3.0",
        kind="flatpak", key_dir="flathub",
        fingerprints=("6E5C05D979C76DAF93C081354184DD4D907A7CAE",),
        signer="Flathub (build verified by simplex.chat)",
        spec={"ref": "chat.simplex.simplex"},
    ),
]

BY_ID = {app.id: app for app in CATALOG}
