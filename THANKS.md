# Thank you

BitFedot only arranges other people's work. It exists because of them.

## Satoshi Nakamoto

For Bitcoin: for the idea, the first implementation, and for walking away and leaving it to everyone. None of this would exist otherwise.

The whitepaper, *Bitcoin: A Peer-to-Peer Electronic Cash System* (2008), ships with this
repository at [`bitfedot/data/docs/bitcoin.pdf`](bitfedot/data/docs/bitcoin.pdf)
(SHA-256 `b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553`; published under the MIT licence) and can be saved from
the app's About page.

## Software BitFedot installs, runs or is built on

| Project | Used for |
|---|---|
| [Bitcoin Core](https://bitcoincore.org) | The node itself — and every contributor and Guix builder who signs its releases |
| [Fulcrum](https://github.com/cculianu/Fulcrum) | Electrum server, by Calin Culianu |
| [Mempool](https://github.com/mempool/mempool) | Block explorer backend and the API behind the Explorer page |
| [Tor](https://www.torproject.org) | Network privacy, onion services, Tor Browser |
| [Sparrow Wallet](https://sparrowwallet.com) | Desktop wallet, by Craig Raw |
| [Mullvad](https://mullvad.net) | VPN and Mullvad Browser |
| [Obscura](https://obscura.com) | Two-party VPN |
| [LibreWolf](https://librewolf.net) | Privacy-hardened Firefox |
| [Element and Matrix](https://element.io) | Decentralised encrypted messaging |
| [SimpleX Chat](https://simplex.chat) | Messaging without identifiers |
| [Fedora](https://fedoraproject.org) | The operating system this is built for |
| [GNOME: GTK, libadwaita, PyGObject](https://www.gnome.org) | The entire user interface |
| [systemd](https://systemd.io) | Runs and sandboxes every service; unlocks the disk with a hardware key (cryptenroll) and keeps the keyring credential |
| [Yubico: YubiKey Manager, libfido2, pam-u2f](https://developers.yubico.com) | Hardware-key setup, disk unlock, login and sudo with a key |
| [oo7](https://github.com/linux-credentials/oo7) | The desktop keyring that opens by itself after a key login |
| [dracut and Plymouth](https://github.com/dracut-ng/dracut-ng) | The boot image and the boot-time PIN prompt |
| [authselect](https://github.com/authselect/authselect) | Fedora's way to switch on hardware-key login |
| [Podman](https://podman.io) | Rootless containers for Mempool |
| [MariaDB](https://mariadb.org) | Mempool's database |
| [firewalld and nftables](https://firewalld.org) | Strict firewall zone and the VPN kill switch |
| [GnuPG](https://gnupg.org) | Every signature check |
| [curl](https://curl.se) | Every download, also through Tor |
| [Flatpak and Flathub](https://flathub.org) | Delivery of sandboxed apps |
| [Python](https://www.python.org) | The language all of this is written in |

Also: the [bitcoin-core/guix.sigs](https://github.com/bitcoin-core/guix.sigs) builders whose
independent signatures make verified installs possible, and everyone who runs a node.

Each project keeps its own licence; BitFedot downloads them from their authors and does
not redistribute them. Their names and marks belong to their owners. BitFedot is an
independent project and is not affiliated with or endorsed by any of them.
