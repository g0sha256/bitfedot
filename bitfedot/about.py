"""Who made this, who it stands on, and the Bitcoin whitepaper.

Pure data plus one helper, used by the About page and mirrored in THANKS.md.
"""
import hashlib
import shutil
from pathlib import Path

from . import paths

AUTHOR = "G0SHA256"
AUTHOR_URL = "https://github.com/G0SHA256"
REPO_URL = "https://github.com/G0SHA256/bitfedot"
ISSUES_URL = REPO_URL + "/issues"
LICENSE_NAME = "The Unlicense (public domain)"
LICENSE_URL = "https://unlicense.org"
LICENSE_SUMMARY = ("BitFedot is released into the public domain. Copy it, change it, sell it, ship it "
                   "inside something else — no permission, no attribution, no conditions.")

# The paper that started it all, bundled so it can be read and saved offline.
WHITEPAPER = paths.ASSETS_DIR / "docs" / "bitcoin.pdf"
WHITEPAPER_SHA256 = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553"
WHITEPAPER_FILENAME = "Bitcoin - A Peer-to-Peer Electronic Cash System (Satoshi Nakamoto, 2008).pdf"

SATOSHI = ("Satoshi Nakamoto", "https://bitcoin.org/bitcoin.pdf",
           "For Bitcoin: for the idea, the first implementation, and for walking away and leaving "
           "it to everyone. None of this would exist otherwise.")

# (name, url, what BitFedot uses it for)
THANKS = [
    ("Bitcoin Core", "https://bitcoincore.org", "The node itself — and every contributor and Guix "
                                                "builder who signs its releases"),
    ("Fulcrum", "https://github.com/cculianu/Fulcrum", "Electrum server, by Calin Culianu"),
    ("Mempool", "https://github.com/mempool/mempool", "Block explorer backend and the API behind the "
                                                      "Explorer page"),
    ("Tor", "https://www.torproject.org", "Network privacy, onion services, Tor Browser"),
    ("Sparrow Wallet", "https://sparrowwallet.com", "Desktop wallet, by Craig Raw"),
    ("Mullvad", "https://mullvad.net", "VPN and Mullvad Browser"),
    ("Obscura", "https://obscura.com", "Two-party VPN"),
    ("LibreWolf", "https://librewolf.net", "Privacy-hardened Firefox"),
    ("Element and Matrix", "https://element.io", "Decentralised encrypted messaging"),
    ("SimpleX Chat", "https://simplex.chat", "Messaging without identifiers"),
    ("Fedora", "https://fedoraproject.org", "The operating system this is built for"),
    ("GNOME: GTK, libadwaita, PyGObject", "https://www.gnome.org", "The entire user interface"),
    ("systemd", "https://systemd.io", "Runs and sandboxes every service"),
    ("Podman", "https://podman.io", "Rootless containers for Mempool"),
    ("MariaDB", "https://mariadb.org", "Mempool's database"),
    ("firewalld and nftables", "https://firewalld.org", "Strict firewall zone and the VPN kill switch"),
    ("GnuPG", "https://gnupg.org", "Every signature check"),
    ("curl", "https://curl.se", "Every download, also through Tor"),
    ("Flatpak and Flathub", "https://flathub.org", "Delivery of sandboxed apps"),
    ("Python", "https://www.python.org", "The language all of this is written in"),
]


def save_whitepaper(folder) -> Path:
    """Copy the bundled whitepaper into `folder` (after checking it is the
    genuine file) and return the path written."""
    data = WHITEPAPER.read_bytes()
    if hashlib.sha256(data).hexdigest() != WHITEPAPER_SHA256:
        raise RuntimeError("The bundled whitepaper does not match its known SHA-256 hash.")
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / WHITEPAPER_FILENAME
    tmp = target.with_suffix(".part")
    tmp.write_bytes(data)
    shutil.move(str(tmp), str(target))
    return target
