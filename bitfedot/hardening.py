"""Fedora security and privacy hardening.

Read-only checks run unprivileged. Everything that changes the system goes
through `as_root()`: one polkit prompt, one short shell script whose every
argument is validated here first. Nothing in this module runs as root on its
own, and nothing is changed unless the user flips the corresponding switch.

  * Security check-up     SELinux, firewall, disk encryption, Secure Boot, …
  * Strict firewall       a dedicated firewalld zone with all inbound closed
  * VPN kill switch       nftables: no traffic may leave except through the VPN
  * Fedora updates        check / install, optional automatic security updates
"""
import ipaddress
import os
import re
import shlex
import time
from pathlib import Path

from . import paths, services, settings, system
from .system import run

FW_ZONE = "bitfedot"
KS_TABLE = "bitfedot_killswitch"
KS_UNIT = "bitfedot-killswitch.service"
KS_RULES = "/etc/bitfedot/killswitch.nft"
AUTO_TIMER = "dnf5-automatic.timer"
AUTO_CONF = "/etc/dnf/dnf5-plugins/automatic.conf"
_IFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_ZONE = re.compile(r"^[A-Za-z0-9_-]{1,17}$")


# -------------------------------------------------------------- privilege --
def as_root(lines, timeout=1800):
    """Run shell `lines` as root in one polkit-authenticated batch (set -e)."""
    if system.DRY_RUN:
        return
    script = "set -eu\n" + "\n".join(lines) + "\n"
    p = run(["pkexec", "/bin/sh", "-c", script], timeout=timeout)
    if p.returncode in (126, 127):
        raise RuntimeError("Administrator authentication was cancelled.")
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip()[-600:] or "The privileged step failed.")


def _sh(*args) -> str:
    return shlex.join(str(a) for a in args)


def _install_file(path, content, mode="644") -> list:
    """Shell lines that write `content` to a root-owned `path`."""
    marker = "BITFEDOT_EOF"
    assert marker not in content
    return [_sh("install", "-d", "-m", "755", os.path.dirname(path)),
            f"cat > {shlex.quote(path)} <<'{marker}'\n{content.rstrip()}\n{marker}",
            _sh("chmod", mode, path)]


# --------------------------------------------------------------- firewall --
def firewall_status() -> dict:
    """State of firewalld as far as an unprivileged user can see it."""
    st = {"available": system.have("firewall-cmd"), "running": False, "zone": "",
          "strict": False, "wide_open": False, "services": [], "ports": []}
    if not st["available"]:
        return st
    st["running"] = run(["firewall-cmd", "--state"], timeout=10).stdout.strip() == "running"
    if not st["running"]:
        return st
    st["zone"] = run(["firewall-cmd", "--get-default-zone"], timeout=10).stdout.strip()
    st["services"] = run(["firewall-cmd", "--list-services"], timeout=10).stdout.split()
    st["ports"] = run(["firewall-cmd", "--list-ports"], timeout=10).stdout.split()
    st["strict"] = st["zone"] == FW_ZONE
    # Fedora Workstation's default zone accepts every port from 1025 upwards.
    st["wide_open"] = any(p.split("/")[0].startswith("1025-") for p in st["ports"])
    st["p2p_open"] = st["wide_open"] or f"{paths.P2P_PORT}/tcp" in st["ports"]
    return st


def firewall_script(s, enable: bool, current_zone: str) -> list:
    """Shell lines that switch the strict zone on or off."""
    if enable:
        want_p2p = services.clearnet_inbound(s)
        z = f"--zone={FW_ZONE}"
        return [
            f"firewall-cmd --permanent --new-zone={FW_ZONE} 2>/dev/null || true",
            f"firewall-cmd --permanent {z} --add-service=dhcpv6-client",
            f"firewall-cmd --permanent {z} --{'add' if s['fw_allow_ssh'] else 'remove'}-service=ssh",
            f"firewall-cmd --permanent {z} --{'add' if want_p2p else 'remove'}-port={paths.P2P_PORT}/tcp",
            "firewall-cmd --reload",
            f"firewall-cmd --set-default-zone={FW_ZONE}",
        ]
    back = s["fw_prev_zone"] if _ZONE.match(s["fw_prev_zone"] or "") else "FedoraWorkstation"
    return [
        f"firewall-cmd --set-default-zone={back} || firewall-cmd --set-default-zone=public",
        f"firewall-cmd --permanent --delete-zone={FW_ZONE} 2>/dev/null || true",
        "firewall-cmd --reload",
    ]


def set_strict_firewall(enable: bool, allow_ssh=None):
    """Move this computer into (or out of) a zone where nothing inbound is
    accepted except what the node itself needs."""
    st = firewall_status()
    if not st["running"]:
        raise RuntimeError("firewalld is not running. Enable it with: sudo systemctl enable --now firewalld")
    changes = {"fw_strict": enable}
    if allow_ssh is not None:
        changes["fw_allow_ssh"] = allow_ssh
    if enable and not st["strict"]:
        changes["fw_prev_zone"] = st["zone"]       # remembered for switching back
    s = {**settings.load(), **changes}
    as_root(firewall_script(s, enable, st["zone"]))
    settings.update(**changes)


def sync_firewall():
    """Re-apply the strict zone after a setting that affects it changed
    (inbound clearnet peers on/off). No-op unless strict mode is on."""
    s = settings.load()
    if s["fw_strict"] and firewall_status()["strict"]:
        as_root(firewall_script(s, True, FW_ZONE))


def firewall_out_of_sync(s) -> bool:
    """Strict zone is active but its P2P port no longer matches the settings."""
    st = firewall_status()
    return bool(st["strict"]) and (f"{paths.P2P_PORT}/tcp" in st["ports"]) != services.clearnet_inbound(s)


# ------------------------------------------------------------ kill switch --
def parse_endpoints(text: str):
    """'1.2.3.4, 2001:db8::/32' -> ([v4 networks], [v6 networks]); raises ValueError."""
    v4, v6 = [], []
    for item in re.split(r"[\s,;]+", text.strip()):
        if item:
            net = ipaddress.ip_network(item, strict=False)
            (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6


def killswitch_rules(iface: str, allow_lan=True, endpoints="") -> str:
    """nftables ruleset: everything this machine sends must leave through
    `iface`. Lives in its own table, so it coexists with firewalld."""
    if not _IFACE.match(iface or ""):
        raise ValueError("Choose a VPN interface first.")
    v4, v6 = parse_endpoints(endpoints)
    rules = [
        'oifname "lo" accept',
        f'oifname "{iface}" accept',
        # VPN daemons (WireGuard, NetworkManager, Mullvad, …) mark the encrypted
        # packets that carry the tunnel itself; ordinary programs cannot set marks.
        'meta mark != 0 accept comment "the VPN tunnel itself"',
        'udp dport { 67, 547 } accept comment "DHCP"',
        'ip6 daddr { fe80::/10, ff00::/8 } accept comment "IPv6 neighbour discovery"',
    ]
    if allow_lan:
        rules += ['ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, '
                  '224.0.0.0/4 } accept comment "local network"',
                  'ip6 daddr fc00::/7 accept comment "local network"']
    if v4:
        rules.append(f'ip daddr {{ {", ".join(v4)} }} accept comment "VPN servers"')
    if v6:
        rules.append(f'ip6 daddr {{ {", ".join(v6)} }} accept comment "VPN servers"')
    rules.append("counter reject with icmpx type admin-prohibited")
    body = "\n".join("        " + r for r in rules)
    return f"""# Managed by BitFedot — VPN kill switch. Remove with:
#   sudo systemctl disable --now {KS_UNIT}
table inet {KS_TABLE}
delete table inet {KS_TABLE}
table inet {KS_TABLE} {{
    chain output {{
        type filter hook output priority filter + 10; policy accept;
{body}
    }}
}}
"""


KS_UNIT_TEXT = f"""# Managed by BitFedot
[Unit]
Description=BitFedot VPN kill switch (blocks traffic that bypasses the VPN)
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f {KS_RULES}
ExecStop=/usr/sbin/nft delete table inet {KS_TABLE}

[Install]
WantedBy=multi-user.target
"""


def killswitch_active() -> bool:
    return run(["systemctl", "is-active", KS_UNIT], timeout=10).stdout.strip() == "active"


def set_killswitch(enable: bool, iface="", allow_lan=True, endpoints=""):
    """Install/remove the system-wide kill switch (persists across reboots)."""
    if enable:
        rules = killswitch_rules(iface, allow_lan, endpoints)   # validates all input
        as_root(_install_file(KS_RULES, rules, "600")
                + _install_file(f"/etc/systemd/system/{KS_UNIT}", KS_UNIT_TEXT)
                + ["systemctl daemon-reload", f"systemctl enable {KS_UNIT}",
                   f"systemctl restart {KS_UNIT}"])
        settings.update(killswitch=True, ks_iface=iface, ks_allow_lan=allow_lan,
                        ks_endpoints=endpoints)
    else:
        as_root([f"systemctl disable --now {KS_UNIT} 2>/dev/null || true",
                 f"nft delete table inet {KS_TABLE} 2>/dev/null || true",
                 f"rm -f {KS_RULES} /etc/systemd/system/{KS_UNIT}",
                 "systemctl daemon-reload"])
        settings.update(killswitch=False)


# ---------------------------------------------------------- Fedora updates --
def _count_packages(output: str) -> int:
    return sum(1 for line in output.splitlines()
               if len(line.split()) >= 3 and "." in line.split()[0] and not line.startswith(" "))


def check_os_updates() -> dict:
    """Ask dnf what it would upgrade (no root, nothing is changed)."""
    all_ = run(["dnf", "-q", "check-upgrade", "--refresh"], timeout=600)
    if all_.returncode not in (0, 100):
        raise RuntimeError((all_.stderr or all_.stdout).strip()[-300:] or "dnf check-upgrade failed")
    sec = run(["dnf", "-q", "check-upgrade", "--security"], timeout=600)
    info = {"count": _count_packages(all_.stdout) if all_.returncode == 100 else 0,
            "security": _count_packages(sec.stdout) if sec.returncode == 100 else 0,
            "reboot": reboot_needed(), "checked": int(time.time())}
    settings.update(os_updates=info)
    return info


def reboot_needed() -> bool:
    """dnf5: exit status 1 when updated core components need a reboot."""
    return run(["dnf", "-q", "needs-restarting"], timeout=120).returncode == 1


def install_os_updates(security_only=False):
    """Returns warnings to show before the next restart (hardware-key boot support)."""
    as_root(["dnf upgrade -y --refresh" + (" --security" if security_only else "")], timeout=7200)
    check_os_updates()
    from . import hardware_keys
    return [text for _sev, text in hardware_keys.health()]


def auto_updates_enabled() -> bool:
    return run(["systemctl", "is-enabled", AUTO_TIMER], timeout=10).stdout.strip() == "enabled"


def set_auto_updates(enable: bool):
    """Unattended *security* updates through Fedora's dnf5 automatic plugin.
    Never reboots by itself."""
    if enable:
        conf = "[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"
        as_root(["dnf install -y dnf5-plugin-automatic"]
                + _install_file(AUTO_CONF, "# Managed by BitFedot\n" + conf)
                + [f"systemctl enable --now {AUTO_TIMER}"])
    else:
        as_root([f"systemctl disable --now {AUTO_TIMER}"])


# ---------------------------------------------------------------- check-up --
def _encrypted(path) -> bool:
    src = run(["findmnt", "-no", "SOURCE", "-T", system.existing_parent(path)], timeout=10).stdout.strip()
    src = src.split("[")[0]           # btrfs subvolume suffix
    if not src:
        return False
    return "crypt" in run(["lsblk", "-sno", "TYPE", src], timeout=10).stdout.split()


def _secure_boot():
    """True / False, or None when it cannot be determined (legacy BIOS, VM)."""
    try:
        var = next(Path("/sys/firmware/efi/efivars").glob("SecureBoot-*"))
        return var.read_bytes()[4] == 1
    except (StopIteration, OSError, IndexError):
        return None


def checkup(s) -> list:
    """-> [{'title', 'ok': True | False | None (informational), 'detail'}]"""
    fw = firewall_status()
    items = []

    def add(title, ok, good, bad):
        items.append({"title": title, "ok": ok, "detail": good if ok else bad})

    selinux = run(["getenforce"], timeout=10).stdout.strip()
    add("SELinux", selinux == "Enforcing", "Enforcing",
        f"{selinux or 'Unavailable'} — set SELINUX=enforcing in /etc/selinux/config")
    add("Firewall", fw["running"], f"firewalld is active (zone “{fw['zone']}”)",
        "firewalld is not running — enable it with: sudo systemctl enable --now firewalld")
    if fw["running"]:
        add("Inbound ports", not fw["wide_open"],
            "Only explicitly allowed services are reachable",
            "This zone accepts connections on every port from 1025 up (the Fedora Workstation "
            "default). Turn on the strict firewall below.")
    add("Disk encryption", _encrypted(s["data_dir"]), "Node data is on an encrypted (LUKS) volume",
        "Node data is not on an encrypted volume; anyone with the disk can read your wallet "
        "labels and onion keys")
    sb = _secure_boot()
    if sb is not None:
        add("Secure Boot", sb, "Enabled", "Disabled in firmware setup")
    add("Service sandbox", bool(s["sandbox"]), "Every service runs in a systemd sandbox",
        "Switched off below")
    add("Automatic security updates", auto_updates_enabled(), "Fedora security updates install "
        "by themselves", "Off — you install updates manually (see Updates)")
    if run(["systemctl", "is-active", "sshd"], timeout=10).stdout.strip() == "active":
        items.append({"title": "SSH server", "ok": None,
                      "detail": "sshd is running. Make sure it uses key authentication only."})
    from . import hardware_keys          # optional feature; only reported once keys are set up
    hw = hardware_keys.state(s)
    if any(hw.get(r) for r in hardware_keys.ROLES):
        problems = hardware_keys.health(hw=hw)
        add("Hardware keys", not problems, "Boot and login settings for your keys are intact",
            " ".join(text for _sev, text in problems))
    if s["killswitch"] or killswitch_active():
        active = killswitch_active()
        add("VPN kill switch", active, f"Active on {s['ks_iface']}", "Configured but not loaded")
    return items
