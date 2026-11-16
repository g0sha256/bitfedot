"""Downloads and upstream version discovery, via curl so everything can be
routed through Tor's SOCKS port (with remote DNS) once Tor is up."""
import os
import re
import socket
import subprocess
import time

from . import paths
from .system import run

UA = "bitfedot"  # generic client name; no user details ever leave the machine


def tor_usable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", paths.TOR_SOCKS), timeout=1):
            return True
    except OSError:
        return False


def _base(use_tor: bool) -> list:
    cmd = ["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
           "--tlsv1.2", "--connect-timeout", "30", "--retry", "3", "-A", UA]
    if use_tor:
        cmd += ["--proxy", f"socks5h://127.0.0.1:{paths.TOR_SOCKS}"]
    return cmd


def proxy_env(use_tor: bool) -> dict:
    env = dict(os.environ)
    if use_tor:
        p = f"socks5h://127.0.0.1:{paths.TOR_SOCKS}"
        env.update(HTTPS_PROXY=p, HTTP_PROXY=p, ALL_PROXY=p)
    return env


def fetch_text(url: str, use_tor=False, timeout=90) -> str:
    return run(_base(use_tor) + ["--max-time", str(timeout), url], timeout=timeout + 10, check=True).stdout


def latest_tag(repo: str, use_tor=False) -> str:
    """Latest *stable* release tag of a GitHub repo. Uses the /releases/latest
    redirect (never points at pre-releases, no API rate limit)."""
    cmd = _base(use_tor)
    cmd.remove("--location")
    out = run(cmd + ["--max-time", "60", "-o", "/dev/null", "-w", "%{redirect_url}",
                     f"https://github.com/{repo}/releases/latest"], timeout=70, check=True).stdout
    m = re.search(r"/releases/tag/([^/?#\s]+)$", out.strip())
    if not m:
        raise RuntimeError(f"Could not determine the latest release of {repo}")
    return m.group(1)


def remote_size(url: str, use_tor=False):
    out = run(_base(use_tor) + ["--head", "--max-time", "60", url], timeout=70).stdout
    sizes = re.findall(r"(?im)^content-length:\s*(\d+)", out)
    return int(sizes[-1]) if sizes else None


def download(url: str, dest, progress=None, use_tor=False):
    """Download `url` to `dest` (resumable). progress(fraction | None)."""
    dest = str(dest)
    part = dest + ".part"
    total = remote_size(url, use_tor) if progress else None
    proc = subprocess.Popen(_base(use_tor) + ["--continue-at", "-", "-o", part, url],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    while proc.poll() is None:
        if progress:
            try:
                done = os.path.getsize(part)
            except OSError:
                done = 0
            progress(min(done / total, 1.0) if total else None)
        time.sleep(0.4)
    if proc.returncode != 0:
        err = (proc.stderr.read() or "").strip()
        raise RuntimeError(f"Download failed: {url}\n{err}")
    os.replace(part, dest)
    if progress:
        progress(1.0)


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0]))


def is_newer(latest: str, installed: str) -> bool:
    if not latest or not installed:
        return False
    return version_tuple(latest) > version_tuple(installed)
