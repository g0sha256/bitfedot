"""Minimal local clients: Bitcoin Core JSON-RPC, Tor control port, Electrum, HTTP."""
import base64
import http.client
import json
import socket
from pathlib import Path

from . import paths


class RPCError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class BitcoinRPC:
    def __init__(self, datadir, port=paths.RPC_PORT):
        self.cookie = Path(datadir) / ".cookie"
        self.port = port

    def call(self, method, *params, timeout=8):
        auth = base64.b64encode(self.cookie.read_bytes().strip()).decode()  # OSError if not running
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request("POST", "/", json.dumps({"jsonrpc": "1.0", "id": "ns", "method": method,
                                                  "params": list(params)}),
                         {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read()
        except http.client.HTTPException as e:
            # A reply cut short or garbled (Bitcoin Core stopping mid-answer) is not an OSError,
            # but for every caller it means the same: not answering right now.
            raise OSError(f"Bitcoin Core RPC: {type(e).__name__}") from e
        finally:
            conn.close()
        try:
            data = json.loads(body)
        except ValueError:
            raise RPCError(resp.status, f"HTTP {resp.status}")
        if data.get("error"):
            raise RPCError(data["error"].get("code"), data["error"].get("message", "RPC error"))
        return data["result"]


class TorControl:
    """Just enough of the control protocol: cookie auth, GETINFO, SIGNAL."""

    def __init__(self, port=paths.TOR_CONTROL, cookie=None):
        self.port = port
        self.cookie = Path(cookie or paths.TOR_DIR / "control_auth_cookie")

    def _session(self, *commands, timeout=5):
        replies = []
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as sock:
            f = sock.makefile("rw", newline="\r\n")
            for cmd in (f"AUTHENTICATE {self.cookie.read_bytes().hex()}", *commands):
                f.write(cmd + "\r\n")
                f.flush()
                lines = []
                while True:
                    line = f.readline()
                    if not line:
                        raise OSError("Tor control connection closed")
                    line = line.rstrip("\r\n")
                    lines.append(line)
                    if len(line) >= 4 and line[3] == " ":
                        break
                if not lines[-1].startswith("250"):
                    raise OSError(lines[-1])
                replies.append(lines)
        return replies[1:]

    def getinfo(self, *keys) -> dict:
        out = {}
        for lines in self._session(*(f"GETINFO {k}" for k in keys)):
            for line in lines:
                if line.startswith("250-") and "=" in line:
                    k, v = line[4:].split("=", 1)
                    out[k] = v
        return out

    def signal(self, name):
        self._session(f"SIGNAL {name}")


def electrum_height(port=paths.FULCRUM_PORT, timeout=2):
    """Tip height reported by the Electrum server, or None if it isn't serving yet."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(b'{"id":1,"method":"blockchain.headers.subscribe","params":[]}\n')
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    return None
                buf += chunk
        return int(json.loads(buf)["result"]["height"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def http_text(port, path="/", timeout=2, limit=4096):
    """Body of a local HTTP GET as text (its first `limit` bytes), or None if it did not
    answer with 200. Never raises: a garbled or truncated reply counts as no answer."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.read(limit).decode(errors="replace") if resp.status == 200 else None
        finally:
            conn.close()
    except (OSError, http.client.HTTPException):
        return None


def http_ok(port, path="/", timeout=2) -> bool:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request("GET", path)
            return conn.getresponse().status == 200
        finally:
            conn.close()
    except (OSError, http.client.HTTPException):
        return False
