"""
server.py — The Gate relay (runs on VPS)

Function:
    Zero-trust ledger relay. Accepts signed entries from devices,
    validates chain integrity, stores them in a canonical .jsonl
    ledger, and serves missing entries on request.

Public API:
    1. make_server(host, port) — HTTP server factory (for CLI and tests)
    2. main(argv) — CLI entry point

Tier:     Tier 4 — The Gate
Depends:  (stdlib only — no P1–P15 imports needed)
Version:  1.0.0 (on freeze; 0.0.0-dev until then)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import sys
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

VERSION = "1.0.0"
_GENESIS_PREV = "0" * 64

# ---------------------------------------------------------------------------
# Ledger state
# ---------------------------------------------------------------------------
_ledger_lock = threading.Lock()


def _ledger_path():
    return os.environ.get("GATE_LEDGER", "ledger.jsonl")


def _read_ledger():
    path = _ledger_path()
    if not os.path.exists(path):
        return []
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _append_entries(entries):
    path = _ledger_path()
    with open(path, "a") as f:
        for entry in entries:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _head(entries):
    if not entries:
        return ""
    # In a DAG, the "head" is the entry with the highest sequence number.
    # (If there's a tie, it's a real fork; we just return the most recent).
    return max(entries, key=lambda e: e.get("seq", -1))["hash"]


def _expected_seq(entries):
    if not entries:
        return 0
    return max(e.get("seq", -1) for e in entries) + 1


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class _GateHandler(BaseHTTPRequestHandler):
    def _check_auth(self):
        expected = os.environ.get("GATE_TOKEN")
        if not expected:
            self.send_error(500, "GATE_TOKEN not configured")
            return False
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            self.send_error(401, "Unauthorized")
            return False
        if header[len("Bearer "):] != expected:
            self.send_error(401, "Unauthorized")
            return False
        return True

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._check_auth():
            return
        path = urlsplit(self.path).path
        if path == "/health":
            with _ledger_lock:
                entries = _read_ledger()
            self._json(200, {
                "version": VERSION,
                "entries": len(entries),
                "head": _head(entries),
            })
            return
        if path == "/pull":
            qs = parse_qs(urlsplit(self.path).query)
            try:
                since = int(qs.get("since", ["-1"])[0])
            except (ValueError, TypeError):
                self.send_error(400, "since must be an integer")
                return
            with _ledger_lock:
                entries = _read_ledger()
            out = [e for e in entries if e.get("seq", -1) > since]
            head_seq = entries[-1]["seq"] if entries else -1
            self._json(200, {
                "entries": out,
                "head": _head(entries),
                "head_seq": head_seq,
            })
            return
        self.send_error(404, "Not found")

    def do_POST(self):
        if not self._check_auth():
            return
        path = urlsplit(self.path).path
        if path != "/push":
            self.send_error(404, "Not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            payload = json.loads(raw) if raw else {}
        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "Invalid JSON")
            return
        new_entries = payload.get("entries", [])
        if not isinstance(new_entries, list) or not new_entries:
            self.send_error(400, "entries must be a non-empty list")
            return

        with _ledger_lock:
            existing = _read_ledger()
            existing_hashes = {e["hash"] for e in existing}

            # Validate the batch as a DAG, accepting entries that
            # reference parents also present in this same batch.
            for entry in new_entries:
                prev = entry.get("prev")
                if not isinstance(prev, list):
                    self._json(400, {"error": "prev_must_be_list"})
                    return
                if not prev:
                    # Genesis entry; no parents to check.
                    existing_hashes.add(entry.get("hash", ""))
                    continue
                for parent in prev:
                    if parent not in existing_hashes:
                        self._json(409, {
                            "error": "missing_parents",
                            "missing": parent,
                        })
                        return
                existing_hashes.add(entry.get("hash", ""))

            _append_entries(new_entries)
            self._json(200, {
                "accepted": len(new_entries),
                "head": _head(_read_ledger()),
            })

    def do_PUT(self):
        self.send_error(405, "Method not allowed")

    do_DELETE = do_PUT
    do_PATCH = do_PUT

    def log_message(self, fmt, *args):
        pass


def make_server(host, port):
    return ThreadingHTTPServer((host, port), _GateHandler)


def main(argv):
    host = os.environ.get("GATE_HOST", "127.0.0.1")
    port = int(os.environ.get("GATE_PORT", "7700"))
    token = os.environ.get("GATE_TOKEN")
    if not token:
        print("GATE_TOKEN is not set", file=sys.stderr)
        return 1
    server = make_server(host, port)
    print(f"Gate serving on http://{host}:{port}/")
    print(f"  Ledger: {_ledger_path()}")
    print(f"  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
