"""
client.py — The Gate client (runs on each device)

Function:
    Pushes local ledger entries to the Gate, pulls missing entries,
    verifies each pulled entry via P1 (recompute hash + verify
    signature), and appends to the local ledger and P8 store.

Public API:
    1. status() — read sync state
    2. push()   — push local entries to Gate
    3. pull()   — pull + verify remote entries
    4. sync()   — pull then push
    5. main(argv) — CLI entry point

Tier:     Tier 4 — The Gate
Depends:  P1 Envelope (verify), P8 Store (insert pulled entries)
Version:  1.0.0 (on freeze; 0.0.0-dev until then)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import sys
import json
import sqlite3
import urllib.request
import urllib.error

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "envelope-layer")))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "store-layer")))
import envelope_v2 as envelope
import store

_STATE_FILE = ".forge-gate-state.json"


def _forge_home():
    return os.environ.get("FORGE_HOME", os.path.expanduser("~/.forge"))


def _local_ledger_path():
    return os.path.join(_forge_home(), "ledger.jsonl")


def _local_db_path():
    return os.path.join(_forge_home(), "forge.db")


def _state_path():
    return os.path.join(_forge_home(), _STATE_FILE)


def _gate_url():
    url = os.environ.get("GATE_URL")
    if not url:
        raise RuntimeError("GATE_URL is not set")
    return url.rstrip("/")


def _gate_token():
    token = os.environ.get("GATE_TOKEN")
    if not token:
        raise RuntimeError("GATE_TOKEN is not set")
    return token


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def _load_state():
    path = _state_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_state(state):
    path = _state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Local ledger
# ---------------------------------------------------------------------------
def _read_local_ledger():
    path = _local_ledger_path()
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


def _append_local_ledger(entries):
    path = _local_ledger_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        for entry in entries:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# P8 store insert (idempotent)
# ---------------------------------------------------------------------------
def _insert_to_store(entries):
    db_path = _local_db_path()
    store.init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        for entry in entries:
            conn.execute(
                "INSERT OR IGNORE INTO ledger "
                "(seq, prev, record, signer, hash, signature) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry["seq"],
                    json.dumps(entry["prev"], separators=(",", ":")),  # list -> JSON text
                    json.dumps(entry["record"], sort_keys=True, separators=(",", ":")),
                    entry["signer"],
                    entry["hash"],
                    entry["signature"],
                ),
            )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Per-entry verification (via P1)
# ---------------------------------------------------------------------------
def _verify_entry(entry):
    try:
        unsigned = {
            "seq": entry["seq"],
            "prev": entry["prev"],
            "record": entry["record"],
            "signer": entry["signer"],
        }
        canonical = envelope.canonical_bytes(unsigned)
        actual_hash = envelope.sha256_hex(canonical)
        digest = envelope.sha256_digest(canonical)
    except (KeyError, TypeError) as e:
        return False, f"malformed entry: {e}"

    if actual_hash != entry.get("hash"):
        return False, f"hash mismatch at seq {entry['seq']}"

    try:
        pubkey = envelope.did_key_decode(entry["signer"])
        sig = bytes.fromhex(entry["signature"])
        if not envelope.verify_bytes(digest, sig, pubkey):
            return False, f"signature invalid at seq {entry['seq']}"
    except Exception as e:
        return False, f"verify error at seq {entry['seq']}: {e}"

    return True, ""


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def _http_get(path):
    req = urllib.request.Request(
        _gate_url() + path,
        headers={"Authorization": f"Bearer {_gate_token()}"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _http_post(path, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        _gate_url() + path,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {_gate_token()}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
def status():
    local = _read_local_ledger()
    local_seq = local[-1]["seq"] if local else -1
    state = _load_state()
    last_pulled = state.get("last_pulled", -1)
    last_pushed = state.get("last_pushed", -1)

    remote = _http_get("/health")
    remote_seq = remote["entries"] - 1 if remote["entries"] else -1

    return {
        "local_head_seq": local_seq,
        "remote_head_seq": remote_seq,
        "last_pulled": last_pulled,
        "last_pushed": last_pushed,
        "pending_pull": max(0, remote_seq - last_pulled),
        "pending_push": max(0, local_seq - last_pushed),
    }


# ---------------------------------------------------------------------------
# push
# ---------------------------------------------------------------------------
def push():
    local = _read_local_ledger()
    state = _load_state()
    last_pushed = state.get("last_pushed", -1)
    to_push = [e for e in local if e["seq"] > last_pushed]

    if not to_push:
        print("Nothing to push.")
        return 0

    try:
        resp = _http_post("/push", {"entries": to_push})
    except urllib.error.HTTPError as e:
        if e.code == 409:
            try:
                err = json.loads(e.read())
            except Exception:
                err = {"expected_seq": "?", "expected_prev": "?"}
            print(
                f"Conflict: Gate expected seq {err.get('expected_seq')}. "
                "Run `forge-gate pull` first, then re-run push.",
                file=sys.stderr,
            )
            return 2
        raise

    state["last_pushed"] = to_push[-1]["seq"]
    _save_state(state)
    print(f"Pushed {resp.get('accepted', len(to_push))} entries.")
    return 0


# ---------------------------------------------------------------------------
# pull
# ---------------------------------------------------------------------------
def pull():
    local = _read_local_ledger()
    local_seq = local[-1]["seq"] if local else -1
    state = _load_state()
    last_pushed = state.get("last_pushed", -1)

    # Always fetch entries we don't have locally.
    remote = _http_get(f"/pull?since={local_seq}")
    entries = remote.get("entries", [])
    head_seq = remote.get("head_seq", -1)

    if not entries:
        # Nothing new, but sync state to reflect server head.
        state["last_pulled"] = max(state.get("last_pulled", -1), head_seq)
        state["last_pushed"] = max(last_pushed, head_seq)
        _save_state(state)
        print("Already up to date.")
        return 0

    existing_hashes = {e["hash"] for e in local}

    verified = []
    for entry in entries:
        prev = entry.get("prev")
        if not isinstance(prev, list):
            print(f"ERROR: entry {entry.get('seq')} prev is not a list", file=sys.stderr)
            return 1
        if prev:
            missing = [p for p in prev if p not in existing_hashes]
            if missing:
                print(f"ERROR: entry {entry.get('seq')} missing parents: {missing}", file=sys.stderr)
                return 1
        ok, err = _verify_entry(entry)
        if not ok:
            print(f"ERROR: P6 rejected entry: {err}", file=sys.stderr)
            return 1
        verified.append(entry)
        existing_hashes.add(entry["hash"])

    _append_local_ledger(verified)
    _insert_to_store(verified)

    # After pull: server has everything up to head_seq, so mark both
    # last_pulled and last_pushed as at least head_seq. Anything we
    # have locally beyond that (server doesn't) is still pending push.
    state["last_pulled"] = max(state.get("last_pulled", -1), head_seq)
    state["last_pushed"] = max(last_pushed, head_seq)
    _save_state(state)
    print(f"Pulled {len(verified)} entries.")
    return 0


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------
def sync():
    rc = pull()
    if rc != 0:
        return rc
    return push()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv):
    if not argv:
        print("usage: forge-gate {status|push|pull|sync}", file=sys.stderr)
        return 2
    cmd = argv[0]
    try:
        if cmd == "status":
            s = status()
            for k, v in s.items():
                print(f"{k}: {v}")
            return 0
        elif cmd == "push":
            return push()
        elif cmd == "pull":
            return pull()
        elif cmd == "sync":
            return sync()
        else:
            print(f"unknown command: {cmd}", file=sys.stderr)
            return 2
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"network error: {e.reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
