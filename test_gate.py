"""
test_gate.py — The Gate test suite

Function:
    Tests server.py (relay endpoints) and client.py (sync commands)
    against real sockets. P6 verification is exercised on pull.

Tier:    Tier 4 — The Gate
Spec:    SPEC.md v1.0.0
Licence: MSL-1.0
"""

import os
import sys
import json
import socket
import tempfile
import threading
import time
import pytest
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = os.path.dirname(os.path.abspath(__file__))
for layer in ("envelope-layer", "sign-layer", "ledger-layer", "genesis-layer", "canon-verify-layer"):
    p = os.path.abspath(os.path.join(ROOT, "..", layer))
    if os.path.isdir(p):
        sys.path.insert(0, p)

import envelope_v2 as envelope
import ledger as ledger_mod
import server
import client


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def temp_ledger():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def test_gate_server(tmp_path, monkeypatch):
    """Start a real Gate server on an ephemeral port with an isolated ledger."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    gate_dir = tmp_path / "gate"
    gate_dir.mkdir()
    gate_ledger = str(gate_dir / "ledger.jsonl")

    monkeypatch.setenv("GATE_TOKEN", "test-token")
    monkeypatch.setenv("GATE_LEDGER", gate_ledger)

    srv = server.make_server("127.0.0.1", port)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}", gate_ledger

    srv.shutdown()
    srv.server_close()
    thread.join(timeout=2)


def _make_entry(seq, prev, record, key):
    """Helper: build a signed ledger entry."""
    did = envelope.did_key_encode(key.public_key())
    unsigned = {"seq": seq, "prev": prev, "record": record, "signer": did}
    canonical = envelope.canonical_bytes(unsigned)
    entry_hash = envelope.sha256_hex(canonical)
    digest = envelope.sha256_digest(canonical)
    sig = envelope.sign_bytes(digest, key)
    return {
        "seq": seq, "prev": prev, "record": record, "signer": did,
        "hash": entry_hash, "signature": sig.hex(),
    }


# ── Server: health ─────────────────────────────────────────────────────
def test_health_empty_gate(test_gate_server):
    url, _ = test_gate_server
    req = urllib.request.Request(url + "/health", headers={"Authorization": "Bearer test-token"})
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read())
    assert data["entries"] == 0
    assert data["head"] == ""
    assert data["version"] == "1.0.0"


def test_health_requires_token(test_gate_server):
    url, _ = test_gate_server
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(url + "/health")
    assert exc.value.code == 401


# ── Server: push ───────────────────────────────────────────────────────
def test_push_valid_genesis(test_gate_server, key):
    url, ledger_path = test_gate_server
    genesis = _make_entry(0, "0" * 64, {"data": "first"}, key)
    body = json.dumps({"entries": [genesis]}).encode()
    req = urllib.request.Request(
        url + "/push", data=body, method="POST",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read())
    assert data["accepted"] == 1
    assert data["head"] == genesis["hash"]
    assert os.path.exists(ledger_path)
    with open(ledger_path) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert len(lines) == 1
    assert lines[0]["seq"] == 0


def test_push_requires_token(test_gate_server, key):
    url, _ = test_gate_server
    genesis = _make_entry(0, "0" * 64, {"data": "first"}, key)
    body = json.dumps({"entries": [genesis]}).encode()
    req = urllib.request.Request(url + "/push", data=body, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 401


def test_push_wrong_prev_is_409(test_gate_server, key):
    url, _ = test_gate_server
    bad = _make_entry(0, "f" * 64, {"data": "first"}, key)
    body = json.dumps({"entries": [bad]}).encode()
    req = urllib.request.Request(
        url + "/push", data=body, method="POST",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 409
    err = json.loads(exc.value.read())
    assert err["error"] == "chain_mismatch"
    assert err["expected_prev"] == "0" * 64
    assert err["expected_seq"] == 0


def test_push_wrong_seq_is_409(test_gate_server, key):
    url, ledger_path = test_gate_server
    genesis = _make_entry(0, "0" * 64, {"data": "first"}, key)
    body = json.dumps({"entries": [genesis]}).encode()
    req = urllib.request.Request(
        url + "/push", data=body, method="POST",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    )
    urllib.request.urlopen(req)

    skipped = _make_entry(2, genesis["hash"], {"data": "third"}, key)
    body2 = json.dumps({"entries": [skipped]}).encode()
    req2 = urllib.request.Request(
        url + "/push", data=body2, method="POST",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req2)
    assert exc.value.code == 409
    err = json.loads(exc.value.read())
    assert err["expected_seq"] == 1


def test_push_chain_is_atomic(test_gate_server, key):
    url, _ = test_gate_server
    e0 = _make_entry(0, "0" * 64, {"data": "first"}, key)
    e2 = _make_entry(2, e0["hash"], {"data": "third"}, key)  # wrong seq
    body = json.dumps({"entries": [e0, e2]}).encode()
    req = urllib.request.Request(
        url + "/push", data=body, method="POST",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 409
    # No partial appends
    resp = urllib.request.urlopen(urllib.request.Request(
        url + "/health", headers={"Authorization": "Bearer test-token"}
    ))
    assert json.loads(resp.read())["entries"] == 0


# ── Server: pull ───────────────────────────────────────────────────────
def test_pull_empty(test_gate_server):
    url, _ = test_gate_server
    req = urllib.request.Request(url + "/pull?since=0", headers={"Authorization": "Bearer test-token"})
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read())
    assert data["entries"] == []


def test_pull_after_push(test_gate_server, key):
    url, _ = test_gate_server
    e0 = _make_entry(0, "0" * 64, {"data": "first"}, key)
    body = json.dumps({"entries": [e0]}).encode()
    urllib.request.urlopen(urllib.request.Request(
        url + "/push", data=body, method="POST",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    ))

    req = urllib.request.Request(url + "/pull?since=-1", headers={"Authorization": "Bearer test-token"})
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read())
    assert len(data["entries"]) == 1
    assert data["entries"][0]["seq"] == 0
    assert data["head"] == e0["hash"]


def test_pull_since_filters(test_gate_server, key):
    url, _ = test_gate_server
    e0 = _make_entry(0, "0" * 64, {"data": "first"}, key)
    e1 = _make_entry(1, e0["hash"], {"data": "second"}, key)
    e2 = _make_entry(2, e1["hash"], {"data": "third"}, key)
    body = json.dumps({"entries": [e0, e1, e2]}).encode()
    urllib.request.urlopen(urllib.request.Request(
        url + "/push", data=body, method="POST",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    ))

    req = urllib.request.Request(url + "/pull?since=0", headers={"Authorization": "Bearer test-token"})
    resp = urllib.request.urlopen(req)
    entries = json.loads(resp.read())["entries"]
    assert len(entries) == 2
    assert entries[0]["seq"] == 1
    assert entries[1]["seq"] == 2


# ── Client: status / push / pull / sync ────────────────────────────────
def test_client_status_empty(test_gate_server, tmp_path, monkeypatch):
    url, gate_ledger = test_gate_server
    forge_home = tmp_path / "client"
    forge_home.mkdir()
    monkeypatch.setenv("GATE_URL", url)
    monkeypatch.setenv("GATE_TOKEN", "test-token")
    monkeypatch.setenv("FORGE_HOME", str(forge_home))

    # Client's local ledger is empty
    status = client.status()
    assert status["local_head_seq"] == -1
    assert status["remote_head_seq"] == -1
    assert status["pending_pull"] == 0
    assert status["pending_push"] == 0


def test_client_push_then_pull(test_gate_server, tmp_path, key, monkeypatch):
    url, gate_ledger = test_gate_server
    forge_home = tmp_path / "device_a"
    forge_home.mkdir()
    local_ledger = os.path.join(str(forge_home), "ledger.jsonl")

    # Write a genesis entry to the client's local ledger
    e0 = _make_entry(0, "0" * 64, {"data": "hello"}, key)
    with open(local_ledger, "w") as f:
        f.write(json.dumps(e0, separators=(",", ":")) + "\n")

    monkeypatch.setenv("GATE_URL", url)
    monkeypatch.setenv("GATE_TOKEN", "test-token")
    monkeypatch.setenv("FORGE_HOME", str(forge_home))

    # Push
    client.push()
    # Gate should now have 1 entry
    req = urllib.request.Request(url + "/health", headers={"Authorization": "Bearer test-token"})
    resp = urllib.request.urlopen(req)
    assert json.loads(resp.read())["entries"] == 1

    # Simulate a second device with empty local ledger
    second_home = tmp_path / "device_b"
    second_home.mkdir()
    second_ledger = os.path.join(str(second_home), "ledger.jsonl")
    monkeypatch.setenv("FORGE_HOME", str(second_home))
    client.pull()
    assert os.path.exists(second_ledger)
    with open(second_ledger) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert len(lines) == 1
    assert lines[0]["seq"] == 0
    assert lines[0]["hash"] == e0["hash"]
