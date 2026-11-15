# SPEC — forge-gate (Tier 4: The Gate)

SPEC.md — specification for The Gate, v1.0.0.

Function:
    Zero-trust ledger relay for multi-device sync. Runs on a VPS.
    Accepts signed entries from devices, stores them in one canonical
    `.jsonl` ledger, and serves missing entries on request.

Tier:     Tier 4 — The Gate
Depends:  P4 (Ledger .jsonl format), P6 (Canon Verify, client-side)
Version:  SPEC 1.0.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)

## 1. Server (`server.py`, runs on VPS)

Environment:
- GATE_TOKEN — shared secret, required at startup
- GATE_LEDGER — path to canonical `.jsonl` (default `./ledger.jsonl`)
- GATE_HOST — bind address (default 127.0.0.1, put behind a proxy)
- GATE_PORT — bind port (default 7700)

### Endpoints

**GET /health**
Returns 200 with JSON:
    {"version": "1.0.0", "entries": int, "head": "hex-or-empty"}

**POST /push**
Authorization: Bearer <GATE_TOKEN>
Body:
    {"entries": [<entry>, <entry>, ...]}
Each entry is a P4-format signed ledger entry.
Server validates:
- Every entry's `prev` matches the previous entry's `hash` in the
  submitted batch, or the current server head for the first entry.
- The `seq` of the first entry is exactly current_server_seq + 1.
If validation passes, appends all entries to canonical ledger and
returns 200 with:
    {"accepted": int, "head": "hex"}
If validation fails, returns 409 with:
    {"error": "chain_mismatch", "expected_prev": "hex", "expected_seq": int}
No partial appends. All-or-nothing per request.

**GET /pull?since=<seq>**
Authorization: Bearer <GATE_TOKEN>
Returns 200 with JSON:
    {"entries": [<entry>, <entry>, ...], "head": "hex"}
Entries are all canonical entries with `seq > since`, in order.

## 2. Client (`client.py`, runs on every device)

Environment:
- GATE_URL — required (e.g. `https://gate.example.com`)
- GATE_TOKEN — required
- FORGE_HOME — local forge home (default `~/.forge`)

State file: `$FORGE_HOME/.forge-gate-state.json`
    {"last_pulled": int, "last_pushed": int}

### Commands

**forge-gate status**
- Reads local ledger head seq (from `$FORGE_HOME/ledger.jsonl`)
- Reads remote head seq (GET /health)
- Prints: local, remote, synced (bool), pending push, pending pull

**forge-gate push**
- Reads local ledger entries with seq > last_pushed
- POST /push
- On 200: updates last_pushed
- On 409: prints "pull required" and exits 2 (usage-ish; not a bug)

**forge-gate pull**
- GET /pull?since=<last_pulled>
- For each returned entry, verify via P6 (canon_verify.verify_ledger
  against an in-memory temp file containing current local + new)
  OR verify individually by re-computing hash and checking signature
  against the entry's signer.
- On success, appends to local ledger and to P8 store.
- On failure, does NOT append; prints "P6 rejected entry <seq>" and
  exits 1.

**forge-gate sync**
- Runs pull, then push.

## 3. Conflict model

The canonical ledger is a single hash chain. Two devices pushing at
the same time cannot both succeed unless their chains agree. The
Gate serialises: first push wins, second gets 409.

A device that receives 409 must pull first, then re-apply its local
entries on top of the new head. This is a manual step in v1.0.0
(the user re-runs `forge-gate sync` after the conflict resolves).

## 4. Known limitations (v1.0.0)

- No per-device tokens. One shared bearer token.
- No push rate limiting.
- No push batching. Large pushes may time out behind a proxy;
  v1.0.0 assumes small batches (10s of entries).
- Conflict resolution is manual: "pull, then push again".
- The Gate does not enforce that a device's signer is pinned. It
  only enforces chain integrity. P6 on the device is the real
  verifier.
- No compression, no pagination. Fine at the scale of one operator.

    
---

## 5. DAG Mode (v2.0.0 Upgrade)

To support multiple devices writing offline and reconciling later, `forge-gate` must support a Directed Acyclic Graph (DAG) rather than a strict linear chain.

### 5.1 The Schema Change
The `prev` field in a ledger entry changes from a string to a list of strings:
```json
{
  "seq": 15,
  "prev": ["hash_of_device_A_seq14", "hash_of_device_B_seq14"],
  "record": { ... },
  "signer": "did:key:..."
}
5.2 The Push Logic

When a client pushes entries to /push, the Gate checks:

1. Are all hashes in the prev array present in the Gate's canonical ledger? (Or is it a genesis entry with prev: []?)
2. If yes, accept the entry and add it to the ledger.
3. If no, reject with 409 missing_parents.

5.3 The Pull Logic

The /pull endpoint returns the entire DAG (or a subset based on since). Clients are responsible for sorting out the topology and merging local state.

5.4 Conflict Resolution

The Gate does not resolve conflicts. It only enforces that the graph is acyclic (no entry can point to itself or a future entry). Conflicts (two devices claiming different facts at the same time) are resolved by the master-mediator and hal on the client side.
