# NOTES — forge-gate (Tier 4: The Gate)

NOTES.md — decisions and open questions for The Gate.

## Decisions

### Sync the ledger, not the database
We sync the append-only `.jsonl` ledger, not `forge.db`. Reason:
SQLite file locking does not survive NFS/SMB. Two devices writing
a network-mounted SQLite file corrupts it. The ledger has no such
problem — it is append-only and each line is self-contained and
signed.

### Zero-trust relay
The Gate never signs anything. Every entry it holds was signed by
the authoring device via P2. The Gate's job is:
1. Accept a push of new entries.
2. Store them.
3. Serve them to devices that ask.

The device does the verification, via P6 (canon_verify), on pull.

### Single canonical ledger
The Gate holds exactly one `ledger.jsonl`. Not one per device.
Sequence numbers are shared across all devices. A device that
pushes appends to the end of the canonical chain. A device that
pulls replays missing entries into its local ledger and store.

### Conflict model
Because ledger entries are hash-chained, there cannot be a fork in
the canonical chain. If two devices push at the same time, the Gate
serialises them: the first push wins, the second device gets a
"conflict" error and must pull before it can push again. This is
the same model Git uses for remote branches.

### What the Gate doesn't do
- It does not generate or store keys.
- It does not sign or verify.
- It does not run P6 (that is the device's job).
- It does not hold a SQLite database.

The Gate is intentionally dumb. Anything that requires trust lives
on the device.

## Open questions

- Q1. Authentication. Shared bearer token is the v1.0.0 answer.
  If the Gate is exposed to the internet, we may want per-device
  tokens (issued by a small registration endpoint). Defer.
- Q2. Storage. A single `.jsonl` file is fine for v1.0.0. At
  scale, we may want to shard by month or per-device. Defer.
- Q3. Pull granularity. v1.0.0 pulls all missing entries since a
  given seq. A future version could pull by topic, by signer, or
  by date range. Defer.
- Q4. Push rate limiting. If a device goes rogue, the Gate could
  be hammered. Not a v1.0.0 concern; the shared token plus the
  hashing chain already limits abuse.
