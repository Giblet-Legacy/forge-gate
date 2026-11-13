# CHANGELOG — forge-gate (Tier 4: The Gate)

CHANGELOG.md — build history for The Gate, latest entry at top.

## [v1.0.0] — 2026-11-13

### Good
- Repository scaffolded: `Giblet-Legacy/forge-gate` created as
  Tier 4 consumer (The Gate).
- `server.py` implemented: `/health`, `/push`, `/pull` endpoints
  over stdlib `http.server`. Bearer-token auth. All-or-nothing
  batch push (chain validated before any commit).
- `client.py` implemented: `status`, `push`, `pull`, `sync`. Pulls
  via P1 (recompute hash + verify Ed25519 signature per entry)
  before appending to local ledger and P8 store.
- 12/12 pytest tests pass.
- Syncs `.jsonl` ledger, not SQLite database. Avoids network file
  locking corruption entirely.
- If the Gate dies, devices keep working. Canonical ledger can be
  rebuilt from any device with the full chain.

### Bad
- Conflict resolution is manual: a device that receives 409 must
  run `forge-gate pull` then re-run `push`. No automatic retry.
- The Gate does not enforce per-device signer pinning. It enforces
  chain integrity only. P6 on the device is the real verifier.

### Ugly
- First test run: 11/12. Bug: `_load_state()` returned `{}` for
  fresh state, so `last_pushed` defaulted to local_seq (0) instead
  of -1. Fixed by defaulting to -1 in both `push` and `status`.
- Second test run: 11/12. Bug: all tests shared `/tmp` as
  `FORGE_HOME`, causing cross-test contamination (leftover
  `ledger.jsonl` from one test leaked into another). Fixed by
  giving each test its own `tmp_path` and keeping the gate's
  ledger separate from the device's forge home.
