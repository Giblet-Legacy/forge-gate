# Forge Stack Context — The Gate

CLAUDE.md — Context briefing for AI assistants working in this repository.

## What this repo is
Tier 4 — The Gate. A zero-trust ledger relay for multi-device sync.
It does NOT hold a SQLite database. It holds a single canonical
`.jsonl` ledger. Devices push their locally-signed entries here and
pull missing entries from here.

## The Immutable Rule
Never rewrite a primitive. Add a layer. The Gate consumes P4 (Ledger
format) and P6 (Canon Verify). It does not rewrite them.

## Zero-trust posture
The Gate does NOT trust devices. Every entry it stores is already
signed by the authoring device via P2. The Gate validates chain
integrity on push but does not re-sign. Receiving devices run P6 to
verify independently before inserting into their local store.

## What it is NOT
- Not a SQLite server. No database on the VPS.
- Not an identity provider. Devices sign their own entries.
- Not a backup. The canonical ledger can be rebuilt from any device
  that has the full chain.

## Constraints
- Standard library only.
- British English (-ise, artefact).
- LF-only.
- Header discipline on every file and function.
