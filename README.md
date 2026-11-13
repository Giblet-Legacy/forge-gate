# forge-gate — Tier 4: The Gate

README.md — repository purpose and contract for The Gate.

Function:
    A zero-trust ledger relay for multi-device sync. Runs on the VPS.
    Holds one canonical `.jsonl` ledger. Devices push their local
    entries and pull entries they're missing. All entries are
    already signed by the authoring device. The Gate is a dumb relay,
    not a database server.

Tier:     Tier 4 — The Gate (Hardware/VPS)
Depends:  P4 (Ledger .jsonl format), P6 (Canon Verify, client-side)
Consumed: Every device (phone, laptop, PC, Pi)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
Status:   0.0.0-dev (in build, pre-freeze)

## Why not SQLite over the network?

You cannot mount a live SQLite database over NFS/SSHFS and let
multiple devices write to it. SQLite's file locking does not
survive network file systems; concurrent writes corrupt the file.

The Gate sidesteps this. It doesn't sync the database. It syncs the
ledger (append-only, hash-chained .jsonl). Each device keeps its
own SQLite database locally and replays new ledger entries into it
after verifying them via P6.

## Architecture

    Phone                 Gate (VPS)               PC / Laptop
    -------               -----------              -----------
    forge.db              ledger.jsonl             forge.db
    (local)  <--pull--    (canonical)   --push-->  (local)
       |                                                |
       +------ push ------>  <----- pull ---------------+

- Push: device sends entries with seq > last_pushed_seq.
- Pull: device requests entries with seq > last_pulled_seq,
  verifies each with P6, appends to local ledger and to P8 store.
- The Gate never sees plaintext keys. It never signs anything.
- If the Gate dies, devices keep working. The canonical ledger
  can be rebuilt from any device that has the full chain.

## What a device runs

    forge gate status    # show sync state
    forge gate push      # push local entries to Gate
    forge gate pull      # pull + verify remote entries
    forge gate sync      # pull then push

Environment:
- GATE_URL (e.g. https://gate.example.com)
- GATE_TOKEN (shared secret; sent as Authorization: Bearer)
