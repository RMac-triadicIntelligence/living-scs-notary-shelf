# Living SCS notary shelf (v1.1.4.1 and v1.1.5)

This repository is a **new shelf**. It is not an update, fork, or replacement of
[living-supply-chain-security](https://github.com/RMac-triadicIntelligence/living-supply-chain-security).
That repository is earlier work. Nothing here was pushed to it.

The trees below are copied byte-for-byte from the unpacked source packs.
Original `MANIFEST_*.sha256` files were not rewritten. No batteries were
re-run for this publication, and no results were regenerated.

## Trees

### `v1.1.4.1/` — Living SCS v1.1.4.1 door-challenge pack

Contents of the v1.1.4.1 pack (105 files), internal layout preserved.

- Changelog: `CHANGELOG_v114.md`, written **2026-09-27 (CT)**. The v1.1.4.1
  follow-up (reviewer items L5-1, backstop logging, corpus expectations,
  packaging) is the same date. `__version__` is `1.1.4.1`.
- Seal: `MANIFEST_v114.sha256` lists SHA-256 for **104** files in this tree.
  The manifest file itself is the 105th file and is not an entry in its own list.
- Engine: `v114/living_scs_v114/core.py`.

### `v1.1.5/` — Living SCS v1.1.5 “The Notary”

Contents of the v1.1.5 pack, internal layout preserved
(`v1.1.5/living_scs_v115/`, 30 files).

- `CHANGELOG_v115.md` and `README_v115.md` describe the notary: the v1.1.4.1
  engine is unchanged and runs inside a separate process. The changelog text
  does not carry its own written date. The shipped code-lane receipt
  `v115/receipts/lane_code_1790640833.json` is named for unix time 1790640833,
  which is **2026-09-28 19:13 CT**.
- Seal: `living_scs_v115/MANIFEST_v115.sha256` lists SHA-256 for **29** files.
  The manifest file itself is the 30th file and is not an entry in its own list.
- `v115/core.py` and `v114/living_scs_v114/core.py` in this tree are the
  v1.1.4.1 engine (hash below).

### `verification/lab7-logs/` — Lab7 logs for v1.1.5

Independent verification logs for the v1.1.5 pack (25 files). No engine is
included. `VERIFICATION_REPORT.md` is dated **2026-09-28 (America/Chicago)**.
These are the logs from that run, not a new run done for this shelf.

### `verification/rerun-2026-09-28/` — independent re-run of v1.1.4.1

Report and logs from an independent re-run of the v1.1.4.1 pack (58 files).
`REPORT.md` is dated **September 28, 2026**. The nested
`living_scs_v114_1.zip` that accompanied those logs is **not** in this
repository: its SHA-256 is
`2dab41e42bc8d86127db89d90c601efca0949ed4c2ef039f1465cc016d62da4f`,
the same bytes as the archive this `v1.1.4.1/` tree was unpacked from.

## Engine hash (confirmed on these bytes)

`v1.1.5` `core.py` matches the v1.1.4.1 engine. All three of these files
hash to the same SHA-256:

`23299fdc63361e632b0f30cc686b09eb3e2a3bb70daf66f51b7378fb5a26baa6`

- `v1.1.4.1/v114/living_scs_v114/core.py`
- `v1.1.5/living_scs_v115/v115/core.py`
- `v1.1.5/living_scs_v115/v114/living_scs_v114/core.py`

That is the hash named in `CHANGELOG_v114.md` and in `MANIFEST_v115.sha256`.
Checked with `sha256sum` on the files in this repository. The two pack
manifests were also checked in place (`sha256sum -c`): 104/104 OK and
29/29 OK. That check confirms these copies match the included hash lists.
It does not re-execute the test batteries.

## What the seal attests

`MANIFEST_v114.sha256` and `MANIFEST_v115.sha256` attest that the files they
name, at the paths they name inside those packs, have the SHA-256 values
they list. `SHA256SUMS` at the repository root is a separate list, made when
this shelf was published. It covers every file in the repository except
`SHA256SUMS` itself: the sealed packs (including the original manifest
files, unmodified), the verification logs, this README, and `LICENSE`.

A matching hash means **these bytes**. It does not mean anything else.

## What the seal does not attest

- It does not attest semantic truth: that a changelog claim, a report
  verdict, a comment, or a test name is correct as a statement about the
  world.
- It does not attest that any third party has re-verified this shelf beyond
  the logs that are already included under `verification/`. Those logs are
  part of the sealed bytes. Publishing them does not add a new reviewer.
- It does not attest that the checks named in those logs were re-run for
  this repository. They were not.

## License

Apache License, Version 2.0. See `LICENSE`. The short Soulshine copyright
notice at the end of `LICENSE` is the same notice used on sibling
repositories (including `raised-not-rented`). No license header was added
inside the sealed trees; doing so would change the hashes.
