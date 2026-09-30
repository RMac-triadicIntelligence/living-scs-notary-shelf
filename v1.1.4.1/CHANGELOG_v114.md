# Living SCS CommitEngine v1.1.4 (lab5 hardening of v1.1.3)

Written 2026-09-27 (CT). New module: `/workspace/lab5/v114/living_scs_v114/core.py`, made by copying
`/workspace/lab3/door_challenge/v113/living_scs_v113/core.py` and applying `make_v114_patch.py`.
The original v1.1.3 tree and `/workspace/lab4` were not modified: `results/originals_sha256_before.txt` and
`results/originals_sha256_after.txt` are byte-identical (30 files).
Unified diff: `results/core_v113_to_v114.diff`. Diffs of the supporting copies: `results/support_copies.diff`.

## v1.1.4.1 (v1.1.4 follow-up, 2026-09-27 CT): reviewer items L5-1, backstop logging, corpus expectations, packaging
`core.py` sha256 is now `23299fdc63361e632b0f30cc686b09eb3e2a3bb70daf66f51b7378fb5a26baa6` (v1.1.4 was `14ce06a0...`).
`__version__` is `1.1.4.1`. The follow-up diff is `results/core_v114_to_v114_1.diff`: 94 added lines and 0 removed lines,
consisting of documentation, one new helper and one log call. The signing and digest formats are unchanged:
`canonical_json`, `sha256_hex`, `signed_body`, `record_hash_for` and `verify_record_chain` are not edited, and the
v1.1.3 byte-compatibility unit test still passes. `make_v114_patch.py` now has a follow-up section. Starting from a
byte copy of v1.1.3 `core.py` it reproduces the new `core.py` byte for byte (`results/patch_reproduction_check.txt`).
All 12 mutant patches still apply exactly once and compile (`results/mutant_patch_check.txt`).

### L5-1: the persisted log can diverge from the engine (contract fix; engine behaviour unchanged)
The problem: a `persist_hook` writes the record durably and then raises. The engine rolls back (correct) and a retry
of the same authorization commits sequence 1 again. An append-only hook therefore persists `[1, 1]`. With a real
clock the retry has a different timestamp, so the two records have different hashes.
* Regression test `tests/test_l5_1_hook_contract.py` (12 tests), output in `results/l5_1_hook_contract.txt`:
  * naive append-only hook: `engine seqs [1] verify_history True | persisted seqs [1, 1] verify_record_chain False`,
    with both a fixed clock (byte-identical duplicate) and an advancing clock (timestamps and record_hash differ). A
    later commit leaves the naive log at `[1, 1, 2]`, which is still broken.
  * idempotent upsert-by-sequence hook: `persisted seqs [1] verify_record_chain True | persisted==engine True`, with a
    fixed clock, an advancing clock, and a keyed history plus a second commit (`[1, 2]`).
* `CommitEngine.__init__` now has a docstring documenting the hook contract:
  * the hook may be called for a commit that is later rolled back if it raises;
  * hooks MUST be idempotent upserts keyed by `record.sequence` (seq N overwrites seq N);
  * hooks must not re-enter the engine;
  * recovery must truncate or reconcile the persisted log to `engine.records`.
  The docstring also records the no-migration note below.
* New public helper `reconcile_persisted_log(persisted_records, *, history_key=None, engine_records=None)`. It does
  four things:
  1. Dedupes by sequence (last write wins).
  2. Keeps the contiguous run 1..n.
  3. Keeps the longest prefix that passes `verify_record_chain`.
  4. If `engine_records` is given, cuts at the first record that differs from it. `engine_records` is authoritative
     and must itself verify.
  It accepts `CommitRecord` instances or JSON mappings, raises Refusal on malformed entries, and returns fresh records
  that always verify. Tested cases: a naive log goes `[1, 1, 2] -> [1, 2]` and equals engine.records; JSON round
  trip; tamper; gap; wrong or missing key; malformed entries; engine records that do not verify.
* Documented limitation: without `engine_records` (a cold start), a final record whose hook wrote and then raised,
  and which was never retried, is correctly signed and chained. The log alone cannot distinguish it from a real commit
  (tested). Closing this needs a two-phase or commit-marker protocol in the application's storage layer.

### Backstop logging
When the pre-commit backstop converts an unexpected exception into `Refusal('malformed input: <Type>')`, it now calls
`logging.getLogger(__name__).warning(..., exc_info=exc)` (module logger `_LOG`) before raising. The Refusal is still
chained `from exc`. A `NullHandler` is attached to the library logger, so nothing reaches `logging.lastResort`/stderr
unless the application configures logging. Records still propagate to the root logger. This is why the harness and
fuzz output are unchanged. Ordinary Refusals are not logged. Test `tests/test_backstop_logging.py` (3 tests,
`results/backstop_logging.txt`): `logged: WARNING living_scs_v114.core: commit pre-commit backstop: unexpected
TypeError converted to Refusal('malformed input: TypeError') | exc_info=TypeError`.
Note: the log call runs under the engine lock. A handler that blocks will block other commits, and a handler that
calls `commit()` is refused as re-entrant.

### Corpus expectations
In `v114/grok_attacks.json` the six `fault_findings` rows (`list_evidence_id`, `sig_non_string`,
`trace_created_str`, `overflow_confidence`, `float_overflow_to_inf`, `surrogate_in_reason`) were changed from
`"expect": "FAULT"` to `"expect": "REFUSE"`. The harness field is `expect`. `v114/round2_attacks.json` carries the
same six rows and was changed the same way. `deep_artifact_name` has no `expect` field, so it was left alone.
The `v113_ref/` copies and the lab3 originals were not changed (`results/attack_expect_changes_v114_1.diff`).
The harness now shows 0 expectation mismatches on all three corpora. The receipt file names follow the attack-file
sha256, so they are now `v114_receipt_993d42fa47ab.json` (grok) and `v114_receipt_101b12fa7fe5.json` (round2).
The stale v114 receipts `7b852fcd45e5` and `70827b33354e` were removed.

### Packaging
The earlier `living_scs_v114.zip` was missing 7 manifest entries (`redteam_v113/{common,fuzz,p2_verify_accepts}.py`
and `tools/{backstop_compare,compare_receipts,differential,fuzz_counts}.py`). All of them are in the package.
`MANIFEST_v114.sha256` now lists every shipped file except itself, including `v113_ref/`, `results/` and
`receipts/`. The paths are relative to the package root, so run `sha256sum -c MANIFEST_v114.sha256` there.
`tests/test_v114_hardening.py` and the new tests locate `v114/` and `v113_ref/` relative to their own file, so
they also run from an unzipped copy. The reviewer's `test_l4_1_reentrancy.py` was copied unchanged into
`redteam_v114/`. Its `common.py` already targets v114. Result: 4/4 PASS (`results/reviewer_l4_1_reentrancy_v114.txt`).
The same file fails 2/4 against v1.1.3, as intended.

### Rerun results (v1.1.4.1)
selftest PASS (0 mismatches, 0 breaches, killed M1 M2 M4). Unit tests: 36 OK (21 hardening + 12 L5-1 + 3 logging).
Harness with --mutants: baseline, grok and round2 are all `GREEN (breaches=0, faults=0, harness errors=0)`, kill 3/12,
0 expectation mismatches. Fuzz seed 1337: REFUSE 17101 / ACCEPT 39 / ADAPTER_REFUSE 3199 / FAULT 0, and the
post-commit sweep has 0 anomalies. Differential: FAULT->REFUSE 538, other diffs 0.
The `results/*v114*` files (selftest, harness, fuzz, differential, unit tests) were regenerated against v1.1.4.1.
The `*v113*` "before" files were not regenerated.

Originals check: `results/originals_sha256_after.txt` was regenerated. The lab3 v1.1.3 tree is still byte-identical.
One lab4 file differs from `originals_sha256_before.txt`: `lab4/fuzz_findings.json`, which was rewritten at
18:16 CT on 2026-09-27. That was before this follow-up started and was not done by lab5 tooling. Its previous
content (sha256 `4a1b6fa1...`) is still present as `lab6/A/fuzz_findings.json`, copied at 18:15 CT. So this is most
likely the reviewer re-running the lab4 fuzzer, which rewrites that output file. No lab3, lab4 or lab6 file changed
while this follow-up ran (110 files hashed before and after).

### Known issues (documented, not changed)
* `verify_history()` is O(n) and runs on every commit, inside `_prepare_commit` and under the lock, so a history of n
  commits costs O(n^2) in total. This was already the case in v1.1.3. A future fix could cache the verified prefix
  length and last hash, then re-verify only on demand or when a record is added.
* There is no migration path from an unkeyed to a keyed history. `history_key` changes every `record_hash`, so an
  existing unkeyed chain cannot be "upgraded" in place. Starting a keyed history requires a new chain, meaning a new
  engine and a fresh record log. Keep the old unkeyed log archived separately, and if you need continuity, anchor its
  final `record_hash` or state digest in the new chain's first commit reason.

## Compatibility
* The public API is kept. Every public name in v1.1.3 still exists (checked by a unit test). Existing call
  signatures are unchanged. The only new constructor argument is the optional keyword `history_key=`.
* The signing and digest formats are unchanged. `canonical_json`, `sha256_hex`, `signed_body`, and the
  proposal, trace and evidence digests are all untouched. A test commits the same inputs on v1.1.3 and on
  v1.1.4 (unkeyed) and gets the same proposal digest, trace digest, signature, `record_hash` and state digest.
  An authorization minted with v1.1.3 objects and sent as JSON commits on v1.1.4. The harness `$ISSUED`
  control commits in every session.
* `record_hash` is still 64 lowercase hex characters. Without `history_key` it is still `sha256(canonical_json(body))`.
* All 12 mutant patches in `_pkg_check_mutations.py` apply exactly once to v1.1.4 and compile. No mutant patch had
  to be moved or rewritten (`results/mutant_patch_check.txt`).
* New public names: `record_hash_for`, `verify_record_chain`, `validate_commit_inputs`, `MAX_NESTING_DEPTH` (64),
  `MAX_SAFE_INTEGER` (2**53), `ED25519_SIGNATURE_HEX_LENGTH` (128).

## Fixes

### 1. persist_hook re-entrancy and atomicity (lab4 L4-1)
Why: in v1.1.3 the hook ran after the checks but before the nonce, determination, record and state were consumed.
The lock is a re-entrant `RLock`, so a hook that called `commit()` with the same authorization committed it twice.
The result was two records with sequences `[1, 1]`, and `verify_history()` returned False.
Changes:
* Re-entrancy guard. `_commit_in_progress` is set under the lock. Any `commit()` made while it is set is refused with
  `Refusal("re-entrant commit refused: ...")`. This covers `restore_state`, because restores are commits. Other
  threads still just wait on the lock.
* `commit()` now runs in three phases:
  1. `_prepare_commit()` runs every check and computes the new state, the stored copy of the state, the resulting
     digest and the complete `CommitRecord`. It does not mutate the engine.
  2. The nonce and determination are reserved, then the hook is called with copies.
  3. The state, record, snapshot and parent link are assigned. These are plain assignments of values already
     computed in phase 1.
* If the hook raises, the reservation is released and the exception propagates unchanged. Nothing else was modified,
  so the v1.1.3 property "a failing hook commits nothing" still holds. The same authorization can be retried once
  the hook works. The guard flag is always cleared in `finally`.
Evidence: `p1_reentrancy.py` went from `num records: 2` / `record sequences: [1, 1]` / `verify_history: False` to
`hook calls: 1` / `reentrant_exc: Refusal: re-entrant commit refused ...` / `num records: 1` / `verify_history: True`.
`p1_persisthook_raises.py` still shows `state changed by failed hook: False`. Unit tests cover:
a re-entrant commit with a different valid authorization, and a re-entrant restore (both refused); the hook seeing
the pre-commit state with the nonce reserved; a hook failure followed by a successful retry; and 16 threads racing
one authorization, which gives exactly 1 commit.

### 2. Optional keyed history integrity (lab4 L4-2)
Why: `record_hash` was an unkeyed sha256, so anyone who can write the record list can append a record that verifies.
Changes: new optional argument `CommitEngine(..., history_key=bytes)`, at least 16 bytes. Anything else raises
Refusal. When a key is set, record hashes are `HMAC-SHA256(key, canonical_json(body))` and `verify_history()`
checks them with `hmac.compare_digest`. When no key is set, hashes stay plain sha256 and are byte-compatible with v1.1.3.
That unkeyed chain only detects accidental corruption. It does not resist deliberate tampering, and this is now
documented in `record_hash_for`. `verify_record_chain(records, history_key=)` never raises (malformed input returns
False) and can check records persisted through the hook.
Limit: the key is held in-process (`engine._history_key`), so it does not protect against code that can read engine
internals. It protects records at rest and against anyone who can write the list but does not have the key.
Evidence (`p1_hist_restore.py`): unkeyed forged append still verifies (`True`, the documented v1.1.3 behaviour). With
a key: `[keyed] verify_history after forged append (attacker sha256): False`, `... (HMAC with wrong key): False`,
and the next commit gives `Refusal history integrity failure`.

### 3. Record aliasing (lab4 L4-3)
`engine.records`, `history_snapshot()` (and so `living_ai_bom`) and the `persist_hook` now get fresh `CommitRecord`
instances (`dataclasses.replace`). The hook still gets a deepcopy of the new state. Evidence (`p1_hook_record_alias.py`):
`hook record is stored record: False`, `verify_history after: True`, `public records[0] is internal: False`,
`verify_history after tampering via public .records: True`.

### 4. Strict `is_sha256()` (lab4 L4-4)
The value must be exactly `str` (not a subclass), 64 characters long, all in `[0-9a-f]`. Evidence (`p1_is_sha256.py`):
upper, leading/trailing space, underscore, plus sign, `0x` and newline all changed from True to False. Real digests
are still True.
Compatibility note: an uppercase digest in an organ mutation or in an initial state's organ inventory is now invalid.
Everything the engine itself emits is lowercase.

### 5. Crash-not-refuse: one input-validation layer at `commit()` entry (lab4 L4-5, L4-6, README F1/F2, grok round 3)
`validate_commit_inputs()` runs first inside the commit lock and raises Refusal only. It checks:
* Types. proposal, trace and auth must be instances of their dataclasses. Every field is read once and rebuilt
  into a fresh instance, and containers are deep-copied, so the checks that follow cannot be raced by the caller's
  objects. Known string fields must be exactly `str`, including evidence_id, detector, maturity_state, source_uri,
  nonce and reason. `created_at`, `observed_at`, `issued_at` and `expires_at` must be exactly `int`, so bool and
  float are rejected. confidence, salience, resonance and convergence must be int or float, not bool. `evidence_ids`
  must be a list or tuple of str, `decision` a `Decision`, `status` a `ProposalStatus`, and `signature` a str of
  exactly 128 hex characters. `mutation` and `interpretation.output` must be dicts.
* Values, using an iterative walk with no Python recursion: nesting deeper than 64 containers is refused (exactly 64
  is allowed and commits when genuinely signed; a 100,000-deep value and reference cycles are refused);
  non-finite floats (inf and nan, including `1e400` from the harness JSON); ints with |x| > 2**53; strings or keys
  that cannot be encoded as UTF-8 (lone surrogates), including in `reason`; non-str mapping keys; and non-JSON types
  such as bytes, set or object.
* An artifact passed with any op other than `install_organ` is refused.
* Backstop: any other non-Refusal/TraceError exception raised during the pre-commit phase becomes
  `Refusal("malformed input: <Type>")`, chained with `from exc`. `MemoryError` is not wrapped. The backstop covers
  phase 1 only. Hook exceptions and anything after the reservation propagate unchanged.
  Example: a genuinely signed `{"op":"set","path":5}` raised a raw `TypeError` in v1.1.3 and now gives
  `Refusal: malformed input: TypeError` (`results/backstop_v113_vs_v114.txt`).
Harness strict_loads was left alone because it is out of scope. `1e400` still reaches the engine and is now refused
(`float_overflow_to_inf -> Refusal: malformed input: non-finite number in proposal.evidence[0].value`).

## Behaviour changes (intentional)
* Raw exceptions (TypeError, ValueError, OverflowError, RecursionError, UnicodeEncodeError, AttributeError) raised
  before a commit are now Refusal. For example, the lab4 raw-string decision now gives
  `Refusal malformed input: auth.decision must be a Decision`.
* grok_attacks `deep_artifact_name` (the real $ISSUED plus an ignored deep artifact) was ACCEPT on v1.1.3 and is now
  `REFUSE: artifact supplied for a non-install_organ operation`. As a result, the next row, `legit_after_all`, is the
  one that commits (REFUSE -> ACCEPT). The session still has exactly 1 accept and there is no breach.
* The six grok `fault_findings` rows now give REFUSE, which is the fix. In v1.1.4 they still carried
  `expect=FAULT` and showed as expect mismatches. In v1.1.4.1 the v114 corpus copies say `expect=REFUSE`, so there are
  0 mismatches.
* Rejected in-process inputs that v1.1.3 may have accepted: non-str mapping keys (these made digests ambiguous,
  e.g. `{1:..}` vs `{"1":..}`), `str` subclasses in known fields, a non-str `reason`, ints beyond 2**53 anywhere in
  signed data, and nesting deeper than 64.
* Uppercase-hex signatures are still accepted. They decode to the same 64 bytes, as in v1.1.3. Signature length
  must now be exactly 128 hex characters. Any other length could never verify anyway.
* `verify_history()` now takes the engine lock and returns False instead of raising on malformed records.

## Test evidence (all in /workspace/lab5/results/)
| check | v1.1.3 | v1.1.4 |
|---|---|---|
| selftest (`selftest_v113.txt` / `selftest_v114.txt`) | 0 mismatches, 0 breaches, killed M1 M2 M4, PASS | 0 mismatches, 0 breaches, killed M1 M2 M4, PASS |
| harness lscs_baseline --mutants | GREEN breaches=0 faults=2 herr=0, kill 3/12 | GREEN breaches=0 faults=0 herr=0, kill 3/12 |
| harness grok_attacks --mutants | GREEN breaches=0 faults=10 herr=0, kill 3/12 | GREEN breaches=0 faults=0 herr=0, kill 3/12 |
| harness round2_attacks --mutants (extra) | GREEN faults=6, kill 3/12 | GREEN faults=0, kill 3/12 |
| fuzz seed 1337, 20,339 trials | REFUSE 16563 / ACCEPT 39 / ADAPTER_REFUSE 3199 / FAULT 538 | REFUSE 17101 / ACCEPT 39 / ADAPTER_REFUSE 3199 / FAULT 0 |
| fuzz STATE-MUTATED / history broken / anomalous accepts | 0 / 0 / 0 | 0 / 0 / 0 |
| fuzz accepts (identical + equivalent) | 33 + 6 | 33 + 6 (same 6: 4 dropped optional trace refs, 2 uppercase sig) |
| post-commit sweep (3,000) | REFUSE 2438 / FAULT 80 / ADAPTER_REFUSE 482, anomalies 0 | REFUSE 2518 / ADAPTER_REFUSE 482, anomalies 0 |
| differential (same key, same 20,339 submissions) | – | ACCEPT->ACCEPT 39, REFUSE->REFUSE 16563, ADAPTER->ADAPTER 3199, FAULT->REFUSE 538, other diffs 0 |
| unit tests `tests/` (all) | – | 36 tests OK (21 hardening + 12 L5-1 hook contract + 3 backstop logging) |

Known pre-existing issue, not an engine issue: the last section of lab4 `p1_hist_restore.py` (LyingArtifact) crashes
with `AttributeError: property 'content' ... has no setter` on both v1.1.3 and v1.1.4. The script constructs its own
subclass incorrectly and never reaches the engine.

## Layout
* `v114/` is a copy of the v113 dir. `living_scs_v114/` is the new package. `lscs_harness.py` was edited only for
  PKG_DIR, the banner and the receipt name. `selftest_v114.py` is a copy of selftest_v113 with a new docstring. The
  copied `selftest_v113.py`, `living_scs_v113/`, `MANIFEST_v113.sha256` and README/packet were left as-is. The copied
  `selftest_v113.py` would now import the v114 harness, and `MANIFEST_v113.sha256` no longer matches the edited
  harness copy. The v113 receipt copies were removed from `v114/receipts`; the originals are untouched.
* `v113_ref/` is a pristine copy used for all "before" runs, so no original file was written.
* `redteam_v113/` and `redteam_v114/` are copies of lab4 repointed to v113_ref and v114, with fuzz output sent to
  results/. `p1_hist_restore.py` in v114 adds the keyed-history check.
* `tools/` contains fuzz_counts.py (exact counts from memory), differential.py, compare_receipts.py and backstop_compare.py.
* Run: `cd v114 && python3 selftest_v114.py && python3 lscs_harness.py grok_attacks.json --mutants`;
  `python3 -m unittest discover -s tests -v` (from the package root; pytest also collects these files if installed).
