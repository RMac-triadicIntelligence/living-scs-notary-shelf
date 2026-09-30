# Living SCS v1.1.3 CommitEngine — Red-Team Report (lab4)

Target (unmodified): `/workspace/lab3/door_challenge/v113/living_scs_v113/core.py`
Harness: `lscs_harness.py` v0.2.1. Work dir: `/workspace/lab4/`. Python 3.13.5, cryptography 43.0.0.
`selftest_v113.py` = PASS (0 mismatches, 0 breaches, kills M1/M2/M4) before this work.

Class legend: **(a)** reachable via the JSON harness under challenge rules; **(b)** reachable only by an
in-process Python caller using the public API; **(c)** not exploitable.
All claims below were produced by running the listed scripts; observed output is quoted.

## Findings table

| id | phase | class | severity | one-line | proof script | observed |
|----|-------|-------|----------|----------|--------------|----------|
| L4-1 | 1/3 | **b** | High (in-proc) | `persist_hook` re-entrancy → double commit, two records seq=1, `verify_history()=False` | `p1_reentrancy.py` | `num records: 2` / `record sequences: [1, 1]` / `verify_history: False` |
| L4-2 | 1/3 | b | Medium | `record_hash` is an **unkeyed** sha256; a caller with list-write access can append a forged record that passes `verify_history()` | `p1_hist_restore.py` | `verify_history after forged append: True` |
| L4-3 | 1/3 | b | Low | `eng.records` / `persist_hook` share the *same* frozen `CommitRecord` objects; `object.__setattr__` tampering flips `verify_history()` to False | `p1_hook_record_alias.py` | `public records[0] is internal: True` / `verify_history after tampering via public .records: False` |
| L4-4 | 1 | c | Info | `is_sha256()` is over-permissive: accepts uppercase, whitespace, `0x`/`+`/`_` (uses `int(v,16)`) | `p1_is_sha256.py` | all 9 variants `is_sha256=True` |
| L4-5 | 3 | c | Info | raw-string `decision` (non-Enum) → `AttributeError` crash-not-refuse, **state unchanged** | `p1_misc.py`,`p1_more.py` | `AttributeError 'str' object has no attribute 'value'` / `state changed: False` |
| L4-6 | 2 | a | Info | 538 fuzz FAULTs (crash-not-refuse, TypeError/ValueError/RecursionError) — all pre-commit, **0** left state changed | `fuzz.py` | see counts below |
| L4-7 | 1/3 | c | none | dict-subclass/`Liar.get` value-swap defeated by result-digest recompute | `p1_misc.py` | `Refusal result digest mismatch` |
| L4-8 | 3 | c | none | injected authority object ignored; constructor rebuilds verifier from pinned key (M9-safe) | `p1_more.py` | `engine._authority is injected object: False` |
| L4-9 | 3 | c | none | attacker key with same authority_id → signature rejected (M8-safe) | `p1_more.py` | `Refusal invalid authorization signature` |
| L4-10 | 3 | c | none | `restore_state` to fabricated snapshot refused (must be a known snapshot) | `p1_hist_restore.py` | `Refusal restore requires a known historical snapshot` |
| L4-11 | 3 | c | none | `OrganArtifact` subclass TOCTOU: `_artifact_snapshot` reads `content` once into a local, hashes the same local | `p1_art_toctou.py` | `snapshot content: b'benign'` |
| L4-12 | 1 | c | none | expiry boundary `now==expires_at` accepts, `+1` refuses; `issued_at` future-skew blocked by clock rollback | `p1_misc.py` | `commit at now==expires_at: ...ACCEPT` / `expired+1: Refusal authorization expired` |
| L4-13 | 3 | c | none | `remove_organ` of a non-organ name (`"maturity"`) only pops from `organs` dict; no protected bypass, result-digest still bound | `p1_more.py` | `ACCEPT remove_organ` (state unchanged, no-op on empty organs) |
| L4-14 | 1/3 | c | none | in-place mutation of `proposal.mutation` after signing → `trace/proposal mismatch` | `p1_toctou.py` | `TraceError trace/proposal mismatch` |
| L4-15 | 1/3 | c | none | `engine.state`, `state_at`, `records` return deep copies / tuples (no internal aliasing of state) | `p1_toctou.py` | internal maturity/tone unchanged after mutating returned value |
| L4-16 | 3 | c | none | ed25519 S+L signature malleability **rejected**; uppercase hex = same 64 bytes = identical transition | `p2_verify_accepts.py` | `S+L rejected: InvalidSignature` / `UPPERCASE hex sig VERIFIES (same bytes)` |
| L4-17 | 1/3 | c | none | persist_hook that RAISES is atomic (state mutated after hook) — nothing committed | `p1_persisthook_raises.py` | `state changed by failed hook: False` / `records: 0` |

## Phase 2 fuzzer (seed=1337, 20,339 trials)

Outcome counts: `{"REFUSE": 16563, "ACCEPT": 39, "ADAPTER_REFUSE": 3199, "FAULT": 538}`
Accepts: total=39, strict-identical to legit=33, non-identical=6.
- The 6 non-identical accepts are all **semantically identical to the legit $ISSUED transition**
  (`same_result=True`, seq==1, verify_history True): 4 drop an *optional* trace field that defaults to
  `null` (`authorization_ref`/`reversal_ref`/`compensation_ref`/`descendant_impact_ref`), 2 uppercase the
  hex signature (decodes to the same 64 bytes). No unauthorized transition.
- STATE-MUTATED-on-non-accept findings: **0**. verify_history-broken findings: **0**.
- Post-commit sweep (3,000 sampled mutations after a legit commit): `{"REFUSE":2438,"FAULT":80,"ADAPTER_REFUSE":482}`,
  0 anomalies. Exact replay of the legit submission after commit: `Refusal: authorization replay`.
- 538 FAULTs = crash-not-refuse only (unhashable list/dict, fromhex TypeError on non-str signature,
  `<` str-vs-int on `created_at`, non-iterable `source_uri`/`evidence_ids`, RecursionError, inf ValueError).
  Every one raised **before** the commit mutated any state (0 atomicity breaks). These match the
  already-known crash-not-refuse class in the brief.

Details saved to `/workspace/lab4/fuzz_findings.json` (counts, per-kind breakdown, fault-by-field, findings).

## Breach assessment (challenge definitions B1–B4)
Nothing found constitutes a breach **through the JSON data channel (class a)**:
- B1 (maturity/organs/policy change), B2 (transition other than $ISSUED), B3 ($ISSUED twice),
  B4 (history verification failure) — **none achieved via the harness**. The engine held.
- L4-1 (persist_hook re-entrancy) does break atomicity and history (B3/B4-like), but it is **class (b)**:
  it requires the constructor `persist_hook` callback, which the harness never supplies and the README
  scopes out ("in-process attacker code is out of scope"). Under challenge rules it is **not a breach**;
  it is a real defect for any embedder that wires a re-entrant persist hook.
- L4-2/L4-3 are class (b) integrity notes (unkeyed record hash + shared frozen record objects). Private
  `_records`/`object.__setattr__` access is the trivially-allowed Python caveat; called out separately, low value.
