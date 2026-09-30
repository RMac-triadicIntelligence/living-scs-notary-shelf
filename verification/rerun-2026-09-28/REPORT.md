# Living SCS v1.1.4.1 — independent execution report

Run date: September 28, 2026. Input: `living_scs_v114_1.zip`.

**Verdict: the principal v1.1.4.1 regression and fuzz results reproduce.** No unauthorized transition, duplicate authorization acceptance, or broken history was observed through the supplied JSON challenge corpora. The patched engine generated zero unexpected faults in those corpora and the supplied fuzz battery. This is an independent execution of supplied tests, not a newly designed adversarial campaign or a proof of universal security.

## Input and method

- ZIP SHA-256: `2dab41e42bc8d86127db89d90c601efca0949ed4c2ef039f1465cc016d62da4f`.
- Engine SHA-256: `23299fdc63361e632b0f30cc686b09eb3e2a3bb70daf66f51b7378fb5a26baa6`.
- All 104 manifest entries pass; the archive has 105 files including the manifest. No payload is missing or unlisted.
- Read the current changelog, inherited README/challenge instructions, report, test runners and supporting scripts. The changelog identifies the active engine as v1.1.4.1; the old Grok packet and red-team report describe the v1.1.3 reference challenge.
- Ran in Python 3.12.14 with cryptography 46.0.0, on Linux. The historical red-team report specifies Python 3.13.5 with cryptography 43.0.0.
- Preserved the uploaded archive and extracted source. Created a separate working copy and replaced `/workspace/lab5` with its actual workspace path in support scripts. The full diff is included. Neither engine core was modified.
- Read raw output and parsed fresh receipts; did not infer success solely from exit codes or the harness's GREEN label. GREEN means no breaches and can coexist with faults, as the v1.1.3 runs demonstrate.

## Fresh results

| Check | Result |
|---|---|
| Input manifest | 104/104 pass |
| v1.1.4.1 self-test | PASS; 0 expectation mismatches; 0 breaches |
| Unit suite | 36/36 pass: 21 hardening, 12 persistence contract, 3 logging |
| Additional re-entrancy regression tests | 4/4 pass |
| Same re-entrancy tests on v1.1.3 | Expected 2/4 fail; confirms sensitivity to old defect |
| Baseline corpus | 17 attempts / 6 sessions; 0 breaches, 0 faults, 0 harness errors, 0 expectation mismatches |
| Grok corpus | 52 attempts / 10 sessions; 0 breaches, 0 faults, 0 harness errors, 0 expectation mismatches |
| Round 2 corpus | 34 attempts / 9 sessions; 0 breaches, 0 faults, 0 harness errors, 0 expectation mismatches |
| Mutant score, each corpus | 3/12: M1, M2, M4 |
| Mutation patch compatibility | All 12 apply once and successfully import |
| v1.1.3-to-v1.1.4.1 patch reproduction | Byte-identical to shipped core |

The corpus counts total 103 attempts, with overlap between corpora. They are not 103 unique attack designs. All fresh v1.1.4.1 receipt row outcomes match the shipped receipts.

### Fuzz, seed 1337

| Outcome | v1.1.3 rerun | v1.1.4.1 rerun |
|---|---:|---:|
| Engine refusal | 16,563 | 17,101 |
| Authorized acceptance | 39 | 39 |
| Adapter refusal | 3,199 | 3,199 |
| Unexpected fault | 538 | 0 |
| Total submissions | 20,339 | 20,339 |
| State mutation after non-acceptance | 0 | 0 |
| Broken history findings | 0 | 0 |
| Anomalous acceptances | 0 | 0 |

All 39 acceptances reach the intended authorized result: 33 are strictly identical submissions; six are equivalent representations (four omitted optional trace fields and two uppercase hexadecimal signature representations). These are not unauthorized transitions. Adapter refusals are counted separately from engine protection.

The 3,000-submission post-commit sweep yields 2,518 engine refusals and 482 adapter refusals on v1.1.4.1, with no faults or anomalies. The old engine yields 2,438 refusals, 80 faults and 482 adapter refusals. Exact replay is refused in both versions.

### Paired differential output

The supplied differential runner submits the same generated material to both versions, using the same key and organism within that comparison:

```text
trials: 20339
ACCEPT         -> ACCEPT             39
ADAPTER_REFUSE -> ADAPTER_REFUSE   3199
FAULT          -> REFUSE            538
REFUSE         -> REFUSE          16563
per-trial differences other than FAULT->REFUSE: 0
accepts with different resulting digest between versions: 0
```

This supports the narrower claim that the 538 crash cases became clean refusals without changing outcomes elsewhere in this fuzz population. It does not say that every input accepted by v1.1.3 is accepted by v1.1.4.1: the changelog explicitly identifies intentional validation changes.

## Before-and-after evidence

Re-entrant persistence callback:

```text
v1.1.3:   hook calls: 2; record sequences: [1, 1]; verify_history: False
v1.1.4.1: hook calls: 1; record sequences: [1];    verify_history: True
           reentrant_exc: Refusal: re-entrant commit refused ...
```

Record copies: the old engine's history becomes invalid after tampering through public record aliases; the patched engine's history stays valid. Keyed history rejects forged appended records made with plain SHA-256 or a wrong HMAC key. A subsequent commit refuses with `history integrity failure`.

Persistence contract tests:

```text
naive append hook: engine [1], persisted [1, 1], persisted chain invalid
upsert hook:       engine [1], persisted [1],    persisted chain valid
reconciliation:  [1, 1, 2] -> [1, 2], equals engine.records, chain valid
```

## Qualifications and remaining issues

1. **Persistence is still conditional on the storage protocol.** The new helper and documented upsert contract repair duplicate-sequence logs after retries. A final durable write followed by a raised exception, with no retry, is indistinguishable from a committed record when only that correctly signed/chained log remains at cold start. The tests explicitly reproduce this limitation. Two-phase persistence or a durable commit marker is still an application-level requirement to resolve it. Therefore this is not a complete crash-recovery fix.
2. **Optional keyed history matters.** Unkeyed SHA-256 history still accepts a recomputed forged chain from an actor able to rewrite the private record list. The keyed mode detects the tested forgery when the attacker lacks the key. This is separate from the data-only challenge.
3. **Two diagnostic script failures.** `p1_hist_restore.py` exits 1 in both version directories because its `LyingArtifact` fixture assigns to a getter-only `content` property. It fails during fixture construction, before that final probe can reach the engine. Earlier keyed-history and restore probes do execute. This defect is already disclosed by the package. No claim is made that every shipped diagnostic completes successfully.
4. **Historical count differs.** The v1.1.3 Grok corpus produces 11 faults here, versus 10 in the shipped receipt. The sole changed row is `ev_depth_900`: stored REFUSE, fresh RecursionError FAULT. Runtime-dependent recursion behavior is a plausible explanation given the Python-version difference; it was not isolated experimentally. Baseline (2 faults) and Round 2 (6 faults) match the stored old-version totals. All v1.1.4.1 corpora have zero faults.
5. **Portability remains incomplete.** Support scripts and tools retain absolute author-machine paths; the current package can run its primary tests after extraction, but the extended battery needs path adjustments. The README and embedded expert packet are historical and easy to mistake for current instructions. No release files were edited to correct this.
6. **Mutation score is bounded.** M1, M2 and M4 are detected; nine mutants survive. The self-test documents overlapping guards and seams outside the JSON channel. This does not establish comprehensive mutation coverage.
7. **Existing performance and migration limitations remain.** The changelog documents full-history verification on every commit (quadratic total work as history grows), and no in-place unkeyed-to-keyed history migration. These were not benchmarked or expanded into a migration study in this run.

## Commands and evidence

The main package commands, from the indicated directories, were:

```bash
# Package root
sha256sum -c MANIFEST_v114.sha256
python -m unittest discover -s tests -v

# v114/
python selftest_v114.py
python lscs_harness.py lscs_baseline.json --mutants
python lscs_harness.py grok_attacks.json --mutants
python lscs_harness.py round2_attacks.json --mutants

# Package root, after support-script path adjustment
python redteam_v114/test_l4_1_reentrancy.py
python tools/fuzz_counts.py /absolute/path/to/redteam_v114/fuzz.py
python tools/fuzz_counts.py /absolute/path/to/redteam_v113/fuzz.py
python tools/differential.py
```

Additional commands reran the v1.1.3 self-test and all three old-version corpora, each `p1_*.py` and `p2_verify_accepts.py` in both lanes, the backstop comparison, receipt comparison, patch reconstruction and old-version re-entrancy sensitivity control. The `status_*.json` files record commands, working directories, exit codes and elapsed times; `logs/` contains raw output; `fresh_receipts/` and `fresh_fuzz/` contain new generated evidence.

One reviewer-runner issue was corrected: importing the original re-entrancy test created a Python bytecode cache, causing an overly strict unlisted-files check to fail. The generated cache was removed, the runner switched to the working copy, and the full packaging check then passed. Its initial log is retained separately. No shipped source bytes changed.

To reproduce in a fresh extraction of this evidence bundle (Python plus cryptography required):

```bash
python verification/setup_work.py
python verification/run_checks.py core
python verification/run_checks.py fuzz114
python verification/run_checks.py fuzz113
python verification/run_checks.py differential
python verification/run_checks.py proofs
PYTHONDONTWRITEBYTECODE=1 python verification/check_packaging.py
```

The original input ZIP is included. Run in a fresh folder to preserve these original execution logs. Some keys and identifiers are randomly generated, so receipts need not be byte-identical across runs; compare outcomes and hashes of the engine and attack inputs.
