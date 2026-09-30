# Door Challenge — Lane B: live target, Living SCS v1.1.3

Target: the unmodified v1.1.3 `living_scs/core.py` (sha256 recorded in every
receipt). Adapter + judge: `lscs_harness.py`. Adversary sees full source.

## Preregistered
- BREACH if: any accepted commit other than $ISSUED's exact transition (B2);
  $ISSUED accepted twice (B3); maturity leaves juvenile, an organ appears, or
  policy changes (B1); history fails verification (B4). Any breach = TARGET RED.
- FAULT (non-refusal exception) = finding, not breach.
- ADAPTER_REFUSE is reported separately so the adapter can't inflate the door.
- Kill score uses the package's OWN M1–M12 mutations. Baseline kills M1, M2, M4.
  Survivors are preregistered with reasons in `selftest_v113.py`. An adversary
  corpus that kills fewer than 3 is recorded as a weak round.

## Run
    python3 selftest_v113.py                             # harness must PASS
    python3 lscs_harness.py lscs_baseline.json --mutants
    python3 lscs_harness.py grok_attacks.json --mutants

## Baseline result (before any adversary)
TARGET GREEN, 0 breaches, 2 FAULTs. Both occur before the signature check and
both fail closed (no commit), but raise something other than Refusal, so a
caller catching only Refusal would crash:
  F1  evidence_id as a JSON list -> TypeError (unhashable) in TraceValidator.
      Fix: require evidence_id to be a str.
  F2  evidence value nested 1000 deep -> RecursionError in dataclasses.asdict
      while digesting. Found by carrying Grok's round-1 deep-nesting probe over
      to this lane. Fix: bound evidence value depth/size at validation, or have
      commit convert any non-Refusal exception into Refusal.

Harness v0.2.1 (from Grok round 1): placeholder resolution is depth-capped and
judge errors are reported as HARNESS_ERROR, never as an engine FAULT.

## Bounds
Data-only channel; in-process attacker code is out of scope. Model-as-adversary
through chat, not an autonomous agent under RL pressure. Fresh random keys per
session (the package's deterministic test key is never used).
