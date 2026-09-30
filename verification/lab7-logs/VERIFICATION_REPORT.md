# Independent Verification — Living SCS v1.1.5 "The Notary"

Verifier: executor subagent, for Rusty. Date: 2026-09-28 (America/Chicago).
Work dir: `/workspace/lab7/`. Package under test:
`.../attachments/dc31e3f9163dde866822e2185936cd6ec9d44f2b54fa3a93c7c0e4c15e1fbd18.zip`
sha256 `dc31e3f9163dde866822e2185936cd6ec9d44f2b54fa3a93c7c0e4c15e1fbd18`, extracts to `living_scs_v115/`.

## Environment
- Box: Linux `6.12.94+`, x86_64. Python `3.13.5`, cryptography `43.0.0`. (Shipped receipt was built on Python 3.12.3 / cryptography 46.0.6 / kernel 6.18.44 — different host, results still reproduce.)
- `/proc/sys/kernel/yama/ptrace_scope`: **absent** on this box (`cat` → No such file or directory) ⇒ same-uid ptrace is unrestricted, exactly as the package claims.
- I have passwordless root here, so I could create the `lscs_notary`/`lscs_organism` users and run the full split-uid matrix. Users were created per the README, used, then deleted; a throwaway user was used for the interpreter-isolation test. No changes left on the box outside `/workspace/lab7`.

## Protected labs untouched
Hashed every file in `lab, lab2..lab6` before and after (282 files each). `diff` of the two hash sets is empty →
**PROTECTED LABS UNCHANGED**. (`before_hashes.txt`, `after_hashes.txt`.)

---

## Claim-by-claim

| # | Claim | Verdict | Key evidence line |
|---|-------|---------|-------------------|
| 1 | Manifest verifies 29/29 from fresh extract; no unlisted/missing; no `__pycache__` shipped | **YES** | `sha256sum -c MANIFEST_v115.sha256` → 29 OK / 0 fail; `comm` of listed vs actual = identical 29/29; zip contains **no** `__pycache__`/`.pyc` |
| 2 | `core.py` byte-identical to v1.1.4.1 (`23299fdc…`) | **YES** | `v115/core.py`, `v114/living_scs_v114/core.py` and `lab5/v114/living_scs_v114/core.py` all sha256 `23299fdc6336…`; `cmp` IDENTICAL. Also identical to lab5: `lscs_harness.py` (`746fc5ee…`), and all three corpora JSONs. |
| 3 | Test suite 29/29, cold from fresh extract, unprivileged | **YES** | fresh `cold/` extract, uid=1000: `Ran 29 tests … OK`, 29 `... ok`, 0 FAIL/ERROR/skip |
| 4 | Default-PINS launch works; one-byte change to a pinned source refused at launch; supervisor.py unpinned = gap | **PARTIAL — important caveat** | Default launch: `LAUNCH OK (default PINS); ISSUED -> ACCEPT seq 1`. One-byte flip: `LAUNCH REFUSED PinMismatch: wire.py …`, `… notary.py …`. **BUT** the refusal only fires on the default `pins=None` path. Every shipped runner passes `pins=supervisor.pins_for(ROOT)`, which *recomputes* pins from disk, so the gate is a **no-op there** (proven: tampered `notary.py` launches GREEN via `run_code_attack.py`/`selftest`). And `supervisor.py`/`session.py`/`organism_runner.py` are unpinned: editing `notary.py` + the `PINS` line in `supervisor.py` yields a working backdoor that passes the default gate. |
| 5 | 3 corpora GREEN, 0 faults, 0 transport errors; prior deep-nest/float-inf FAULTs now WIRE_REFUSE | **YES** | grok `{ACCEPT 1, ADAPTER_REFUSE 5, REFUSE 29, WIRE_REFUSE 17}`; round2 `{…REFUSE 27, WIRE_REFUSE 1}`; baseline `{…REFUSE 12, WIRE_REFUSE 1}`. faults=0, transport_errors=0, all GREEN. lab5 v1.1.3 rows that were `FAULT` (RecursionError deep-nesting, `float_overflow_to_inf`) are now `WIRE_REFUSE`. |
| 6 | In-process code attacks can't move the ledger; 18/18 GREEN across local/same-uid/split-uid; junk-key build fails on pin binding | **YES** | `lane_code.py` as root: **GREEN=18 RED=0** across all three isolation modes. code_01 self-report: `local engine err: authority public key does not match the configured pin` (junk-key build fails); spliced/replayed/self-signed all `REFUSE`; ledger stays `records≤1, maturity juvenile, verify_history True`. |
| 7 | Two backdoored notary variants caught (B1_maturity=mature) | **YES** | `run_notary_mutants.py`: shipped `GREEN`; `NM1_hidden_admin_op RED B1_maturity=mature (caught)`; `NM2_frame_force_bypass RED B1_maturity=mature (caught)` → the attack lane can genuinely fail. |
| 8 | code_06b ptrace: same-uid ATTACH succeeds (no yama), split-uid denied | **YES** | same-uid: `ptrace_attach: SUCCESS - notary memory is reachable by this uid`; split-uid: `DENIED: Operation not permitted`. code_06 capability probe agrees: split-uid `/proc/<pid>/{mem,environ,maps}` = PermissionError, signal = PermissionError. Box has no `yama/ptrace_scope`. |
| 9 | Code review for holes | see below | — |

---

## Review findings, ranked by severity (file:line)

### H1 — Launch pin gate is bypassed by every shipped runner (the pin claim does not hold as advertised)
`supervisor.py:102-111` verifies against whatever `pins` it is handed. The default (`pins=None → supervisor.PINS`) is the real gate, but **all five runners** hand it freshly recomputed pins instead:
`run_code_attack.py:29-30`, `lane_code.py:39`, `run_corpus_oop.py:62`, `selftest_v115.py:25-26`, `run_notary_mutants.py:42-43`, plus `tests/test_v115.py:242`, all pass `pins=supervisor.pins_for(ROOT)`. `pins_for` (`supervisor.py:50`) just sha256s the current files, so pinned-vs-actual always matches → the gate is a no-op on every path a user actually runs.
Proven: a one-byte edit to `notary.py` **launches GREEN** through `run_code_attack.py` and `selftest_v115.py` (`out_4_pins.txt` sections C/C2; `out_9_pinpath.txt`). Only the hand-written default-PINS launch refuses it. So claim 4's "refused at launch" is true only for a code path the shipped tooling never uses. **The single-byte-change test in `test_v115.py:183` tests `verify()` in isolation, not the launch path the runners take — so the green test does not cover the gap.**

### H2 — Notary interpreter is not isolated (`-I`); user-site / `PYTHON*` runs inside the notary and CAN move the ledger at same-uid
`supervisor.py:123-126` launches `[sys.executable, copies["notary.py"], …]` with **no `-I`/`-S`/`-s`** and an env that still allows Python's user site-packages. So `usercustomize.py` in the notary account's `~/.local/.../site-packages` executes **inside the notary before `notary.py`**, even though all four pinned files are byte-identical and the default gate passes.
Demonstrated (throwaway user with a writable home, modeling local / same-uid where the notary account's home is writable by the attacker): planted `usercustomize` patches `MinatoAuthority.verify → True` in the notary's own engine; then a forged AUTHORIZE (bad signature) over `set_maturity=mature` is **ACCEPTED**:
```
pins verified (default supervisor.PINS), notary launched pid …
forged AUTHORIZE (bad sig) -> ACCEPT
LEDGER: records 1 maturity mature verify_history True
```
(`out_9_usersite.txt`.) This is a **ledger integrity** break, not just confidentiality, and it needs **no ptrace/OS-debug capability** — only write access to the notary user's Python user-site. Reachability by mode: the notary env has no `HOME`, so Python resolves user-site from the passwd home. **local** mode: notary and organism are the same account (e.g. `box`), so organism code in session N can plant `~/.local/lib/python3.X/site-packages/usercustomize.py` and **every later notary launch** is compromised (cross-session persistence; the notary of the *current* session is already running). **same-uid**: out of the box `useradd -M` leaves `/home/lscs_organism` absent and `/home` root-owned, so not push-button unless that home exists and is writable. **split-uid**: blocked (organism can't write the notary user's home). Still, it contradicts the README's framing that at same-uid "the ledger held" and only *confidentiality* fails to ptrace: a same-uid adversary who can write the notary account's home moves the ledger. Fix: launch with `python3 -I` (and/or set `PYTHONNOUSERSITE=1`, unset `HOME`). Note the env already sets `PYTHONDONTWRITEBYTECODE=1` but not the isolation flags.

### M1 — Wire depth scanner is a counter that can go negative (frame desync latent)
`wire.py:51-69` `check_depth` decrements on every `}`/`]` with no floor and no balance check. A frame with leading closers drives `depth` negative, so a later legitimately-deep subtree can exceed 96 real levels while the counter reads ≤96 and passes the gate. On the shipped path the follow-on `json.loads` rejects the malformed text, so today it is contained (`out_9_negdepth.txt`: check_depth passes, decode raises `bad JSON`). But depth safety is asserted "before any parser runs"; a future refactor that reorders or hardens the parser could expose it. Low exploitability now, but the invariant is weaker than documented.

### M2 — Float-overflow *literals* (`1e999`) bypass the wire's non-finite guard
`wire.py:88-92` blocks `NaN`/`Infinity` tokens via `parse_constant`, but a numeric literal like `1e999`/`1e400` decodes to `float('inf')` **without** triggering `parse_constant`, so a non-finite float *does* cross the wire into the engine. README/CHANGELOG say "a non-finite float is not encodable on the wire … the organism cannot even express one" — that is true for the organism's own `encode()` (`wire.py:122-125`) but **false for the decode side** the notary applies to attacker-controlled raw frames. Confirmed: `wire.decode(b'{"x": 1e999}') → {'x': inf}`. It is caught one layer deeper by the engine's own non-finite walker (`REFUSE: non-finite number in proposal.evidence[0].value`, `out_9_raw_wire.txt`), so no breach — but the "can't be expressed on the wire" claim is inaccurate; the real backstop is the v1.1.4 engine, not the wire.

### L1 — supervisor/session/organism_runner unpinned (as Claude states)
`tools_v115/pin.py:1-3` and `SOURCES` (`supervisor.py:31-32`) deliberately exclude `supervisor.py`. That is defensible for `supervisor.py` (it *is* the trust root; whoever edits it already owns the launch). But `session.py` (mints keys, signs the canonical envelopes) and `organism_runner.py` are also unpinned and are executed in-process by the runners; combined with H1 this widens the "who can edit a file and still pass the gate" surface. Whoever can write these files owns the outcome. Concrete: `out_4_pins.txt` section D — editing `notary.py` + the `PINS` literal gives a working `grow_up` backdoor that passes the default gate.

### Positives confirmed (no issue)
- History key is **not** passed via argv/env: it rides in the config JSON file whose path is on argv, and `notary.py:260` `os.unlink(cfg_path)` removes it at startup; `/proc/<pid>/environ` shows only `PATH`/`PYTHONDONTWRITEBYTECODE` (code_06 probe). Key lives only in notary memory. Good.
- Organism cannot influence the notary's argv/PINS/paths: the supervisor builds argv and copies sources; the organism only gets pipe fds + signed material + its own `core.py` copy path (`organism_runner.py:322`). `notary.py` loads core/harness from its own `HERE` (`notary.py:198-199`), never an organism-supplied path.
- Channel separation holds: organism ops limited to `commit`/`head` with strict field-set equality (`notary.py:241-245`); judge-only `shutdown` is unreachable from the organism channel.
- Pipe framing: 4-byte length prefix, `MAX_FRAME` 2 MB enforced on both declared and actual length (`wire.py:26-48`), non-blocking, duplicate-key and non-UTF-8 rejected. `check_depth` on 2 MB string ≈0.10s (no DoS).
- Time source is `TrustedClock(cfg["clock_t0"])` fixed at config build; organism has no path to advance it.

---

## What I could not / did not do
- Everything ran. split-uid required root + the two nologin users; I had passwordless root, created them per the README, ran the full 18-cell matrix (GREEN=18/RED=0), then deleted the users. If you reproduce on a box without root, split-uid rows can't run and `lane_code.py` auto-restricts to `local`+`same-uid` (`lane_code.py:332`).
- H2 was demonstrated with a throwaway user that has a writable home (models local / same-uid-with-home). I intentionally did **not** plant anything in the shared `box` account's real `~/.local`.

## Bottom line
The engine-carry-forward (claims 2), manifest (1), tests (3), equivalence lane (5), code-attack matrix (6), mutant lane (7), and ptrace boundary (8) all **reproduce exactly**. The two things to flag to Rusty: (H1) the launch-time pin gate is effectively **off** on every runner the package ships, so "a one-byte source change is refused at launch" holds only on a code path nobody runs; and (H2) the notary interpreter isn't isolated, so at local/same-uid an attacker who can write the notary account's Python user-site can move the **ledger** (not just read the key), which is stronger than the ptrace-only caveat the README admits. Both are launch-hygiene fixes (`-I`, and gate against the frozen `PINS` constant, not recomputed pins), not engine problems.
