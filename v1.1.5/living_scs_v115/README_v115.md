# Living SCS v1.1.5 — how to run

Start with `CHANGELOG_v115.md` for what this is and why. This file is just the
run sheet.

## Layout
```
v114/living_scs_v114/core.py   engine, byte-identical to v1.1.4.1 (23299fdc…)
v114/lscs_harness.py           the data-only adapter the notary reuses
v114/*.json                    corpora: grok_attacks, round2_attacks, lscs_baseline
v115/                          the notary layer (new in v1.1.5)
  wire.py notary.py supervisor.py session.py organism_runner.py
  selftest_v115.py run_corpus_oop.py run_code_attack.py lane_code.py run_notary_mutants.py
  attacks/                     six in-process code adversaries
  tests/test_v115.py           29 unit + integration tests
  tools_v115/pin.py            recompute release pins
  receipts/                    runtime receipts from the code-channel matrix
MANIFEST_v115.sha256           sha256 of every shipped file
```

## Requirements
- Python 3.12+, `cryptography`. No network.
- `local` mode runs as the current user and needs no privileges.
- `same-uid` / `split-uid` create/drop to the users `lscs_notary` (uid 1001) and
  `lscs_organism` (uid 1002) and therefore need **root** to launch. Create them with:
  ```
  useradd -M -s /usr/sbin/nologin lscs_notary
  useradd -M -s /usr/sbin/nologin lscs_organism
  ```
- Pins are already filled in `supervisor.py`. To recompute after any change to a
  pinned file: `python3 v115/tools_v115/pin.py`.

## Run (from the `v115/` directory)
```
python3 selftest_v115.py                      # harness status, local mode
python3 -m unittest -v tests.test_v115        # 29/29 OK

# equivalence lane — data-only corpus through the notary pipe
python3 run_corpus_oop.py ../v114/grok_attacks.json
python3 run_corpus_oop.py ../v114/round2_attacks.json
python3 run_corpus_oop.py ../v114/lscs_baseline.json

# in-process CODE adversary; verdict comes only from the notary ledger
python3 run_code_attack.py attacks/code_01_monkeypatch_verify.py --isolation local
sudo python3 run_code_attack.py attacks/code_01_monkeypatch_verify.py --isolation same-uid
sudo python3 run_code_attack.py attacks/code_01_monkeypatch_verify.py --isolation split-uid

# full code-channel matrix (every attack × every isolation), writes a receipt
sudo python3 lane_code.py

# proof the code lane can fail: shipped notary GREEN, two backdoored variants caught
python3 run_notary_mutants.py
```

## The one result to read
`sudo python3 run_code_attack.py attacks/code_06b_ptrace_reach.py --isolation same-uid`
vs `--isolation split-uid`. same-uid: attach **succeeds** (this kernel has no
`yama/ptrace_scope`) — an OS-capable same-uid adversary could read the notary's
in-memory key. split-uid: attach **denied** by the kernel. The ledger holds in both;
confidentiality only becomes real at uid separation. That is the boundary v1.1.5
establishes, and the reason the next rung is container/hardware.
