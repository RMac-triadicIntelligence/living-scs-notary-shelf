# Living Supply-Chain Security — v1.1.5 "The Notary"

**Thesis of the line:** a self-updating system must not self-authorize. The paper
argues it; v1.1.3/v1.1.4 proved an *in-process* gate holds against a *data-only*
adversary. v1.1.5 confronts the gap the door-challenge README admitted was out of
scope — **an adversary that runs its own code in the same interpreter as the gate** —
by moving the authorization boundary off a Python object and onto an **OS process
boundary**.

The engine does not change. `core.py` is byte-identical to v1.1.4.1
(`sha256 23299fdc…`) and runs **unmodified inside** the notary process.

---

## What moved

| | v1.1.4.1 | v1.1.5 |
|---|---|---|
| Boundary | in-process `CommitEngine` object | separate **notary** process |
| Adversary channel | data-only submissions | data-only submissions **+ full in-process code** |
| Ledger of record | object attribute | held by the notary; organism never touches it |
| Pinned public key + history key | constructor args | live only in the notary's process memory |
| Trust root | (implicit) | **supervisor**: sha256-pins every file the notary executes, copies to a private run dir, re-verifies the copies, drops the notary to its own uid |

The organism **proposes** over a framed, data-only pipe (`wire.py`). The notary
**decides**, and only its ledger says what happened. This makes the door
challenge's data-only channel the actual architecture, and — for the first time on
this line — lets the in-process code-attack threat be *run*, not just declared out
of scope.

## New components (all under `v115/`)

- **`wire.py`** — the only language the notary speaks. 4-byte length + UTF-8 JSON.
  Nesting depth is counted on the **raw bytes, before any parser runs** (the
  "count the boxes at the door" fix), so no frame can make the notary recurse.
  Encoding is **iterative** (any depth at any recursion limit). Strict decode:
  UTF-8 only, duplicate keys rejected, `NaN`/`Infinity` rejected. A non-finite
  float is **not encodable on the wire** — the organism cannot even express one.
- **`notary.py`** — hosts the unmodified engine in its own process. Two channels
  that never mix (organism: `commit`/`head`; judge: `head`/`shutdown`). Reuses the
  v1.1.4 harness adapter, so its input channel is exactly the channel the 103
  corpus attempts and 20,339 fuzz trials already exercised. The config file
  (carrying the history key) is `unlink`ed at startup: the key then lives only in
  process memory, never on disk or in the environment. Faults are reported, not
  fatal.
- **`supervisor.py`** — the trust root and launcher (pin → copy → re-verify →
  drop-uid). Isolation modes: `local`, `same-uid`, `split-uid`.
- **`session.py`** — mints keys, signs the three canonical submissions
  (ISSUED-authorize, REFUSED-`set_maturity=mature`, EXPIRED), and hands the
  organism only signed envelopes + public parameters. The private key is never
  written anywhere the organism or the notary can read.
- **`organism_runner.py`** — hosts attacker **code** in the organism process with
  full Python and white-box holdings (including the path to its own copy of
  `core.py`).
- Runners: **`selftest_v115.py`** (harness status), **`run_corpus_oop.py`**
  (equivalence lane — replays a data-only corpus through the pipe),
  **`run_code_attack.py`** / **`lane_code.py`** (in-process code adversary,
  every attack × every isolation mode, verdict from the ledger),
  **`run_notary_mutants.py`** (proves the code lane can fail).
- **`attacks/`** — six in-process code adversaries (monkeypatch `verify`,
  self-issued authority, replay flood, protocol abuse, capability probe, ptrace
  reach).
- **`tests/test_v115.py`** — 29 unit + integration tests for the new surface.
- **`tools_v115/pin.py`** — computes and writes the release pins.

---

## Headline results

1. **In-process code forgery cannot move the ledger of record.** An adversary that
   loads its own copy of the engine and patches `MinatoAuthority.verify → True`
   still cannot make the notary record an unauthorized transition. Proven across
   `local`, `same-uid`, and `split-uid`. The legit ISSUED authorize is accepted
   (one record), the REFUSED target is refused, spliced and replayed envelopes are
   refused, maturity stays `juvenile`, history verifies. (Building a junk-key
   engine fails locally too: the engine binds the verifier's key to the pin in its
   constructor.)

2. **Data-only equivalence through the pipe.** The same three corpora, replayed
   over the wire, give the same verdicts as in-process, with **0 faults** and
   **0 transport errors**:
   - grok_attacks: `{ACCEPT 1, ADAPTER_REFUSE 5, REFUSE 29, WIRE_REFUSE 17}`
   - round2: `{ACCEPT 1, ADAPTER_REFUSE 5, REFUSE 27, WIRE_REFUSE 1}`
   - baseline: `{ACCEPT 1, ADAPTER_REFUSE 3, REFUSE 12, WIRE_REFUSE 1}`
   Every v1.1.3 deep-nesting / float-overflow **FAULT** is now a clean
   **`WIRE_REFUSE` at the door** — it never reaches the engine.

3. **The code lane can fail (so its GREENs mean something).** Two deliberately
   backdoored notary variants — a hidden admin op that pokes state, and a
   frame-level `force` flag that bypasses the engine — are both **caught** as
   `B1_maturity=mature`. Two other variants show the boundary's shape: a `force`
   flag *inside* the submission is caught earlier by the strict adapter
   (`ADAPTER_REFUSE`); merely loosening frame keys changes nothing, because the
   engine still checks the signature.

4. **Code-channel matrix: 18/18 GREEN, RED 0** (6 attacks × 3 isolation modes),
   with a runtime receipt recording Python/cryptography/kernel versions, the
   organism uid, and the notary pid. See `v115/receipts/lane_code_1790640833.json`.

## The finding that matters most — an honest boundary

The process boundary becomes a **trust boundary only at uid separation or above.**

`code_06b_ptrace_reach.py` does `PTRACE_ATTACH` then immediately detaches (it reads
and modifies nothing):

- **same-uid:** attach **SUCCEEDS** — this kernel has no `yama/ptrace_scope`, so a
  same-uid, OS-capable adversary *could* read the history key out of the notary's
  memory. The ledger held (attach alone changes nothing), but **confidentiality
  did not**.
- **split-uid:** attach is **DENIED** by the kernel (`Operation not permitted`).

So: the same-uid process boundary resists in-*language* attacks — monkeypatching,
object tampering, protocol abuse — but **not** OS-level same-uid debugging
(`ptrace`/`/proc/pid/mem`), which is demonstrated here rather than assumed. Real
confidentiality of the key and the ledger needs **uid separation**, and the next
rungs — container, then hardware (the project's Genesis Validator / PKCS#11 line) —
harden it further.

---

## Tests

`python3 -m unittest -v tests.test_v115` → **29/29 OK**. Covers: the wire
depth-scanner (accepts at the cap, refuses one past it, ignores brackets inside
strings, honours escaped quotes); the iterative encoder (encodes a depth-3000 value
with the recursion limit set to 300); non-finite rejection in **both** directions
(encode and decode); framing (reassembly, split frames, oversize refusal, duplicate
key, non-UTF-8); the supervisor pin gate (self-verifies, detects a single-byte
change, refuses an empty pin set); the engine's own non-finite message (N6
regression anchor); an end-to-end notary run over the pipe; and **host
recursion-limit invariance** (the grok corpus is GREEN with 0 faults at recursion
limits 300 / 1000 / 5000).

---

## Provenance & honesty

- The engine (`core.py`, `746fc5ee…` harness) is the **Grok-authored, fully
  verified v1.1.4.1** carried forward unchanged.
- The v1.1.5 **notary layer and its attack lane are Claude-authored.** That makes
  the results above **author evidence**, not adversarial evidence. The intended
  next step is a **"Lane C: code channel" door-challenge packet** that hands this
  notary to Grok and ChatGPT as code-channel adversaries, the same way the
  data-only door challenge was handed out for v1.1.3/v1.1.4.
- **Bounds, stated plainly:** the same-uid process boundary is an *in-language*
  boundary, not an OS-isolation boundary. Where confidentiality of the key/ledger
  matters, run **split-uid or stronger**. This package demonstrates that boundary
  rather than papering over it.

## Next rung

uid → container (namespaces/seccomp, no `ptrace` capability) → hardware key
custody (PKCS#11). Each rung turns the "attach succeeds" line above into "attach
denied" against a stronger adversary.

---

## Pinned files the notary executes (sha256)

```
core.py          23299fdc63361e632b0f30cc686b09eb3e2a3bb70daf66f51b7378fb5a26baa6
lscs_harness.py  746fc5ee009a62b0641611227a353706f5030f320f6b2f0c0bbced36ea0d91e6
notary.py        6b854cfabcd8b2e275f5d3d67fa9b71b3fa909eb6cea057ecb45b11536e645d8
wire.py          3c5e1600624ad6ce56d4fe5ee93b36e18ef0da1e43cab7ba20ad714c79ae23d2
```
