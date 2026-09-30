# lab4 proof scripts: v1.1.3 (before) vs v1.1.4 (after) - key lines, verbatim

## p1_art_toctou.py
| v1.1.3 | v1.1.4 |
|---|---|
| `NOTE: snapshot reads content ONCE into local, then hashes same local -> no TOCTOU` | `NOTE: snapshot reads content ONCE into local, then hashes same local -> no TOCTOU` |
| `stored reason: TAMPERED` | `stored reason: authorized mutation` |

## p1_hist_restore.py
| v1.1.3 | v1.1.4 |
|---|---|
| `=== verify_history: is record_hash keyed? can we forge a record? ===` | `=== verify_history: is record_hash keyed? can we forge a record? ===` |
| `verify_history after forged append: True` | `verify_history after forged append: True` |
| `-> record_hash is unkeyed sha256; anyone with list write access can forge a valid chain` | `-> record_hash is unkeyed sha256; anyone with list write access can forge a valid chain` |
| `-> restore fabricated: Refusal restore requires a known historical snapshot` | `[keyed] verify_history after legit commit: True` |
| `Traceback (most recent call last):` | `[keyed] verify_history after forged append (attacker sha256): False` |
| `AttributeError: property 'content' of 'LyingArtifact' object has no setter` | `[keyed] verify_history after forged append (HMAC with wrong key): False` |
| `` | `[keyed] commit on forged history -> Refusal history integrity failure` |
| `` | `-> restore fabricated: Refusal restore requires a known historical snapshot` |
| `` | `Traceback (most recent call last):` |
| `` | `AttributeError: property 'content' of 'LyingArtifact' object has no setter` |

## p1_hook_record_alias.py
| v1.1.3 | v1.1.4 |
|---|---|
| `hook record is stored record: True` | `hook record is stored record: False` |
| `verify_history before: True` | `verify_history before: True` |
| `stored reason now: TAMPERED` | `stored reason now: authorized mutation` |
| `verify_history after: False` | `verify_history after: True` |
| `public records[0] is internal: True` | `public records[0] is internal: False` |
| `verify_history after tampering via public .records: False` | `verify_history after tampering via public .records: True` |
| `history_snapshot -> Refusal history integrity failure` | `` |

## p1_is_sha256.py
| v1.1.3 | v1.1.4 |
|---|---|
| `plain64          len=64 is_sha256=True` | `plain64          len=64 is_sha256=True` |
| `upper            len=64 is_sha256=True` | `upper            len=64 is_sha256=False` |
| `leading_space    len=64 is_sha256=True` | `leading_space    len=64 is_sha256=False` |
| `trailing_space   len=64 is_sha256=True` | `trailing_space   len=64 is_sha256=False` |
| `underscore       len=64 is_sha256=True` | `underscore       len=64 is_sha256=False` |
| `plus_sign        len=64 is_sha256=True` | `plus_sign        len=64 is_sha256=False` |
| `0x_prefix        len=64 is_sha256=True` | `0x_prefix        len=64 is_sha256=False` |
| `newline          len=64 is_sha256=True` | `newline          len=64 is_sha256=False` |
| `real_digest      len=64 is_sha256=True` | `real_digest      len=64 is_sha256=True` |

## p1_misc.py
| v1.1.3 | v1.1.4 |
|---|---|
| `commit at now==expires_at: 9038b97f25a896a6 ACCEPT` | `commit at now==expires_at: 9038b97f25a896a6 ACCEPT` |
| `-> expired+1: Refusal authorization expired` | `-> expired+1: Refusal authorization expired` |
| `-> future skew: Refusal trusted clock rollback detected` | `-> future skew: Refusal trusted clock rollback detected` |
| `=== Enum identity: in-process auth with raw string decision ===` | `=== Enum identity: in-process auth with raw string decision ===` |
| `built raw-decision auth; decision= 'authorize'` | `built raw-decision auth; decision= 'authorize'` |
| `-> commit: AttributeError 'str' object has no attribute 'value'` | `-> commit: Refusal malformed input: auth.decision must be a Decision` |
| `-> commit: Refusal result digest mismatch` | `-> commit: Refusal result digest mismatch` |

## p1_more.py
| v1.1.3 | v1.1.4 |
|---|---|
| `=== confirm raw-str-decision fault leaves nothing committed ===` | `=== confirm raw-str-decision fault leaves nothing committed ===` |
| `raised: AttributeError 'str' object has no attribute 'value'` | `raised: Refusal malformed input: auth.decision must be a Decision` |
| `state changed: False` | `state changed: False` |
| `-> forged-key commit: Refusal invalid authorization signature` | `-> forged-key commit: Refusal invalid authorization signature` |
| `ACCEPT remove_organ 47638fff12b739ab state: {'maturity': 'juvenile', 'personality': {'tone': 'humble'}, 'organs': {}, 'policy': {'egress': 'deny'}}` | `ACCEPT remove_organ 47638fff12b739ab state: {'maturity': 'juvenile', 'personality': {'tone': 'humble'}, 'organs': {}, 'policy': {'egress': 'deny'}}` |

## p1_persisthook_raises.py
| v1.1.3 | v1.1.4 |
|---|---|
| `commit raised: RuntimeError durable write failed` | `commit raised: RuntimeError durable write failed` |
| `state changed by failed hook: False` | `state changed by failed hook: False` |
| `records: 0 nonces: 0` | `records: 0 nonces: 0` |

## p1_reentrancy.py
| v1.1.3 | v1.1.4 |
|---|---|
| `hook calls: 2` | `hook calls: 1` |
| `reentrant_result: 9038b97f25a896a6` | `reentrant_result: None` |
| `reentrant_exc: None` | `reentrant_exc: Refusal: re-entrant commit refused: a commit is already in progress on this engine` |
| `num records: 2` | `num records: 1` |
| `record sequences: [1, 1]` | `record sequences: [1]` |
| `verify_history: False` | `verify_history: True` |
| `used_nonces: 1 used_dets: 1` | `used_nonces: 1 used_dets: 1` |

## p1_toctou.py
| v1.1.3 | v1.1.4 |
|---|---|
| `commit -> TraceError trace/proposal mismatch` | `commit -> TraceError trace/proposal mismatch` |

## p2_verify_accepts.py
| v1.1.3 | v1.1.4 |
|---|---|
| `S+L rejected: InvalidSignature` | `S+L rejected: InvalidSignature` |
| `UPPERCASE hex sig VERIFIES (same bytes)` | `UPPERCASE hex sig VERIFIES (same bytes)` |

