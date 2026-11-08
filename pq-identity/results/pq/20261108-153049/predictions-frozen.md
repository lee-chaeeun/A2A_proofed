# Frozen predictions — PQ identity matrix (declared 2026-11-08 before the first run)

Columns: C+tls | EC-env+tls | EC-env+cb | PQ-env+tls | PQ-env+cb | PQ-file+cb | PQ-device+tls | PQ-device+cb. A/B = task delivered to that deployment; R = rejected; N = accepted but dispatch refused before send (no recipient).

| id | scenario | C+tls | EC-env+tls | EC-env+cb | PQ-env+tls | PQ-env+cb | PQ-file+cb | PQ-device+tls | PQ-device+cb |
|---|---|---|---|---|---|---|---|---|---|
| P1 | honest A, one delivery | A | A | A | A | A | A | A | A |
| P2 | recorded proof replayed against a fresh nonce | R | R | R | R | R | R | R | R |
| P3 | context tamper: relay changes the action of the forwarded challenge | B | R | R | R | R | R | R | R |
| P4 | wrong enrolled key: B presents its own genuine keys under A's key ids | B | R | R | R | R | R | R | R |
| P5 | algorithm confusion / classical fallback | B | R | R | R | R | R | R | R |
| P6 | application volume copied (incl. PQ-file seed) + A's TLS credentials, no signer access | B | R | R | R | R | B | R | R |
| P7 | address hijack without TLS credentials | R | R | R | R | R | R | R | R |
| P8 | relay with A's TLS credentials, untouched forwarding | B | B | R | B | R | R | B | R |
| P9 | relay + binding strip, exporter injection, chosen nonce and cross-policy forward | B | R | R | R | R | R | R | R |
| P10 | valid proof, then proof connection closed and A's name repointed to B before dispatch | N | N | N | N | N | N | N | N |
| P11 | two concurrent deliveries for one session | A | A | A | A | A | A | A | A |
| P12 | classical-compromise surrogate: A's TLS credentials + EC signer access, no PQ key | B | B | B | R | R | R | R | R |
| X1 | boundary control: A's TLS credentials + PQ software signer and device signer access | B | R | R | B | B | B | B | B |
| X2 | boundary control: copy of A's emulator NV file in a third fwTPM instance + A's authValue | B | R | R | R | R | B | B | B |
| X3 | boundary control: attacker-generated ML-DSA key presented under A's key ids | B | R | R | R | R | R | R | R |
| X4 | boundary control: PQ-file key rotated in the registry (version 2) while the copied volume holds version 1 | B | R | R | R | R | R | R | R |

Notes:
* P2: C+tls rejects at endpoint equality (card declares A's origin); proof arms at nonce/context
* P3: the honest signer signs the tampered action; the requester compares with its own issued context
* P4: signature does not verify under A's pinned key; includes another deployment's genuine ML-DSA key
* P5: closed algorithm set pinned per policy base; no downgrade
* P6: only the volume-held PQ key is copied; gated and device keys are not
* P7: TLS name check
* P8: the measured relay: binding, not the algorithm, decides
* P9: under +tls arms the rewrite is self-defeating (reject), not protection; P8 is the working attack there
* P10: dispatch refused before any task byte; no receipt anywhere (C+tls pins the discovery connection)
* P11: exactly one release, to A
* P12: capability surrogate, not a quantum attack: B is granted the classical secret and not the independently enrolled PQ key
* X1: authorized signing reproduces the capability (and the copied volume carries the PQ-file key)
* X2: emulator state is a file; the clone reproduces the device key capability (PQ-file from the copied volume)
* X3: key substitution rejected under the pinned public key
* X4: the pinned key id/version rejects the stale copied key

P11 predicts exactly one release per cell. Boundary controls X1/X2 are expected attacker successes that bound the simulated device model: authorized signing or state cloning reproduces the capability.
