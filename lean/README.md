# Auth laws

<!--
SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0
-->

A small Lean model of the laws behind `auth`, with explicit toy assumptions.
The point is to rule out classes of transcript and cursor errors rather than
check a collection of examples.

With Lean 4.24.0 installed:

```sh
python3 lean/check.py
```

The script uses only Lean's `Std`, compiles from scratch with warnings as errors,
and audits the axioms used by twenty definitions and theorems. It writes the
commands, exit codes, axiom output and source hashes to `lean/verification.txt`.
The toolchain is pinned in `lean-toolchain`; no Mathlib dependency is needed.

## Codecs

`AuthCodec.lean` makes the prefix law explicit:

```
decode (encode x ++ suffix) = some (x, encode x, suffix)
```

The suffix matters. Round-tripping an isolated value doesn't establish that
concatenating openings is safe. Successful decoding must also partition its
input into the bytes consumed and the suffix left over.

The file proves these laws for zero-byte Unit, a byte, checked Boolean tags,
and sequential pairs. Encoding injectivity and prefix-freedom follow for each
codec. These laws are obligations for custom serializers, not consequences of
their C++ signatures. They don't distinguish encodings of different types.

`Representation` relates resident prover values to verifier values by erasure
and equal serialized bytes. Pairing preserves that relation. A nested sealed
field erases its resident payload and keeps its digest.

## Cursor and commitments

`AuthVerifier.lean` models local decoding, hashing exactly the consumed bytes,
and committing the external cursor after successful return construction.

- `seal_correspondence`: sealing corresponding values gives the same digest.
- `checked_authentic`: under binding at the expected commitment, an accepted
  opening has the expected value and exact bytes.
- `rejection_unchanged`: failure leaves the external cursor unchanged, including
  failure during final return construction.
- `success_exact` and `cursor_conservation`: success consumes exactly the checked
  prefix, stays within the input, and preserves its total extent.
- `finish_iff`: finishing succeeds exactly when the remaining bytes are empty.

`Resident` carries the seal-time invariant relating its value and digest;
`makeSealed` establishes it. `sealedRepresentation` serializes only the digest
of such a coherent resident value.

## Replay

`AuthReplay.lean` allows later openings to depend on earlier decoded values.
It proves both directions we need:

- `honest_replay`: the prover's transcript replays to the same observation and
  leaves any following suffix untouched. This needs no binding assumption.
- `accepted_replay`: under binding at the commitments on the honest path,
  accepted replay has that same observation and consumes exactly that transcript.

There is no binding obligation for branches that authentic replay never takes.
`honest_finish` rejects nonempty extensions of an honest transcript.

Zero-byte values are a useful boundary case: opening Unit need not advance the
cursor. `zero_byte_event_ambiguity` proves that different numbers of openings
can produce identical bytes. `finish()` establishes byte exhaustion, not an
opening count or a unique computation.

## Assumptions and scope

`BindingAt hash committed` says that a candidate with the same digest has the
same bytes. It is a theorem parameter, not an axiom about SHA-256. This perfect
binding premise is stronger than computational collision resistance. The
identity hash on byte strings supplies a consistent toy instance; a security
argument for SHA-256 would need an adversary model and a reduction.

Encoding is pure, deterministic and stable after sealing. Custom codecs must
satisfy the prefix and partition laws, and related representations must emit
the same bytes. This model proves byte/Boolean/Unit/pair instances, not the C++
integer loops, arrays, variants, allocations or arbitrary custom serializers.

The replay program is terminating and uses one resident/verifier representation
throughout. Both sides follow the same continuation on the erased visible
value. Resident payloads in requests are ghost witnesses for the commitments;
verifier replay uses only their digests. This models representation-respecting
use of the database interface, not arbitrary C++ callbacks or a heterogeneous
family of payload types.

Replay describes successful prover executions. The C++ prover appends an opening
before returning its value, so a throwing return can leave bytes appended. The
verifier commits its cursor only after successful return construction. We prove
its rollback law separately and do not claim prover rollback.

The input remains immutable and serializers don't mutate the external cursor
reentrantly. C++ object lifetime, pointer arithmetic, unwinding, machine integer
bounds, compiler output and SHA-256 implementation remain refinement obligations.

## Correspondence to the implementation

The model was checked against `b21de16ac0a69177b6ebd9adba833c25b60c0dee`.

| Implementation | Model |
|---|---|
| [`encode`/`decode` and field order](../src/auth/serialization.ccm) | Codec prefix and partition laws |
| [`prover::sealed`, `seal`](../src/auth.ccm) | Resident coherence, digest-only erasure and seal correspondence |
| [`prover::unseal`](../src/auth.ccm) | Successful transcript append order |
| [`verifier::unseal`](../src/auth.ccm) | Local checked decode, then transactional cursor commit |
| [`verifier::finish`](../src/auth.ccm) | Byte exhaustion |

The proofs establish the model's laws. They are not an automatic translation or
an end-to-end verification of the C++ implementation. `Check.lean` lists the
axiom audits; only Lean's standard `propext`, `Classical.choice` and `Quot.sound`
appear. There are no admitted proofs or additional axioms.
