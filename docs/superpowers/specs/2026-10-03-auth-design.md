<!--
SPDX-FileType: DOCUMENTATION
SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0
-->

# C++26 authenticated computation

Port the tape-based design in [the Rust auth library](https://github.com/ekmett/rust/blob/main/auth/src/lib.rs) to C++26. A computation is instantiated for either a prover or a verifier. The database is passed explicitly by reference through application helpers. Hash-consed reconstruction is a separate future experiment.

## Database and proofs

Exports are explicit. `import auth;` exposes `db`, `sealed<DB, T>`, `prover`, `verifier`, and `auth_error`. `auth.hash` exports `digest` and `sha256`; `auth.serialization` exports `bytes`, `writer`, `reader`, `encode`, and `decode`. The main module imports these utilities without re-exporting them, so callers opt in to those names with separate imports. All names stay in namespace `auth`. The three modules share `auth_error` through the small `auth.error` module, which they re-export; neither utility depends on the other or on the main module.

Each database implementation supplies an associated class template `sealed<T>`. `prover::sealed<T>` contains a SHA-256 digest and a resident `T` stored directly; `verifier::sealed<T>` contains only the 32-byte digest, independent of the size of `T`. Equality and ordering use only the digest. Both serialize only the digest. Sealed-value serialization methods are private to the stream implementation. Prover serialization assumes a writing stream, documented by an invariant comment without a runtime check; verifier serialization supports both directions. Resident values stay private. Prover sealed values use implicit copy and move operations, so their copyability follows the payload type. `unseal` takes a sealed value by value: passing an lvalue copies when supported, while passing an rvalue moves. Other database implementations define their own sealed-value representation without inheritance or registration.

The `db` concept checks the associated sealed template and the `seal`/`unseal` operations using `std::uint32_t` as a representative serializable payload; C++ cannot express a universal requirement over all payload types. Actual calls instantiate and check the relevant payload type. Algorithms take `db auto& db`, use `auto` for local sealed values, and call ordinary member functions. `prover` owns its `proof` buffer directly; `verifier` owns its cursor and borrows the transcript. Both satisfy `db`, as can other implementations. Callers pass their database directly, for example `go(p)` or `go(v)`, and helpers pass the same reference onward. Data structures that store sealed values are parameterized by the database type and can use `sealed<DB, T>` to select its associated sealed template. The alias strips reference qualifiers from the database type, so `sealed<decltype(db), T>` also works for a `db auto& db` parameter.

`seal` hashes the serialized value. The prover retains that value; the verifier discards it. Prover `unseal` serializes the resident value to `proof` and returns it by move. Verifier `unseal` decodes the next value, hashes exactly the consumed bytes against the supplied digest, and returns the reconstructed value.

The proof is a flat byte vector containing concatenated openings without external framing. The verifier borrows its storage, retains a fixed end pointer, and advances only its front cursor. The proof buffer must outlive the verifier and remain unchanged during replay. A finish check rejects unused bytes. Truncation, malformed values, and digest mismatches raise exceptions in release builds too. An opening advances the cursor only after successful decoding, verification, and construction of the returned value. Zero-byte values consume no proof bytes.

## One serialization definition

Use [Gaffer on Games' shared read/write stream approach](https://gafferongames.com/post/serialization_strategies/): application types define one templated `serialize` function, and the stream type determines the direction at compile time. Provide a `Stream::reading` constant for structural branches. C++ explicit object parameters allow that same member definition to access const fields while writing and mutable fields while reading.

The initial format is byte-aligned: fixed-width unsigned integers in little-endian order, validated one-byte booleans and variant tags, and raw bytes for digests. Encode fields individually, never object padding or pointer values. Add only the primitives needed by the tree demonstration and serializer checks. Deserialization constructs an initially empty/default value and validates every read. `decode<T>(span)` returns a pair containing the value and a pointer immediately after its consumed bytes; the caller retains the original end. That pointer borrows the input storage. Trailing bytes are available to subsequent decodes. Invalid application discriminants fail through the same exception mechanism. Serialization definitions must be deterministic and preserve values on writing.

SHA-256 hashes exactly the serialized bytes of a value, including only the digests of child sealed values. Use the installed OpenSSL implementation. There is no requirement to reproduce Rust's JSON or SHA-1 hashes. Type information is supplied by the computation rather than encoded as global type identifiers.

## Files and verification

The module interfaces are `auth.ccm` (`auth`), `hash.ccm`, `serialization.ccm`, and `error.ccm`. `auth-test.cc` exercises the implementation and includes build commands using the installed Homebrew LLVM and OpenSSL. `auth-api-test.cc` exercises the public database API while importing only `auth`. CMake builds the module library and CTest executables; optional Doxygen documentation lives under `doc/`.

Verify deterministic integer bytes and a known SHA-256 vector; serializer round trips and truncated input; sealed-value serialization omitting resident values; the Rust tree traversal returning the same result in prover and verifier modes; and rejection of altered, missing, or unused proof bytes. Exercise a third database implementation and interleave independent prover and verifier objects to check state separation. Confirm invalid proofs remain rejected with `NDEBUG` enabled, run AddressSanitizer and UndefinedBehaviorSanitizer, and disable copy elision to test preservation of the verifier cursor when a return move throws.
