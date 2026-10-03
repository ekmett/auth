# C++26 authenticated computation

Port the tape-based design in [the Rust auth library](https://github.com/ekmett/rust/blob/main/auth/src/lib.rs) to C++26. A computation is instantiated for either a prover or a verifier. Its database state is implicit, following the scoped context mechanism in `/Users/ekmett/jitney/jitney.ccm`. Hash-consed reconstruction is a separate future experiment.

## Database and proofs

`proof<T>` contains a SHA-256 digest and an optional resident `T`. Equality and ordering use only the digest. Serialization writes only the 32 digest bytes; reading produces a proof without a resident value. Keep the value private so callers cannot mutate it after its digest is computed. Recursive application types use explicit indirection as in the Rust tree example.

Computations use `template<class Db>` and call `Db::auth(value)` and `Db::unauth(std::move(proof))`. Neither operation nor application helpers take a database argument. `auth` hashes the serialized value. The prover retains that value; the verifier discards it. Prover `unauth` serializes the resident value onto the tape and returns the value by move. Verifier `unauth` checks the next tape entry against the supplied digest, deserializes it, and returns the reconstructed value.

The tape is a vector of byte buffers, preserving one frame per opening, as the Rust implementation preserves one string per opening. The verifier borrows an immutable tape and owns its cursor. The tape must outlive the verifier and remain unchanged during replay. A finish check rejects unused entries. Truncation, missing resident values, malformed values, and digest mismatches raise exceptions in release builds too. An opening advances the cursor only after successful verification and decoding.

## Implicit context

An RAII `db_scope` binds a concrete prover or verifier backing object and restores the previous binding on destruction, including exception unwinding. A shared backing base records the mode; accessing the context with the wrong `Db` or without an active scope fails before accessing mode-specific state. This avoids unchecked casts from an arbitrary pointer.

The default active-context pointer is `thread_local`. An opt-in AArch64 build reserves `x28` using `-ffixed-x28` for every participating translation unit, following jitney. Both forms expose the same API. Scopes are noncopyable and nonmovable. Register builds establish a scope at every entry or foreign callback boundary. Context scopes do not cross coroutine suspension or thread migration.

## One serialization definition

Use [Gaffer on Games' shared read/write stream approach](https://gafferongames.com/post/serialization_strategies/): application types define one templated `serialize` function, and the stream type determines the direction at compile time. Provide a `Stream::reading` constant for structural branches. C++ explicit object parameters allow that same member definition to access const fields while writing and mutable fields while reading.

The initial format is byte-aligned: fixed-width unsigned integers in little-endian order, validated one-byte booleans and variant tags, and raw bytes for digests. Encode fields individually, never object padding or pointer values. Add only the primitives needed by the tree demonstration and serializer checks. Deserialization constructs an initially empty/default value, validates every read, and requires the frame to be consumed completely. Invalid application discriminants fail through the same exception mechanism. Serialization definitions must be deterministic and preserve values on writing.

SHA-256 hashes exactly the serialized bytes of a value, including only the digests of child proofs. Use the installed OpenSSL implementation. There is no requirement to reproduce Rust's JSON or SHA-1 hashes. Type information is supplied by the computation rather than encoded as global type identifiers.

## Files and verification

Start with `auth.ccm`, following jitney's module style, and one `auth-test.cc` with documented build commands using the installed Homebrew LLVM and OpenSSL. Do not introduce a build framework for this experiment.

Verify deterministic integer bytes and a known SHA-256 vector; serializer round trips and truncated input; proof serialization omitting resident values; the Rust tree traversal returning the same result in prover and verifier modes; and rejection of altered, missing, or unused tape entries. Exercise nested context restoration, restoration after exceptions, wrong/missing contexts, and thread isolation. Build and run the same checks with TLS and reserved `x28`, and confirm invalid proofs remain rejected with `NDEBUG` enabled.
