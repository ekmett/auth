# auth

<!--
SPDX-FileType: DOCUMENTATION
SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0
-->

<!-- badges:start -->
[![build + docs](https://img.shields.io/github/actions/workflow/status/ekmett/auth/build.yml?branch=main&style=flat&label=build+%2B+docs&logo=githubactions&logoColor=white)](https://github.com/ekmett/auth/actions/workflows/build.yml?query=branch%3Amain)
[![proofs](https://img.shields.io/github/actions/workflow/status/ekmett/auth/lean.yml?branch=main&style=flat&label=proofs&logo=githubactions&logoColor=white)](https://github.com/ekmett/auth/actions/workflows/lean.yml?query=branch%3Amain)
[![issues](https://img.shields.io/github/issues/ekmett/auth?style=flat&label=issues&color=007ec6&logo=github&logoColor=white)](https://github.com/ekmett/auth/issues)
[![commits](https://img.shields.io/github/commit-activity/w/ekmett/auth?style=flat&label=commits&color=007ec6&logo=github&logoColor=white)](https://github.com/ekmett/auth/activity)

[![CMake: 3.30+](https://img.shields.io/static/v1?label=CMake&message=3.30%2B&color=064F8C&style=flat&logo=cmake&logoColor=white)](CMakeLists.txt)
[![C++: 26](https://img.shields.io/static/v1?label=C%2B%2B&message=26&color=00599C&style=flat&logo=cplusplus&logoColor=white)](README.md)
[![Clang: 21](https://img.shields.io/static/v1?label=Clang&message=21&color=6f42c1&style=flat&logo=llvm&logoColor=white)](README.md)
[![Lean: 4.24.0](assets/badges/lean-version.svg)](lean/lean-toolchain)

[![license: BSD-2-Clause OR Apache-2.0](assets/badges/license.svg)](LICENSE.md)
[![Contributor Covenant: 2.0](https://img.shields.io/static/v1?label=Contributor+Covenant&message=2.0&color=007ec6&style=flat&logo=contributorcovenant&logoColor=white)](CODE_OF_CONDUCT.md)

[![docs: read](https://img.shields.io/static/v1?label=docs&message=read&color=007ec6&style=flat)](https://ekmett.github.io/auth/)
<!-- badges:end -->

C++26 authenticated computation. Run the same algorithm with a prover to produce
a proof and with a verifier to check it. Pass the db by reference:

```cpp
#include <cstdint>
import auth;
using namespace auth;

auto compute(db auto& db) {
  auto value = db.seal(std::uint32_t{41});
  return db.unseal(value) + 1;
}

int main() {
  prover p;
  auto answer = compute(p);
  verifier v{p.proof};
  auto replay = compute(v);
  v.finish();
  return answer == replay ? 0 : 1;
}
```

`seal` retains the value and its SHA-256 digest in prover mode, and only the digest
in verifier mode. `unseal` appends the value's serialized bytes to `p.proof`, or
reconstructs and checks the value when verifying. `finish()` rejects unused bytes.

Pass a copyable sealed value as an lvalue to keep it, or use `std::move` to consume
it. The proof buffer must outlive its verifier and remain unchanged during replay.

## Walking a sealed tree

Build a tree with `bin` and integer leaves, then follow a path through its sealed
children. A `std::variant` distinguishes leaves from bins. Each bin seals its two
children:

```cpp
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <utility>
#include <variant>
import auth;
import auth.serialization;
using namespace auth;

template<db DB> struct bin;

template<db DB>
struct tree {
  // The box makes the recursive variant finite.
  std::variant<std::uint32_t, std::unique_ptr<bin<DB>>> value;
  tree() = default;
  tree(std::uint32_t leaf) : value(leaf) {}
  tree(bin<DB> node) : value(std::make_unique<bin<DB>>(std::move(node))) {}
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) { s(self.value); }
};

template<db DB>
struct bin {
  sealed<DB, tree<DB>> left, right;
  bin() = default;
  bin(DB& db, tree<DB> l, tree<DB> r)
    : left(db.seal(std::move(l))), right(db.seal(std::move(r))) {}
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) { s(self.left, self.right); }
};

template<db DB>
bin(DB&, auto, auto) -> bin<DB>;

enum class direction { left, right };
using enum direction;

template<db DB>
std::optional<std::uint32_t> at(DB& db, sealed<DB, tree<DB>> root,
                              std::initializer_list<direction> path) {
  auto node = db.unseal(std::move(root));
  for (auto d : path) {
    auto fork = std::get_if<1>(&node.value);
    if (!fork) return {};
    node = db.unseal(std::move(d == left ? (*fork)->left : (*fork)->right));
  }
  if (auto leaf = std::get_if<std::uint32_t>(&node.value)) return *leaf;
  return {};
}

int main() {
  prover p;
  auto root = p.seal(tree{bin(p, bin(p, 1, 2), 3)});
  const auto expected_root = encode(root); // Just the root's digest.
  auto answer = at(p, std::move(root), {left, right});

  verifier v{p.proof};
  auto [root_digest, next] = decode<sealed<verifier, tree<verifier>>>(expected_root);
  auto replay = at(v, root_digest, {left, right});
  v.finish();
  return answer == 2 && replay == answer ? 0 : 1;
}
```

The proof contains the serialized values unsealed during proving, so its size
equals the serialized size of the portion of the sealed structure you walk,
counting each opening. The expected root digest is supplied separately to the
verifier and is not part of `p.proof`.

Unvisited subtrees contribute only their digests in visited parents. Their
contents are absent from the proof, however large those subtrees become.
Sealing values does not append to the proof; unsealing does. Repeatedly unsealing
the same value records its serialized bytes each time. There are no framing
bytes between openings.

## Build and test

Use CMake 3.30 or newer, Ninja, a compiler supporting C++26 modules and explicit
object parameters, and OpenSSL. The tested compiler is Homebrew Clang 21.

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
  -DCMAKE_OSX_SYSROOT="$(xcrun --show-sdk-path)" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On other systems, select the appropriate `clang++` path and omit `CMAKE_OSX_SYSROOT`.
The explicit SDK path lets Clang's module dependency scanner find macOS headers.
If OpenSSL is not found, set `OPENSSL_ROOT_DIR` to its installation prefix.
Exceptions must be enabled.

Applications using `add_subdirectory` link to `auth::auth`, which supplies the
modules and C++26 requirement. Set `AUTH_BUILD_TESTS=OFF` to omit the tests.

## Modules and serialization

| Import | API |
| --- | --- |
| `auth` | `db`, `sealed<DB, T>`, `prover`, `verifier`, `auth_error` |
| `auth.hash` | `digest`, `sha256`, `auth_error` |
| `auth.serialization` | `bytes`, `writer`, `reader`, `encode`, `decode`, `auth_error` |
| `auth.error` | `auth_error` |

All names belong to namespace `auth`. Import hashing and serialization separately
when needed. `sealed<DB, T>` names a db's sealed value type. `prover::proof` is the
flat byte vector containing the computation's ordered sequence of openings.

Custom types define one `serialize` method for both directions, following
[Glenn Fiedler's Serialization Strategies](https://gafferongames.com/post/serialization_strategies/).
The stream supplies checked field operations and a compile-time `reading` flag:

```cpp
struct point {
  std::uint32_t x = 0, y = 0;
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& stream) {
    stream(self.x, self.y);
  }
};
```

Unsigned integers use fixed-width little-endian encoding; booleans use one byte.
Arrays serialize their elements without a length prefix. Variants encode an
alternative index followed by its value. A boxed value adds no pointer or presence
bytes; use a variant to express an empty alternative. A serializer must be
deterministic and preserve its input while writing. Decoding default-constructs
the destination and returns `{value, next}`, where `next` points into the original
input immediately after the consumed bytes. The caller keeps the original end.
Concatenated openings therefore need no external framing.

## Documentation

With Doxygen 1.18 or newer and Python 3 installed:

```sh
cmake -S . -B build -DAUTH_BUILD_DOCS=ON
cmake --build build --target auth_docs
```

Open `build/docs/html/index.html`. API contracts live beside their declarations;
documentation warnings fail the build. The build also emits XML for tooling.

## License and contact

Licensed under your choice of [BSD-2-Clause or Apache-2.0](LICENSE.md).
See the [contribution guidelines](CONTRIBUTING.md),
[code of conduct](CODE_OF_CONDUCT.md), and [security policy](SECURITY.md).

Edward Kmett can be reached at <ekmett@gmail.com>, on Libera Chat as `ekmett`,
and on Twitter/X as `@kmett`.
