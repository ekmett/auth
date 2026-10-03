// SPDX-FileType: Source
// SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
// SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

#include <array>
#include <cstdint>
#include <concepts>
#include <iostream>
#include <initializer_list>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <type_traits>
#include <vector>
#include <variant>

import auth;
import auth.hash;
import auth.serialization;

// Build from this directory (Homebrew LLVM and OpenSSL):
// CXX=/opt/homebrew/opt/llvm/bin/clang++
// SSL=/opt/homebrew/opt/openssl@3
// OUT=$(mktemp -d)
// FLAGS="-std=c++2c -O2 -Wall -Wextra -Werror"
// For release checks, append -DNDEBUG. In zsh use an array for FLAGS or run in bash.
// To force the throwing-return regression, append
// -fno-elide-constructors -DAUTH_TEST_NO_ELISION to FLAGS.
// $CXX $FLAGS --precompile error.ccm -o $OUT/auth.error.pcm
// $CXX $FLAGS -fprebuilt-module-path=$OUT -I$SSL/include \
//   --precompile hash.ccm -o $OUT/auth.hash.pcm
// $CXX $FLAGS -fprebuilt-module-path=$OUT \
//   --precompile serialization.ccm -o $OUT/auth.serialization.pcm
// $CXX $FLAGS -fprebuilt-module-path=$OUT \
//   --precompile auth.ccm -o $OUT/auth.pcm
// for TEST in auth-test auth-api-test; do
//   $CXX $FLAGS -fprebuilt-module-path=$OUT $TEST.cc $OUT/*.pcm \
//     -L$SSL/lib -Wl,-rpath,$SSL/lib -lcrypto -o $OUT/$TEST
//   $OUT/$TEST
// done

using namespace auth;

void check(bool ok, std::string_view message) {
  if (!ok) throw std::runtime_error(std::string(message));
}

template<class F>
void rejects(F&& f) {
  try { f(); }
  catch (const auth_error&) { return; }
  throw std::runtime_error("expected auth_error");
}

struct record {
  std::uint32_t number = 0;
  bool flag = false;
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) { s(self.number, self.flag); }
  bool operator==(const record&) const = default;
};

struct empty {
  template<class Self, class Stream>
  void serialize(this Self&, Stream&) {}
};

void serialization_checks() {
  const record value{0x12345678, true};
  const bytes expected{0x78, 0x56, 0x34, 0x12, 1};
  check(encode(value) == expected, "integer encoding is little endian");
  auto [decoded, rest] = decode<record>(expected);
  check(decoded == value, "shared serializer round trip");
  check(rest == expected.data() + expected.size(), "cursor follows decoded bytes");
  check(encode(empty{}).empty(), "empty encoding");
  auto [nothing, unchanged] = decode<empty>(expected);
  (void)nothing;
  check(unchanged == expected.data(),
        "empty value consumes no bytes");
  check(decode<empty>({}).second == nullptr, "empty value decodes from empty input");
  auto max = std::numeric_limits<std::uint64_t>::max();
  check(encode(max) == bytes(8, 0xff), "maximum integer encoding");
  check(decode<std::uint64_t>(bytes(8, 0xff)).first == max, "maximum integer decoding");
  for (std::size_t n = 0; n < expected.size(); ++n)
    rejects([&] { (void)decode<record>(std::span(expected).first(n)); });
  auto bad = expected;
  bad.back() = 2;
  rejects([&] { (void)decode<record>(bad); });
  auto concatenated = expected;
  concatenated.insert(concatenated.end(), 8, 0xff);
  concatenated.push_back(7);
  auto [first, after_first] = decode<record>(concatenated);
  const auto end = concatenated.data() + concatenated.size();
  auto [second, after_second] = decode<std::uint64_t>({after_first, end});
  auto [third, after_third] = decode<std::uint8_t>({after_second, end});
  check(first == value && second == max && third == 7 && after_third == end,
        "different-sized values decode without framing");
  check(after_first == concatenated.data() + 5 && after_second == concatenated.data() + 13,
        "returned cursors advance through the original bytes");
  const digest abc{
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
    0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
    0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
  check(sha256(bytes{'a','b','c'}) == abc, "SHA-256 known vector");

  using choice = std::variant<std::uint32_t, bool>;
  check(encode(choice{true}) == bytes({1,1}), "variant index precedes its payload");
  check(std::get<bool>(decode<choice>(bytes{1,1}).first), "variant selects the active alternative");
  rejects([&] { (void)decode<choice>(bytes{2}); });
  rejects([&] { (void)decode<choice>(bytes{0,1,2}); });
  auto boxed = std::make_unique<std::uint32_t>(42);
  check(encode(boxed) == bytes({42,0,0,0}), "boxing adds no wire bytes");
  check(*decode<std::unique_ptr<std::uint32_t>>(encode(boxed)).first == 42,
        "boxed value reconstruction");
  rejects([&] { (void)encode(std::unique_ptr<std::uint32_t>{}); });
}

struct tip {
  std::uint32_t value = 0;
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) { s(self.value); }
};

template<db DB> struct bin;

template<db DB>
struct tree {
  // The box makes the recursive variant finite.
  std::variant<tip, std::unique_ptr<bin<DB>>> value;
  tree() = default;
  tree(tip leaf) : value(leaf) {}
  tree(bin<DB> node) : value(std::make_unique<bin<DB>>(std::move(node))) {}
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) { s(self.value); }
};

template<db DB>
struct bin {
  sealed<DB, tree<DB>> left, right;
  bin() = default;
  bin(DB& db, auto l, auto r)
    : left(db.seal(tree<DB>{std::move(l)})),
      right(db.seal(tree<DB>{std::move(r)})) {}
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) { s(self.left, self.right); }
};

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
  if (auto leaf = std::get_if<tip>(&node.value)) return leaf->value;
  return {};
}

std::optional<std::uint32_t> go(db auto& db) {
  auto root = db.seal(tree{bin(db, bin(db, tip(1), tip(2)), tip(3))});
  return at(db, std::move(root), {left, right});
}

void replay_checks() {
  prover p;
  check(go(p) == 2, "prover traversal");
  check(p.proof.size() == 135, "three openings concatenate as 65 plus 65 plus 5 bytes");
  check(bytes(p.proof.begin() + 130, p.proof.end()) == bytes({0,2,0,0,0}),
        "internal nodes serialize child digests only");
  auto replay = [](const auto& proof) {
    verifier v{proof};
    check(go(v) == 2, "verifier traversal");
    v.finish();
  };
  replay(p.proof);
  auto bad = p.proof;
  bad[131] ^= 1;
  rejects([&] { replay(bad); });
  bad = p.proof;
  bad.pop_back();
  rejects([&] { replay(bad); });
  bad = p.proof;
  bad.push_back(0);
  rejects([&] { replay(bad); });
}

template<class T>
auto commitment(const bytes& data) {
  return decode<verifier::sealed<T>>(encode(sha256(data))).first;
}

void sealed_checks() {
  prover p;
  auto resident = p.seal(std::uint32_t{42});
  const auto wire = encode(resident);
  check(wire.size() == 32, "sealed is only a digest");
  check(p.unseal(resident) == 42, "copyable sealed opens without moving");
  auto moved = std::move(resident);
  check(resident == moved && (resident <=> moved) == 0, "sealed identity ignores value");
  check(p.unseal(std::move(moved)) == 42, "resident value survives move");
  verifier v{p.proof};
  {
    auto wrong = v.seal(std::uint32_t{43});
    rejects([&] { (void)v.unseal(std::move(wrong)); });
    auto expected = decode<verifier::sealed<std::uint32_t>>(wire).first;
    check(v.unseal(expected) == 42,
          "hash mismatch does not advance cursor");
    check(v.unseal(std::move(expected)) == 42, "repeated opening after copying sealed");
    v.finish();
    rejects([&] { (void)v.unseal(decode<verifier::sealed<std::uint32_t>>(wire).first); });
  }
  // Invalid encodings or a hash that includes unconsumed bytes must fail.
  const std::vector<bytes> malformed{{2}, {1,0,0}, {1,0,0,0,0}, {2,0,0,0,0}};
  for (std::size_t i = 0; i < malformed.size(); ++i) {
    const auto& proof = malformed[i];
    verifier check_decode{proof};
    if (i == 0)
      rejects([&] { (void)check_decode.unseal(commitment<bool>(proof)); });
    else if (i == 3)
      rejects([&] { (void)check_decode.unseal(commitment<tree<verifier>>(proof)); });
    else
      rejects([&] { (void)check_decode.unseal(commitment<std::uint32_t>(proof)); });
    rejects([&] { check_decode.finish(); });
  }
}

// A third database chooses its own sealed representation, without hashing.
struct memory_db {
  template<class T> struct sealed { T value; };
  std::size_t openings = 0;

  template<class T>
  sealed<T> seal(T value) const { return {std::move(value)}; }

  template<class T>
  T unseal(sealed<T> p) {
    ++openings;
    return std::move(p.value);
  }
};

static_assert(db<prover> && db<verifier> && db<memory_db>);
static_assert(db<prover&> && db<verifier&>);
static_assert(std::same_as<sealed<prover, std::uint32_t>, prover::sealed<std::uint32_t>>);
static_assert(std::same_as<sealed<verifier&, std::uint32_t>, verifier::sealed<std::uint32_t>>);
static_assert(std::same_as<sealed<memory_db, std::uint32_t>, memory_db::sealed<std::uint32_t>>);
static_assert(!db<int> && !db<const prover> && !db<const verifier>);
struct missing_unauth {
  template<class T> struct sealed {};
  template<class T> sealed<T> seal(T);
};
struct wrong_result {
  template<class T> struct sealed {};
  template<class T> sealed<T> seal(T);
  template<class T> void unseal(sealed<T>);
};
static_assert(!db<missing_unauth> && !db<wrong_result>);
static_assert(std::is_copy_constructible_v<prover::sealed<std::uint32_t>>);
static_assert(std::is_copy_assignable_v<prover::sealed<std::uint32_t>>);
static_assert(!std::is_copy_constructible_v<prover::sealed<tree<prover>>>);
static_assert(!std::is_copy_assignable_v<prover::sealed<tree<prover>>>);
static_assert(std::is_move_constructible_v<prover::sealed<tree<prover>>>);
static_assert(std::is_move_assignable_v<prover::sealed<tree<prover>>>);
static_assert(sizeof(verifier::sealed<std::uint32_t>) == sizeof(digest));
static_assert(sizeof(verifier::sealed<std::array<std::uint8_t, 1024>>) == sizeof(digest));

void custom_database_checks() {
  memory_db custom;
  check(go(custom) == 2 && custom.openings == 3, "third database tree traversal");
  auto resident = custom.seal(std::uint32_t{42});
  check(custom.unseal(std::move(resident)) == 42, "custom sealed representation");
}

void independent_database_checks() {
  prover p, other;
  check(p.unseal(p.seal(std::uint32_t{7})) == 7, "first prover");
  check(other.unseal(other.seal(std::uint32_t{8})) == 8, "second prover");
  check(p.proof == bytes({7,0,0,0}) &&
        other.proof == bytes({8,0,0,0}), "provers own separate tapes");
  verifier v{p.proof};
  verifier second{p.proof};
  check(v.unseal(commitment<std::uint32_t>(p.proof)) == 7, "first verifier");
  v.finish();
  rejects([&] { second.finish(); });
  check(other.unseal(other.seal(std::uint32_t{9})) == 9, "interleaved prover");
  check(second.unseal(commitment<std::uint32_t>(p.proof)) == 7, "second verifier");
  v.finish();
  second.finish();
}

void empty_opening_check() {
  prover p;
  (void)p.unseal(p.seal(empty{}));
  check(p.proof.empty(), "empty openings need no framing bytes");
  verifier v{p.proof};
  (void)v.unseal(v.seal(empty{}));
  v.finish();
}

#if defined(AUTH_TEST_NO_ELISION)
struct move_failure {};

struct throwing_value {
  std::uint32_t number = 0;
  static inline int moves = 0;
  throwing_value() = default;
  throwing_value(throwing_value&& other) : number(other.number) {
    if (++moves == 2) throw move_failure{};
  }
  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) { s(self.number); }
};

void throwing_return_check() {
  const bytes proof{42,0,0,0};
  verifier v{proof};
  bool failed = false;
  try { (void)v.unseal(commitment<throwing_value>(proof)); }
  catch (const move_failure&) { failed = true; }
  check(failed, "second move throws while returning the opening");
  rejects([&] { v.finish(); });
  check(v.unseal(commitment<throwing_value>(proof)).number == 42,
        "return failure preserves the opening for retry");
  v.finish();
}
#endif

int main() {
  serialization_checks();
  replay_checks();
  sealed_checks();
  custom_database_checks();
  independent_database_checks();
  empty_opening_check();
#if defined(AUTH_TEST_NO_ELISION)
  throwing_return_check();
#endif
  std::cout << "serialization, replay, rejection, and independent database checks passed\n";
}
