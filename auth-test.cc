#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

import auth;

// Build from this directory (Homebrew LLVM and OpenSSL):
// CXX=/opt/homebrew/opt/llvm/bin/clang++
// SSL=/opt/homebrew/opt/openssl@3
// OUT=$(mktemp -d)
// FLAGS="-std=c++2c -O2 -Wall -Wextra -Werror -pthread"
// For the register context, append -DAUTH_CONTEXT_X28 -ffixed-x28 to FLAGS.
// For release checks, append -DNDEBUG. In zsh use an array for FLAGS or run in bash.
// To force the throwing-return regression, append
// -fno-elide-constructors -DAUTH_TEST_NO_ELISION to FLAGS.
// $CXX $FLAGS -I$SSL/include --precompile auth.ccm -o $OUT/auth.pcm
// $CXX $FLAGS -fmodule-file=auth=$OUT/auth.pcm auth-test.cc $OUT/auth.pcm \
//   -L$SSL/lib -Wl,-rpath,$SSL/lib -lcrypto -pthread -o $OUT/auth-test
// $OUT/auth-test

using namespace authenticated;

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
  check(decode<record>(expected) == value, "shared serializer round trip");
  check(encode(empty{}).empty(), "empty encoding");
  (void)decode<empty>({});
  auto max = std::numeric_limits<std::uint64_t>::max();
  check(encode(max) == bytes(8, 0xff), "maximum integer encoding");
  check(decode<std::uint64_t>(bytes(8, 0xff)) == max, "maximum integer decoding");
  for (std::size_t n = 0; n < expected.size(); ++n)
    rejects([&] { (void)decode<record>(std::span(expected).first(n)); });
  auto bad = expected;
  bad.back() = 2;
  rejects([&] { (void)decode<record>(bad); });
  bad = expected;
  bad.push_back(0);
  rejects([&] { (void)decode<record>(bad); });
  const digest abc{
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
    0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
    0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
  check(sha256(bytes{'a','b','c'}) == abc, "SHA-256 known vector");
}

struct tree {
  std::uint32_t value = 0;
  std::unique_ptr<proof<tree>> left{}, right{};

  template<class Self, class Stream>
  void serialize(this Self& self, Stream& s) {
    std::uint8_t tag = self.left ? 1 : 0;
    s(tag, self.value);
    if (tag > 1) throw auth_error("invalid tree tag");
    if (tag == 1) {
      if constexpr (Stream::reading) {
        self.left = std::make_unique<proof<tree>>();
        self.right = std::make_unique<proof<tree>>();
      }
      s(*self.left, *self.right);
    } else if constexpr (Stream::reading) {
      self.left.reset();
      self.right.reset();
    }
  }
};

enum class direction { left, right };

template<class Db>
tree bin(std::uint32_t value, tree left, tree right) {
  return {value, std::make_unique<proof<tree>>(Db::auth(std::move(left))),
                 std::make_unique<proof<tree>>(Db::auth(std::move(right)))};
}

template<class Db>
std::optional<std::uint32_t> at(tree node, std::span<const direction> path) {
  for (auto d : path) {
    if (!node.left) return {};
    auto next = std::move(d == direction::left ? node.left : node.right);
    node = Db::unauth(std::move(*next));
  }
  return node.value;
}

template<class Db>
std::optional<std::uint32_t> go() {
  auto y = bin<Db>(0, tree{1}, tree{2});
  auto x = bin<Db>(0, std::move(y), tree{2});
  const direction path[]{direction::left, direction::right};
  return at<Db>(std::move(x), path);
}

void replay_checks() {
  prover p;
  {
    db_scope active{p};
    check(go<prover>() == 2, "prover traversal");
  }
  check(p.tape.size() == 2, "only traversed nodes appear on tape");
  check(p.tape[0].size() == 69 && p.tape[1] == bytes({0,2,0,0,0}),
        "internal nodes serialize child digests only");
  auto replay = [](const auto& tape) {
    verifier v{tape};
    db_scope active{v};
    check(go<verifier>() == 2, "verifier traversal");
    v.finish();
  };
  replay(p.tape);
  auto bad = p.tape;
  bad[1][1] ^= 1;
  rejects([&] { replay(bad); });
  bad = p.tape;
  bad.pop_back();
  rejects([&] { replay(bad); });
  bad = p.tape;
  bad.push_back({});
  rejects([&] { replay(bad); });
}

template<class T>
proof<T> commitment(const bytes& frame) {
  return decode<proof<T>>(encode(sha256(frame)));
}

void proof_checks() {
  prover p;
  db_scope active{p};
  auto resident = prover::auth(std::uint32_t{42});
  const auto wire = encode(resident);
  check(wire.size() == 32, "proof is only a digest");
  auto absent = decode<proof<std::uint32_t>>(wire);
  check(resident == absent && (resident <=> absent) == 0, "proof identity ignores value");
  rejects([&] { (void)prover::unauth(std::move(absent)); });
  auto moved = std::move(resident);
  rejects([&] { (void)prover::unauth(std::move(resident)); });
  check(prover::unauth(std::move(moved)) == 42, "resident value survives move");
  verifier v{p.tape};
  {
    db_scope verify{v};
    auto wrong = verifier::auth(std::uint32_t{43});
    rejects([&] { (void)verifier::unauth(std::move(wrong)); });
    check(verifier::unauth(decode<proof<std::uint32_t>>(wire)) == 42,
          "hash mismatch does not consume frame");
    v.finish();
    rejects([&] { (void)verifier::unauth(decode<proof<std::uint32_t>>(wire)); });
  }
  // These inputs have matching hashes: decoding itself must reject them.
  const std::vector<bytes> malformed{{2}, {1,0,0}, {1,0,0,0,0}, {2,0,0,0,0}};
  for (std::size_t i = 0; i < malformed.size(); ++i) {
    std::vector<bytes> tape{malformed[i]};
    verifier check_decode{tape};
    db_scope verify{check_decode};
    if (i == 0)
      rejects([&] { (void)verifier::unauth(commitment<bool>(tape[0])); });
    else if (i == 3)
      rejects([&] { (void)verifier::unauth(commitment<tree>(tape[0])); });
    else
      rejects([&] { (void)verifier::unauth(commitment<std::uint32_t>(tape[0])); });
    rejects([&] { check_decode.finish(); });
  }
}

void context_checks() {
  rejects([] { (void)prover::auth(std::uint32_t{1}); });
  prover p;
  {
    db_scope outer{p};
    rejects([] { (void)verifier::auth(std::uint32_t{1}); });
    prover other;
    try {
      db_scope inner{other};
      check(prover::unauth(prover::auth(std::uint32_t{2})) == 2, "nested scope");
      throw 0;
    } catch (int) {}
    check(prover::unauth(prover::auth(std::uint32_t{3})) == 3, "restored scope");
    check(other.tape.size() == 1 && p.tape.size() == 1, "separate backing state");
    std::exception_ptr failure;
    std::thread worker([&] {
      try {
        db_scope boundary;
        rejects([] { (void)prover::auth(std::uint32_t{1}); });
        prover local;
        db_scope thread_scope{local};
        check(prover::unauth(prover::auth(std::uint32_t{4})) == 4, "thread value");
        check(local.tape.size() == 1, "thread backing state");
      } catch (...) { failure = std::current_exception(); }
    });
    worker.join();
    if (failure) std::rethrow_exception(failure);
    check(prover::unauth(prover::auth(std::uint32_t{5})) == 5, "parent context survives thread");
    check(p.tape.size() == 2, "thread did not write parent tape");
  }
  rejects([] { (void)prover::auth(std::uint32_t{1}); });
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
  const std::vector<bytes> tape{{42,0,0,0}};
  verifier v{tape};
  db_scope scope{v};
  bool failed = false;
  try { (void)verifier::unauth(commitment<throwing_value>(tape[0])); }
  catch (const move_failure&) { failed = true; }
  check(failed, "second move throws while returning the opening");
  rejects([&] { v.finish(); });
  check(verifier::unauth(commitment<throwing_value>(tape[0])).number == 42,
        "return failure preserves the opening for retry");
  v.finish();
}
#endif

int main() {
  // Establish a known empty context at the ABI boundary, including for x28.
  db_scope boundary;
  serialization_checks();
  replay_checks();
  proof_checks();
  context_checks();
#if defined(AUTH_TEST_NO_ELISION)
  throwing_return_check();
#endif
  std::cout << "serialization, replay, rejection, and context checks passed\n";
}
