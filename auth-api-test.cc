// SPDX-FileType: Source
// SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
// SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

#include <cstdint>
#include <stdexcept>
#include <utility>

import auth;

using namespace auth;

template<db DB>
std::uint32_t open(DB& db, sealed<DB, std::uint32_t> value) {
  return db.unseal(std::move(value));
}

std::uint32_t example(db auto& db) {
  sealed<decltype(db), std::uint32_t> value = db.seal(std::uint32_t{41});
  return open(db, value) + 1;
}

int main() {
  prover p;
  if (example(p) != 42) throw std::runtime_error("prover result");
  verifier v{p.proof};
  if (example(v) != 42) throw std::runtime_error("verifier result");
  v.finish();

  try {
    (void)v.unseal(v.seal(std::uint32_t{41}));
  } catch (const auth_error&) {
    return 0;
  }
  throw std::runtime_error("expected exhausted proof");
}
