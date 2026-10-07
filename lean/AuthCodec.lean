-- SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
-- SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

import Std

namespace Auth

abbrev Bytes := List UInt8

/-- Decoder success records precisely the consumed prefix and remaining suffix. -/
structure Parsed (α : Type) where
  value : α
  used : Bytes
  rest : Bytes
  deriving DecidableEq

/-- Custom serializers must discharge these laws. They are not inferred from
    C++ signatures. Partition also constrains successful noncanonical input. -/
structure Codec (α : Type) where
  encode : α → Bytes
  decode : Bytes → Option (Parsed α)
  decode_encode : ∀ x suffix, decode (encode x ++ suffix) = some ⟨x, encode x, suffix⟩
  partition : ∀ input p, decode input = some p → input = p.used ++ p.rest

namespace Codec

def unit : Codec Unit where
  encode _ := []
  decode input := some ⟨(), [], input⟩
  decode_encode _ _ := rfl
  partition _ _ h := by cases h; rfl

def byte : Codec UInt8 where
  encode x := [x]
  decode
    | [] => none
    | x :: xs => some ⟨x, [x], xs⟩
  decode_encode _ _ := rfl
  partition input p h := by
    cases input with
    | nil => simp at h
    | cons x xs => simp only [Option.some.injEq] at h; cases h; rfl

/-- The one-byte Boolean codec accepts only the tags0 and1. -/
def boolean : Codec Bool where
  encode b := [if b then 1 else 0]
  decode
    | [] => none
    | x :: xs => if x = 0 then some ⟨false, [x], xs⟩
                 else if x = 1 then some ⟨true, [x], xs⟩ else none
  decode_encode b _ := by cases b <;> rfl
  partition input p h := by
    cases input with
    | nil => simp at h
    | cons x xs =>
      dsimp at h
      split at h
      · cases h; rfl
      · split at h
        · cases h; rfl
        · simp at h

/-- Sequential fields, without an extra frame or length prefix. -/
def pair (a : Codec α) (b : Codec β) : Codec (α × β) where
  encode x := a.encode x.1 ++ b.encode x.2
  decode input := do
    let p ← a.decode input
    let q ← b.decode p.rest
    return ⟨(p.value, q.value), p.used ++ q.used, q.rest⟩
  decode_encode x suffix := by simp [List.append_assoc, a.decode_encode, b.decode_encode]
  partition input p h := by
    cases ha : a.decode input with
    | none => simp [ha] at h
    | some pa =>
      cases hb : b.decode pa.rest with
      | none => simp [ha, hb] at h
      | some pb =>
        simp [ha, hb] at h
        cases h
        rw [a.partition input pa ha, b.partition pa.rest pb hb, List.append_assoc]

theorem encode_injective (c : Codec α) : Function.Injective c.encode := by
  intro x y h
  have he := c.decode_encode x []
  rw [h, c.decode_encode y] at he
  cases he
  rfl

/-- No valid encoding is a proper prefix of another encoding of this type. -/
theorem prefix_free (c : Codec α) (x y : α) (suffix : Bytes)
    (h : c.encode x ++ suffix = c.encode y) : x = y ∧ suffix = [] := by
  have he := c.decode_encode x suffix
  rw [h, ← List.append_nil (c.encode y), c.decode_encode y] at he
  cases he
  exact ⟨rfl, rfl⟩

end Codec

/-- Prover payloads and verifier payloads can be different types. Erasure
    forgets resident values inside nested sealed fields but preserves bytes. -/
structure Representation (P V : Type) where
  encode : P → Bytes
  codec : Codec V
  erase : P → V
  same_bytes : ∀ p, codec.encode (erase p) = encode p

namespace Representation

def identity (c : Codec α) : Representation α α := ⟨c.encode, c, id, fun _ => rfl⟩

def pair (a : Representation P V) (b : Representation Q W) : Representation (P × Q) (V × W) where
  encode p := a.encode p.1 ++ b.encode p.2
  codec := a.codec.pair b.codec
  erase p := (a.erase p.1, b.erase p.2)
  same_bytes p := by simp [Codec.pair, a.same_bytes, b.same_bytes]

/-- A nested resident commitment serializes only its digest. No recovery of
    the resident payload is required when decoding that field. -/
def sealed (digest : Codec D) : Representation (P × D) D where
  encode p := digest.encode p.2
  codec := digest
  erase := Prod.snd
  same_bytes _ := rfl

theorem decode_encode (r : Representation P V) (p : P) (suffix : Bytes) :
    r.codec.decode (r.encode p ++ suffix) = some ⟨r.erase p, r.encode p, suffix⟩ := by
  rw [← r.same_bytes p, r.codec.decode_encode]

end Representation
end Auth
