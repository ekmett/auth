-- SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
-- SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

import AuthCodec

namespace Auth

/-- A toy perfect-binding premise at this particular committed byte string.
    This is a theorem parameter, NOT an axiom about SHA-256. -/
def BindingAt (hash : Bytes → D) (committed : Bytes) : Prop :=
  ∀ candidate, hash candidate = hash committed → candidate = committed

/-- The identity hash witnesses consistency of the toy assumptions. -/
theorem identity_binding (committed : Bytes) : BindingAt (id : Bytes → Bytes) committed := by
  intro candidate h
  exact h

/-- Resident commitments carry the invariant established by prover::seal.
    It must remain valid through subsequent serialization and opening. -/
structure Resident (r : Representation P V) (hash : Bytes → D) where
  value : P
  digest : D
  coherent : digest = hash (r.encode value)

def makeSealed (r : Representation P V) (hash : Bytes → D) (p : P) : Resident r hash :=
  ⟨p, hash (r.encode p), rfl⟩

/-- Prover sealing and verifier sealing of the corresponding representation
    compute the same digest. Neither operation emits an opening. -/
theorem seal_correspondence (r : Representation P V) (hash : Bytes → D) (p : P) :
    (makeSealed r hash p).digest = hash (r.codec.encode (r.erase p)) := by
  simp [makeSealed, r.same_bytes]

/-- A coherent resident sealed field is decoded as a digest-only field. Pair
    closure of Representation builds larger values containing such fields. -/
def sealedRepresentation (r : Representation P V) (hash : Bytes → D)
    (digestCodec : Codec D) : Representation (Resident r hash) D where
  encode p := digestCodec.encode p.digest
  codec := digestCodec
  erase p := p.digest
  same_bytes _ := rfl

/-- The local decoder/hash phase does not change the external cursor. -/
def checked [DecidableEq D] (c : Codec α) (hash : Bytes → D) (target : D)
    (input : Bytes) : Option (Parsed α) := do
  let p ← c.decode input
  if hash p.used = target then some p else none

theorem checked_success [DecidableEq D] (c : Codec α) (hash : Bytes → D)
    (target : D) (input : Bytes) (p : Parsed α)
    (h : checked c hash target input = some p) :
    c.decode input = some p ∧ hash p.used = target := by
  unfold checked at h
  cases hd : c.decode input with
  | none => simp [hd] at h
  | some q =>
    by_cases hh : hash q.used = target
    · simp [hd, hh] at h
      cases h
      exact ⟨rfl, hh⟩
    · simp [hd, hh] at h

theorem checked_honest [DecidableEq D] (c : Codec α) (hash : Bytes → D)
    (x : α) (suffix : Bytes) :
    checked c hash (hash (c.encode x)) (c.encode x ++ suffix) =
      some ⟨x, c.encode x, suffix⟩ := by
  simp [checked, c.decode_encode]

/-- Binding plus deterministic prefix decoding identifies both the value and
    the exact checked bytes, even for adversarial input with trailing data. -/
theorem checked_authentic [DecidableEq D] (c : Codec α) (hash : Bytes → D)
    (x : α) (input : Bytes) (p : Parsed α)
    (bound : BindingAt hash (c.encode x))
    (h : checked c hash (hash (c.encode x)) input = some p) :
    p.value = x ∧ p.used = c.encode x := by
  obtain ⟨hd, hh⟩ := checked_success c hash _ input p h
  have hb := bound p.used hh
  have hp := c.partition input p hd
  rw [hb] at hp
  rw [hp, c.decode_encode] at hd
  have he := Option.some.inj hd
  exact ⟨(congrArg Parsed.value he).symm, hb⟩

structure Cursor where
  position : Nat
  remaining : Bytes
  deriving DecidableEq

def advance (s : Cursor) (p : Parsed α) : Cursor :=
  ⟨s.position + p.used.length, p.rest⟩

inductive Failure where
  | rejected
  | returnConstruction
  deriving DecidableEq

/-- deliver models the final return construction. Even failure there leaves
    the externally visible cursor untouched, like advance_on_success. -/
def tryOpen [DecidableEq D] (c : Codec α) (hash : Bytes → D) (target : D)
    (deliver : α → Bool) (s : Cursor) : Except Failure α × Cursor :=
  match checked c hash target s.remaining with
  | none => (.error .rejected, s)
  | some p => if deliver p.value then (.ok p.value, advance s p)
              else (.error .returnConstruction, s)

theorem rejection_unchanged [DecidableEq D] (c : Codec α) (hash : Bytes → D)
    (target : D) (deliver : α → Bool) (s : Cursor) (e : Failure)
    (h : (tryOpen c hash target deliver s).1 = .error e) :
    (tryOpen c hash target deliver s).2 = s := by
  unfold tryOpen at *
  split at *
  · rfl
  · split at * <;> simp_all

theorem success_exact [DecidableEq D] (c : Codec α) (hash : Bytes → D)
    (target : D) (deliver : α → Bool) (s : Cursor) (x : α)
    (h : (tryOpen c hash target deliver s).1 = .ok x) :
    ∃ p, checked c hash target s.remaining = some p ∧ p.value = x ∧
      deliver x = true ∧ (tryOpen c hash target deliver s).2 = advance s p := by
  unfold tryOpen at *
  split at *
  · simp at h
  · rename_i p hp
    split at *
    · rename_i hd
      simp only [Except.ok.injEq] at h
      exact ⟨p, hp, h, by simpa [h] using hd, by simp [hd]⟩
    · simp at h

/-- On success position advances by exactly the hashed prefix, within the
    original bounds; total input extent is unchanged. -/
theorem cursor_conservation [DecidableEq D] (c : Codec α) (hash : Bytes → D)
    (target : D) (s : Cursor) (p : Parsed α)
    (h : checked c hash target s.remaining = some p) :
    s.position ≤ (advance s p).position ∧
    (advance s p).position ≤ s.position + s.remaining.length ∧
    (advance s p).position + (advance s p).remaining.length =
      s.position + s.remaining.length := by
  have hp := c.partition s.remaining p (checked_success c hash target _ p h).1
  have hl := congrArg List.length hp
  simp only [List.length_append] at hl
  simp only [advance]
  omega

def finish (s : Cursor) : Bool := s.remaining.isEmpty

theorem finish_iff (s : Cursor) : finish s = true ↔ s.remaining = [] := by
  simp [finish]

/-- Zero-byte values are permitted; opening one need not move the cursor. -/
theorem zero_byte_open (hash : Bytes → D) [DecidableEq D] (s : Cursor) :
    tryOpen Codec.unit hash (hash []) (fun _ => true) s = (.ok (), s) := by
  cases s
  simp [tryOpen, checked, Codec.unit, advance]

end Auth
