-- SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
-- SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

import AuthVerifier

namespace Auth

/-- A finite adaptive computation. P is ghost resident data identifying each
    commitment; only its digest is used by verifier replay. Continuations see
    the verifier-visible V representation. This expresses the required
    representation-respecting computation, not arbitrary C++ functions. -/
inductive Program (P V Result : Type) where
  | done (result : Result)
  | request (resident : P) (next : V → Program P V Result)

/-- Successful prover execution: append each opening, then continue. Exceptions
    after append in the C++ prover are outside this successful-trace function. -/
def prove (r : Representation P V) : Program P V Result → Result × Bytes
  | .done result => (result, [])
  | .request resident next =>
    let tail := prove r (next (r.erase resident))
    (tail.1, r.encode resident ++ tail.2)

/-- Replay can branch on the value it actually decodes. Accepted values are
    delivered successfully here; failing return construction is in tryOpen. -/
def replay [DecidableEq D] (r : Representation P V) (hash : Bytes → D) :
    Program P V Result → Bytes → Option (Result × Bytes)
  | .done result, input => some (result, input)
  | .request resident next, input => do
    let p ← checked r.codec hash (hash (r.encode resident)) input
    replay r hash (next p.value) p.rest

/-- Only commitments along the successful prover path need the toy binding
    premise. No assumption about unused alternatives is required. -/
def Bound (r : Representation P V) (hash : Bytes → D) : Program P V Result → Prop
  | .done _ => True
  | .request resident next =>
    BindingAt hash (r.encode resident) ∧ Bound r hash (next (r.erase resident))

theorem checked_representation [DecidableEq D] (r : Representation P V)
    (hash : Bytes → D) (resident : P) (suffix : Bytes) :
    checked r.codec hash (hash (r.encode resident)) (r.encode resident ++ suffix) =
      some ⟨r.erase resident, r.encode resident, suffix⟩ := by
  simp [checked, r.decode_encode]

/-- Honest replay requires no binding assumption. Every branch follows the
    prover-visible erasure, and any following proof suffix is left intact. -/
theorem honest_replay [DecidableEq D] (r : Representation P V) (hash : Bytes → D)
    (program : Program P V Result) (suffix : Bytes) :
    replay r hash program ((prove r program).2 ++ suffix) =
      some ((prove r program).1, suffix) := by
  induction program with
  | done result => rfl
  | request resident next ih =>
    simp [prove, replay, List.append_assoc, checked_representation, ih]

/-- Accepted adversarial replay returns the same observation AND consumes
    exactly the honest transcript, under binding at the encountered commitments. -/
theorem accepted_replay [DecidableEq D] (r : Representation P V) (hash : Bytes → D)
    (program : Program P V Result) (bound : Bound r hash program)
    (input rest : Bytes) (result : Result)
    (h : replay r hash program input = some (result, rest)) :
    result = (prove r program).1 ∧ input = (prove r program).2 ++ rest := by
  induction program generalizing input rest result with
  | done expected =>
    simp [replay] at h
    obtain ⟨hr, hi⟩ := h
    exact ⟨hr.symm, hi⟩
  | request resident next ih =>
    obtain ⟨hb, hn⟩ := bound
    cases hc : checked r.codec hash (hash (r.encode resident)) input with
    | none => simp [replay, hc] at h
    | some p =>
      have hb' : BindingAt hash (r.codec.encode (r.erase resident)) := by
        simpa [r.same_bytes] using hb
      have hc' : checked r.codec hash (hash (r.codec.encode (r.erase resident))) input = some p := by
        simpa [r.same_bytes] using hc
      obtain ⟨hv, hu⟩ := checked_authentic r.codec hash (r.erase resident) input p hb' hc'
      have hp := r.codec.partition input p (checked_success r.codec hash _ input p hc).1
      rw [r.same_bytes] at hu
      rw [hu] at hp
      have ht : replay r hash (next (r.erase resident)) p.rest = some (result, rest) := by
        simpa [replay, hc, hv] using h
      obtain ⟨hr, hs⟩ := ih (r.erase resident) hn p.rest rest result ht
      constructor
      · exact hr
      · simpa [prove, List.append_assoc, hs] using hp

/-- Finishing rejects every nonempty extension of an honest transcript. -/
theorem honest_finish [DecidableEq D] (r : Representation P V) (hash : Bytes → D)
    (program : Program P V Result) (suffix : Bytes) :
    (∃ result, replay r hash program ((prove r program).2 ++ suffix) = some (result, []))
      ↔ suffix = [] := by
  rw [honest_replay]
  simp

/-- Empty encodings mean exhaustion cannot count or uniquely frame opening
    events. This counterexample prevents an overstrong transcript claim. -/
theorem zero_byte_event_ambiguity :
    (prove (Representation.identity Codec.unit) (Program.done () : Program Unit Unit Unit)).2 =
    (prove (Representation.identity Codec.unit) (Program.request () (fun _ => .done ()))).2 := rfl

end Auth
