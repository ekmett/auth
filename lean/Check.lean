-- SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
-- SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

import AuthReplay

#print axioms Auth.Codec.unit
#print axioms Auth.Codec.byte
#print axioms Auth.Codec.boolean
#print axioms Auth.Codec.pair
#print axioms Auth.Codec.encode_injective
#print axioms Auth.Codec.prefix_free
#print axioms Auth.Representation.decode_encode
#print axioms Auth.identity_binding
#print axioms Auth.seal_correspondence
#print axioms Auth.checked_honest
#print axioms Auth.checked_authentic
#print axioms Auth.rejection_unchanged
#print axioms Auth.success_exact
#print axioms Auth.cursor_conservation
#print axioms Auth.finish_iff
#print axioms Auth.zero_byte_open
#print axioms Auth.honest_replay
#print axioms Auth.accepted_replay
#print axioms Auth.honest_finish
#print axioms Auth.zero_byte_event_ambiguity
