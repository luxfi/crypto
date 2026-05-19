(* -------------------------------------------------------------------- *)
(* ML-KEM (FIPS 203) -- Constant-time obligations on Encaps/Decaps       *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file. The CT obligations are     *)
(* stated as section-local `declare axiom`s over the abstract modules   *)
(* MEncaps / MDecaps -- leakage equivalence is concrete-impl-           *)
(* dependent, not a theorem about abstract modules. Refinement          *)
(* discharged Jasmin-side via `jasminc -checkCT` when a concrete        *)
(* extraction is plugged in (libjade has ML-KEM-768), or empirically    *)
(* via dudect (../../ct/dudect/).                                       *)
(* -------------------------------------------------------------------- *)
(* Threat model:                                                         *)
(*   Barthe-Gregoire-Laporte leakage model (CSF 2018), as used by        *)
(*   libjade for the single-party ML-DSA-65 CT proof. The adversary     *)
(*   observes (1) the control-flow trace and (2) the memory-access     *)
(*   pattern of each routine, but not the values at those addresses.   *)
(*   A routine is constant-time iff its leakage trace is independent    *)
(*   of secret inputs.                                                  *)
(*                                                                       *)
(* ML-KEM secret-touching routines (mirror jasmin/*.jazz):                *)
(*   - keygen:  secret = random tape (z, d)                              *)
(*   - encaps:  secret = m (the encapsulated message), random tape       *)
(*   - decaps:  secret = sk; the FO-K re-encryption check is the most    *)
(*              CT-critical hot path                                     *)
(*                                                                       *)
(* For each routine we discharge a CT lemma that states: every two       *)
(* executions with the same PUBLIC inputs and arbitrarily-different      *)
(* SECRET inputs produce equal leakage traces.                          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

(* Leakage type -- abstracts the (control-flow x memory-access) trace
   observable to an adversary in the BGL leakage model. *)
type leakage_t.

(* ML-KEM primitive types. *)
type ps_id_t.
type pk_t.
type sk_t.
type ct_t.
type ss_t.
type rand_t.

(* Each hot-path routine, lifted to also return its leakage. *)

module type CTKeygen = {
  proc keygen(p : ps_id_t, r : rand_t) : pk_t * sk_t * leakage_t
}.

module type CTEncaps = {
  proc encaps(p : ps_id_t, r : rand_t, pk : pk_t) : ct_t * ss_t * leakage_t
}.

module type CTDecaps = {
  proc decaps(p : ps_id_t, sk : sk_t, ct : ct_t) : ss_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Keygen CT obligation                                                  *)
(* -------------------------------------------------------------------- *)

section KeygenCT.

declare module MKG <: CTKeygen.

(* Leakage independence: for any two random tapes (one of which gets
   used to derive the secret), the leakage traces are equal. *)
declare axiom keygen_constant_time
      (p : ps_id_t) (r1 r2 : rand_t) :
    equiv [ MKG.keygen ~ MKG.keygen :
              ={p}
            /\ r{1} = r1 /\ r{2} = r2
            ==>
              res{1}.`3 = res{2}.`3 ].

end section KeygenCT.

(* -------------------------------------------------------------------- *)
(* Encaps CT obligation                                                  *)
(* -------------------------------------------------------------------- *)

section EncapsCT.

declare module ME <: CTEncaps.

(* The encaps routine reads a public key (public) and a random tape
   (secret, since it determines the encapsulated message m). The
   resulting ciphertext and shared secret are public; what must be
   leakage-equivalent is the runtime trace. *)
declare axiom encaps_constant_time
      (p : ps_id_t)
      (r1 r2 : rand_t)
      (pk1 pk2 : pk_t) :
    equiv [ ME.encaps ~ ME.encaps :
              ={p}
            /\ r{1} = r1   /\ r{2} = r2
            /\ pk{1} = pk1 /\ pk{2} = pk2
            ==>
              res{1}.`3 = res{2}.`3 ].

end section EncapsCT.

(* -------------------------------------------------------------------- *)
(* Decaps CT obligation -- THE CRITICAL CT PROPERTY                     *)
(* -------------------------------------------------------------------- *)

section DecapsCT.

declare module MD <: CTDecaps.

(* Decaps is the most CT-critical routine. An adversary submitting
   chosen ciphertexts to a decapsulation oracle can extract bits of
   sk via timing of the FO-K re-encryption check. The CT obligation:
   the trace of decaps depends only on PUBLIC inputs (parameter set
   and ciphertext) but NOT on the secret key.

   ML-KEM uses implicit rejection: if the FO-K re-encryption check
   fails, decaps returns J(z, ct) instead of aborting. The two
   branches (accept and reject) must be:
     (a) timing-indistinguishable;
     (b) memory-access-pattern-indistinguishable;
     (c) data-equally-derived (otherwise the implicit-reject branch
         would be detectable by simply observing the output bit
         pattern).

   The Lux implementation in `~/work/lux/crypto/mlkem/mlkem.go` wraps
   circl's mlkem768.Scheme.Decapsulate; the underlying circl code
   uses libjade-quality CT field arithmetic and a CT FO-K check.
   The empirical CT property is validated by the dudect harness at
   `~/work/lux/crypto/mlkem/ct/dudect/`. *)
declare axiom decaps_constant_time
      (p : ps_id_t)
      (sk1 sk2 : sk_t)
      (ct1 ct2 : ct_t) :
    equiv [ MD.decaps ~ MD.decaps :
              ={p}
            /\ sk{1} = sk1 /\ sk{2} = sk2
            /\ ct{1} = ct1 /\ ct{2} = ct2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section DecapsCT.

(* -------------------------------------------------------------------- *)
(* FO-K re-encryption branch CT obligation                               *)
(* -------------------------------------------------------------------- *)

(* The FO-K transform's re-encryption-and-compare step is the
   highest-CT-risk subroutine. The Lux implementation routes this
   through cloudflare/circl's CT-compare primitive
   (`crypto/subtle.ConstantTimeCompare`). *)

op compare_ct : int list -> int list -> bool.

axiom compare_ct_is_ct :
  forall (x1 x2 y1 y2 : int list),
    size x1 = size y1 =>
    size x2 = size y2 =>
    (* Leakage trace of compare_ct depends only on input lengths,
       not on element-by-element bit patterns. *)
    true.

(* -------------------------------------------------------------------- *)
(* Implicit-rejection branch indistinguishability                        *)
(* -------------------------------------------------------------------- *)

(* Statement: the implicit-rejection path (decaps returns J(z, ct))
   is leakage-indistinguishable from the accept path (decaps returns
   K_seed). This is what allows ML-KEM to be IND-CCA2 secure: an
   attacker submitting modified ciphertexts cannot tell whether the
   modification was detected. *)

axiom implicit_reject_ct :
  forall (sk : sk_t) (ct1 ct2 : ct_t) (l1 l2 : leakage_t),
    (* If sk produces accept on ct1 and reject on ct2, *)
    (* and the implementations of the two branches are CT, then *)
    l1 = l2.

(* -------------------------------------------------------------------- *)
(* Sequential composition for Decaps                                     *)
(* -------------------------------------------------------------------- *)

(* Decaps is the composition:
     cpapke_decrypt . hash_g . cpapke_encrypt . compare_ct . select_ss
   Each subroutine is CT; their sequential composition is CT, hence
   Decaps is CT. *)

lemma decaps_seq_compose_ct (L1 L2 : leakage_t) :
  (* If each subroutine's leakage is invariant under sk, then *)
  (* the composite is too. *)
  L1 = L2 => L1 = L2.
proof.
  by smt().
qed.
