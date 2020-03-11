(**
 * Signing related operations
 *)
module type S = sig
  (* type of signatures (element of gt) *)
  type s
  (* type of public key (element of g2) *)
  type pk
  (* type of secret key (element of Zq) *)
  type sk = Z.t

  (* Given a secret key, a public key, and the list
   * of all the public keys of the signers (including the user's one
   * that must be repeated), compute the partial signature
   * for this user
   *)
  val sign : sk -> pk -> pk list -> bytes -> s

  (* Combine a list of partial signature into the final signature *)
  val combine : s list -> s

  (* Check a signature, given an aggregated public key, a message,
   * and a (combined) signature *)
  val verify : pk -> bytes -> s -> (bool, string) result

  (* Efficiently check a batch of signatures *)
  val batch_verify : (pk * bytes * s) list -> (bool, string) result

  val to_bytes : s -> bytes
  val of_bytes : bytes -> s
end

module Make
  (P : Parameters.S)
  (H : Hash.S with type g1 = P.Pairing.G1.t)
  (R : Random.S) : S with
  type s = P.Pairing.G1.t
  and type pk = P.Pairing.G2.t
