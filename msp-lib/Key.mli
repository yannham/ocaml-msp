(**
 * Keys related operations
 *)
module type S = sig
  (* type of public key (element of g2) *)
  type pk
  (* type of secret key (element of Zq) *)
  type sk = Z.t

  (* Generate a fresh pair of a public key and secret key *)
  val generate : unit -> pk * sk
  (* Aggregate a list of public key *)
  val aggregate : pk list -> pk

  val pk_to_bytes : pk -> bytes
  val pk_of_bytes : bytes -> pk

  val sk_to_bytes : sk -> bytes
  val sk_of_bytes : bytes -> sk
end

module Make (P : Parameters.S) (H : Hash.S with type g1 = P.Pairing.G1.t) (R :
  Random.S) : (S with type pk = P.Pairing.G2.t)
