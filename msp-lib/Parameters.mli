(** Signature of a pairing scheme *)
module type S = sig
  module Pairing : Pairing.S

  (* order of the groups of Pairing *)
  val q : Z.t
  (* the security parameter kappa used in batch verification with duplicated
   * messages *)
  val batch_param : int
end
