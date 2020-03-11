(** Signature of a random number generator *)
module type S = sig
  (* Generate a random number between 0 and argument (excluded) *)
  val random : Z.t -> Z.t
  (* Generate n random bits, ie a number between 0 and 2^k *)
  val random_bits : int -> Z.t
end
