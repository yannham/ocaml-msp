module type Group_S = sig
  type t

  val one : unit -> t
  val gen : unit -> t

  val inv : t -> t
  val mul : t -> t -> t
  val exp : Z.t -> t -> t

  val eq : t -> t -> bool

  val to_bytes : t -> bytes
  val of_bytes : bytes -> t
end


module type S = sig
  module G1 : Group_S
  module G2 : Group_S
  module Gt : Group_S

  val pairing : G1.t -> G2.t -> Gt.t
end
