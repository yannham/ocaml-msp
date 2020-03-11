(**
 * Signature of a module that provides necessary hash functions
 *)
module type S = sig
  type g1
  type sk = Z.t

  val h0 : bytes -> g1
  val h1 : bytes -> sk
end
