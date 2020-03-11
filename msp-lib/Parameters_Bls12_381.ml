(** The of_z function of Bls12_381.Fr is not correctly implemented,
 *  as it fails for any integer that is not represented on exactly
 *  Bls12_381.Fr.size. We fix this by padding the byte representation
 *  with zero before converting it
 *)
let pad n s = match Bytes.length s with
 | l when l > n -> invalid_arg "Cannot pad a sequence longer than the size"
 | l when l = n -> s
 | l ->
   let dest = Bytes.make n '\000' in
   Bytes.blit s 0 dest 0 l;
   dest;;

let of_z' z =
  Z.to_bits z
  |> Bytes.of_string
  |> pad Bls12_381.Fr.size
  |> Bls12_381.Fr.of_bytes

module OfEc (Ec : Bls12_381.Elliptic_curve_sig.T with type Scalar.t =
  Bls12_381.Fr.t) : (Pairing.Group_S with type t = Ec.t) = struct
  type t = Ec.t

  let one = Ec.zero
  let gen = Ec.one

  let inv = Ec.negate
  let mul = Ec.add

  let exp n x =
    of_z' n
    |> Ec.mul x

  let eq = Ec.eq

  let to_bytes = Ec.to_bytes
  let of_bytes = Ec.of_bytes
end

module OfFf (Ff : Bls12_381.Ff_sig.T) = struct
  type t = Ff.t

  let one = Ff.one
  let gen () = failwith "Ff.gen: not implemented"

  let inv x = match Ff.is_zero x with
    | true  -> failwith "Tried to take the inverse of zero in a Ff"
    | false -> Ff.inverse x

  let mul = Ff.mul

  let exp n x = Ff.pow x n

  let eq = Ff.eq

  let to_bytes = Ff.to_bytes
  let of_bytes = Ff.of_bytes
end

let q = Bls12_381.Fr.order
let batch_param = 64

module Pairing = struct
  module G1 = OfEc(Bls12_381.G1.Uncompressed)
  module G2 = OfEc(Bls12_381.G2.Uncompressed)
  module Gt = OfFf(Bls12_381.Fq12)

  let pairing = Bls12_381.Pairing.pairing
end
