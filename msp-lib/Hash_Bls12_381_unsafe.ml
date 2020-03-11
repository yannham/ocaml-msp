(** To hash in Zq, as the order q is represented on 255 bits, we generate a 256
 * bits using SHA, convert it to an integer, and use it if it is lower tha q, or
 * hash it again until it is.
 *
 *  To hash in G1, we hash in Zq and raise the generator to the power of the
 *  result
 *
 *  These functions may or may not be secure, but have not been proved so
 *)

type g1 = Parameters_Bls12_381.Pairing.G1.t
type sk = Z.t

(* THIS FUNCTION IS NOT CRYPTOGRAPHICALLY SECURE
 * NEED TO BE REPLACED WITH A PROPER CRYPTOGRAPHIC HASH FUNCTION
 * IT IS ONLY USED AS REPLACEMENT DURING DEVELOPMENT
 *)
let h1 b =
  let rec reduce hash_hex = function
    | h when Z.Compare.(h < Parameters_Bls12_381.q) -> h
    | _ ->
      let next_hex = Sha256.string hash_hex
        |> Sha256.to_hex in
      Z.of_string_base 16 next_hex
      |> reduce next_hex
  in
  reduce (Bytes.to_string b) Parameters_Bls12_381.q

(* THIS FUNCTION IS NOT CRYPTOGRAPHICALLY SECURE
 * NEED TO BE REPLACED WITH A PROPER CRYPTOGRAPHIC HASH FUNCTION
 * IT IS ONLY USED AS REPLACEMENT DURING DEVELOPMENT
 *)
let h0 b =
  Parameters_Bls12_381.Pairing.G1.(
    gen ()
    |> exp (h1 b)
  )
