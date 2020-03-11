module type S = sig
  type pk
  type sk = Z.t

  val generate : unit -> pk * sk
  val aggregate : pk list -> pk

  val pk_to_bytes : pk -> bytes
  val pk_of_bytes : bytes -> pk

  val sk_to_bytes : sk -> bytes
  val sk_of_bytes : bytes -> sk
end

module Make (P : Parameters.S) (H : Hash.S with type g1 = P.Pairing.G1.t) (R : Random.S) =
  struct
  module G2 = P.Pairing.G2
  type pk = G2.t
  type sk = Z.t

  let generate () =
    let sk = R.random P.q in
    let pk = G2.(
      gen ()
      |> exp sk
      ) in
    (pk, sk)

  let concat pks =
    List.map (fun pk -> G2.to_bytes pk) pks
    |> Bytes.concat Bytes.empty

  let aggregate = function
    | [] -> G2.one ()
    | (pk::pks as l) ->
      let pks_cat = concat l in
      let subterm pki =
        let e =
          Bytes.cat (G2.to_bytes pki) pks_cat
          |> H.h1 in
        G2.exp e pki
        in
      let first_term = subterm pk in
      List.fold_left (fun acc pk -> subterm pk |> G2.mul acc) first_term pks

  let pk_of_bytes = G2.of_bytes
  let pk_to_bytes = G2.to_bytes

  let sk_of_bytes bs =
    Bytes.to_string bs
    |> Z.of_bits

  let sk_to_bytes sk =
    Z.to_bits sk
    |> Bytes.of_string
end
