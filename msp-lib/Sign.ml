module type S = sig
  type s
  type pk
  type sk = Z.t

  val sign : sk -> pk -> pk list -> bytes -> s
  val combine : s list -> s
  val verify : pk -> bytes -> s -> (bool, string) result
  val batch_verify : (pk * bytes * s) list -> (bool, string) result

  val to_bytes : s -> bytes
  val of_bytes : bytes -> s
end

module Make
  (P : Parameters.S)
  (H : Hash.S with type g1 = P.Pairing.G1.t)
  (R : Random.S) = struct
  open P.Pairing

  type s = G1.t
  type pk = G2.t
  type sk = Z.t

  (* Take the first element of a non-empty list as the initializer of a
   * specialized fold (where 'b = 'a). When doing a product, this avoid the
   * first useless multiplication, namely the multiplication by the neutral
   * element
   *)
  let product mul one = function
    | [] -> one ()
    | x::xs -> List.fold_left mul x xs

  let prod_g1 = product G1.mul G1.one
  let prod_g2 = product G2.mul G2.one
  let prod_gt = product Gt.mul Gt.one

  let concat pks =
    List.map (fun pk -> G2.to_bytes pk) pks
    |> Bytes.concat Bytes.empty

  let sign sk pk pks m =
    let pks_cat = concat pks in
    let a =
      Bytes.cat (G2.to_bytes pk) pks_cat
      |> H.h1 in
    let e = Z.((a * sk) mod P.q)  in
    H.h0 m
    |> G1.exp e

  let combine = prod_g1 

  let verify_unsafe apk m sign =
    let p1 = pairing sign G2.(gen () |> inv) in
    let p2 = pairing (H.h0 m) apk in
    Gt.(eq (mul p1 p2) (one ()))

  let verify apk m sign =
    try
      Ok (verify_unsafe apk m sign)
    with _ -> Error "Uknown error in signature verification"

  (* Take a list of triplet (public key, message, signature)
   * and return either `Distinct of all messages are distinct,
   * or `Duplicate groups if there are duplicated messages. In the latter case,
   * groups is a list of list of triplet, which is a partition of the batch by
   * message's value (hash, in practice)
   *
   * Warning: this does not preserve the original list order
   *)
  let group_duplicates batch =
    Stdlib.(
      let t = Hashtbl.create (List.length batch) in
      (* Add all message to the hashtable, using SHA-256 as a key,
       * and return a boolean indicating if there where duplicate
       * and a list of all the distinct hashes of messages
       *)
      let has_dup, hashes = List.fold_left (fun (has_dup,hashes) ((_,m,_) as x) ->
        let h = Sha256.string (Bytes.to_string m)
          |> Sha256.to_bin in
        let was_bound = Hashtbl.mem t h in
        Hashtbl.add t h x;
        if was_bound then
          (true, hashes)
        else
          (has_dup, h::hashes)) (false, []) batch in
      if has_dup then
        let groups = List.map (fun hash -> Hashtbl.find_all t hash) hashes in
        `Duplicate groups
      else
        `Distinct
    )

  let batch_verify_distinct_unsafe batch =
    let sigma = List.map (fun (_,_,s) -> s) batch
      |> prod_g1 in
    let lhs = pairing sigma (G2.gen ()) in
    let rhs = List.map (fun (apk,m,_) -> pairing (H.h0 m) apk) batch
      |> prod_gt in
    Gt.eq lhs rhs

  let batch_verify_duplicate_unsafe groups =
    (* groups do not respect the original batch order, we reconstruct it *)
    let batch = List.flatten groups in
    let length = List.length batch in
    let es = List.init length (fun _ -> R.random_bits P.batch_param) in
    let sigma = List.map2 (fun (_,_,s) e -> G1.exp e s) batch es
      |> prod_g1 in
    let lhs = pairing sigma (G2.gen ()) in
    let rhs = List.fold_left (fun (es,acc) group ->
      match group with
      | [] -> assert false
      | (_,m,_)::_ ->
        (* For each group of signatures with the same message, raise each public
         * key to the corresponding random exponent, then compute their product
         * p and return the remainder of the random exponents and add the term
         * e(H0(m), p) to the stack acc
         *)
          let raise_key state pk = match state with
            | ([],_) -> assert false
            | (e::es, acc) -> (es, (G2.exp e pk)::acc) in

          let es, pks = List.fold_left (fun state (pk,_,_) ->
            raise_key state pk) (es, []) group in
          let subterm = prod_g2 pks
            |> pairing (H.h0 m) in
          (es, subterm::acc)) (es, []) groups
      |> snd
      |> prod_gt in
    Gt.eq lhs rhs

  let batch_verify (batch : (pk * bytes * s) list)  =
    match group_duplicates batch with
      | `Distinct -> (
        try
          Ok (batch_verify_distinct_unsafe batch)
        with _ -> Error "uknown error during signature verification")
      | `Duplicate groups -> (
        try
          Ok (batch_verify_duplicate_unsafe groups)
        with _ -> Error "uknown error during signature verification")

  let to_bytes = G1.to_bytes
  let of_bytes = G1.of_bytes
end
