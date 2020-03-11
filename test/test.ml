let msg_min_size = 16
let msg_max_size = 1024
let keys_min_count = 2 
let keys_max_count = 10 
let batch_min_size = 5 
let batch_max_size = 20 

module Parameters = Msp_lib.Parameters_Bls12_381

module Key = Msp_lib.Key.Make
  (Parameters)
  (Msp_lib.Hash_Bls12_381_unsafe)
  (Msp_lib.Random_fortuna)

module Sign = Msp_lib.Sign.Make
  (Parameters)
  (Msp_lib.Hash_Bls12_381_unsafe)
  (Msp_lib.Random_fortuna)

let take n l =
  let rec take_ n acc l = match (n,l) with
    | 0, _ -> List.rev acc
    | _, [] -> Stdlib.invalid_arg "take: n must be smaller than the length of the list"
    | n, x::xs -> take_ (n-1) (x::acc) xs
  in
  take_ n [] l

let shuffle l =
  let a = Array.of_list l in
  for i = Array.length a-1 downto 1 do
    let j = Stdlib.Random.int (i+1) in
    let tmp = a.(i) in
    a.(i) <- a.(j);
    a.(j) <- tmp;
  done;
  Array.to_list a

let message_gen =
  QCheck.(
    Gen.int_range msg_min_size msg_max_size
    |> string_of_size)

let keys_gen n =  
  List.init n (fun _ -> ())
  |> List.map Key.generate

let batch_gen = 
  QCheck.(
    pair message_gen @@ int_range keys_min_count keys_max_count
    |> list_of_size @@ gen @@ int_range batch_min_size batch_max_size 
  )

(* Generate random parameters for a batch
 * (list of pairs of a message and a batch size)
 * with duplicated messages
 *)
let batch_dup_gen =
  let gen state =
    QCheck.Gen.(
      let msg_gen = QCheck.gen message_gen in
      let size = int_range batch_min_size batch_max_size state in
      let distinct = int_range 1 (max (size-1) 1) state in
      let pool = Array.init distinct (fun _ -> msg_gen state) in
      List.init size (fun _ ->  
        let i = int_bound (distinct-1) state in
        let n = int_range keys_min_count keys_max_count state in 
        (pool.(i),n))
    ) in
  QCheck.make gen

let sign m n =
  let m = Bytes.of_string m in
  let keys = keys_gen n in
  let pks = List.map fst keys in
  let apk = Key.aggregate pks in 
  let s = List.map (fun (pk,sk) -> Sign.sign sk pk pks m) keys
    |> Sign.combine in
  (apk,m,s)

let test_verify_good count =
  let check (m,n) =
    let apk, m, s = sign m n in
    match Sign.verify apk m s with
    | Ok true -> true
    | _ -> false
  in
  let gen = QCheck.(pair message_gen (int_range keys_min_count keys_max_count)) in
  QCheck.Test.make ~count ~name:"verify good signature" gen check

let test_verify_bad count =
  let n = QCheck.Gen.generate1 (QCheck.Gen.int_range keys_min_count
    keys_max_count) in
  let m = QCheck.Gen.generate1 (QCheck.gen message_gen) in
  let apk, m, s = sign m n in

  let check m' =
    let m' = Bytes.of_string m' in
    QCheck.assume (m <> m');
    match Sign.verify apk m' s with
    | Ok false -> true
    | _ -> false
  in
  QCheck.Test.make ~count ~name:"verify bad signature" message_gen check

let test_batch_verify_good count =
  let check data =
    let batch = List.map (fun (m,n) -> sign m n) data in 
    match Sign.batch_verify batch with
    | Ok true -> true
    | _ -> false
  in
  QCheck.Test.make ~count ~name:"batch_verify good signature" batch_gen check

(* Test that shuffling the batch does not impact the verification *)
let test_batch_verify_shuffle count =
  let check data =
    let batch = List.map (fun (m,n) -> sign m n) data in 
    match Sign.batch_verify (shuffle batch) with
    | Ok true -> true
    | _ -> false
  in
  QCheck.Test.make ~count ~name:"batch_verify shuffle" batch_gen check

let test_batch_verify_dup_good count =
  let check data =
    let batch = List.map (fun (m,n) -> sign m n) data in 
    match Sign.batch_verify batch with
    | Ok true -> true
    | _ -> false
  in
  QCheck.Test.make ~count ~name:"batch_verify duplicate good signature"
    batch_dup_gen check

let test_batch_verify_bad count =
  let data = QCheck.Gen.generate1 (QCheck.gen batch_gen) in 
  let batch = List.map (fun (m,n) -> sign m n) data in
  let batch_size = List.length batch in

  let check (m',index) =
    let m' = Bytes.of_string m' in
    QCheck.assume (0 <= index && index < batch_size);
    let batch' = List.mapi (fun i ((apk,_,s) as v) ->
      if i = index then
        (apk,m',s)
      else
        v) batch in
    match Sign.batch_verify batch' with
    | Ok false -> true
    | _ -> false
  in
  let gen = QCheck.(pair message_gen @@ int_bound (batch_size-1)) in
  QCheck.Test.make ~count ~name:"batch_verify bad signature" gen check

let test_batch_verify_dup_bad count =
  let data = QCheck.Gen.generate1 (QCheck.gen batch_dup_gen) in 
  let batch = List.map (fun (m,n) -> sign m n) data in
  let batch_size = List.length batch in

  let check (m',index) =
    QCheck.assume (0 <= index && index < batch_size);
    let m' = Bytes.of_string m' in
    let batch' = List.mapi (fun i ((apk,_,s) as v) ->
      if i = index then
        (apk,m',s)
      else
        v) batch in
    match Sign.batch_verify batch' with
    | Ok false -> true
    | _ -> false
  in
  let gen = QCheck.(pair message_gen @@ int_bound (batch_size-1)) in
  QCheck.Test.make ~count ~name:"batch_verify duplicate bad signature" gen check

let () =
  QCheck_runner.run_tests [
    test_verify_good 10;
    test_verify_bad 50;
    test_batch_verify_good 5;
    test_batch_verify_shuffle 5;
    test_batch_verify_dup_good 5;
    test_batch_verify_bad 5;
    test_batch_verify_dup_bad 5] ~verbose:true
  |> exit;
