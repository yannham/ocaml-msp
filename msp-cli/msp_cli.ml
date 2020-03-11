module Parameters = Msp_lib.Parameters_Bls12_381

module Key = Msp_lib.Key.Make
  (Parameters)
  (Msp_lib.Hash_Bls12_381_unsafe)
  (Msp_lib.Random_fortuna)

module Sign = Msp_lib.Sign.Make
  (Msp_lib.Parameters_Bls12_381)
  (Msp_lib.Hash_Bls12_381_unsafe)
  (Msp_lib.Random_fortuna)

let usage_msg =
{eof|Usage: msp-cli ACTION [ARGUMENTS...] [-o output_file]

ACTIONS:
  - combine <file 1> ... <file n>:
    Read partial signatures from specified files and combine them into the final
    signature (one round of MSP)
  - sign <message file> <pk file> <sk file> <pk file 1> .. <pk file n>:
    Given the public key and the secret key of the user, together with the list
    of all the public keys of the signers (including the user's one that must be
    repeated), generate a partial signature of the content of the message file
    for the given parameters
  - keygen:
    generate a fresh pair of public key and secret key. If an output file is
    specified, store them in output and output_pub, otherwise in file id_msp and
    id_msp.pub, or variant with indexes if these names are already taken
  - aggregate <pk_file 1> ... <pk_file n>:
    produce the aggregated public key of a set of users
  - verify <message file> <signature file> <aggregated public key file>
|eof}

let print_usage_and_exit () =
  Printf.eprintf "%s" usage_msg;
  exit 2

let output = ref None
let help = ref false
let args = Queue.create ()

let push_arg arg = Queue.add arg args
let set_ref_opt r v = r := Some v

let speclist = [
  ("-o", Arg.String (set_ref_opt output), "Write the output in the specified file rather
  than on the standard output");
  ("-h", Arg.Set help, "Print this help message")
]

let read_file file =
  Stdlib.(
    let ic = open_in_bin file in
    let b = Buffer.create 512 in
    let block = Bytes.create 512 in
    let rec loop () =
      match input ic block 0 512 with
      | 0 ->
          close_in ic;
          Buffer.contents b
      | n ->
          Buffer.add_subbytes b block 0 n;
          loop ()
    in
    loop ()
  )

let read_decode file =
    match read_file file |> Base64.decode with
    | Ok s -> Bytes.of_string s
    | Error (`Msg s) ->
      Printf.eprintf "Error when decoding file %s: %s." file s;
      Printf.eprintf " Files must constain bse64 representation the date (keys,
      signatures, etc.)\n";
      exit 1

let write_encode file data =
  Stdlib.(
    let oc = open_out_bin file in
    let data = Bytes.to_string data |> Base64.encode in
    match data with
    | Ok s ->
        output_string oc s;
        close_out oc
    | Error (`Msg s) ->
        Printf.eprintf "Error during base64 encoding of data: %s" s;
        exit 1
  )

let read_signature file =
  let content = read_decode file in
  try
    Sign.of_bytes content
  with _ ->
    Printf.eprintf "Error when parsing the signature: the base64 encoded content
      does not represent a valid signature\n";
    exit 1

let read_pk file =
  let data = read_decode file in
  try
    Key.pk_of_bytes data
  with _ ->
    Printf.eprintf "Error when parsing the public key: the base64 encoded content
      does not represent a valid signature\n";
    exit 1

let read_sk file =
  let data = read_decode file in
  try
    Key.sk_of_bytes data
  with _ ->
    Printf.eprintf "Error when parsing the public key: the base64 encoded content
      does not represent a valid signature\n";
    exit 1

let write_pk file data =
  Key.pk_to_bytes data
  |> write_encode file

let write_sk file data =
  Key.sk_to_bytes data
  |> write_encode file

let output_result s =
  let () = match !output with
  | None -> Printf.printf "%s\n" s
  | Some file ->
    let oc = open_out file in
    output_string oc s;
    close_out oc in
  exit 0

let output_encode bs =
  match bs |> Bytes.to_string |> Base64.encode with
    | Ok s -> output_result s
    | Error (`Msg s) ->
        Printf.eprintf "Error during the base64 encoding of the result: %s" s;
        exit 1

let select_key_files () =
  let file = "id_msp" in
  let rec loop n =
    let pk_f, sk_f =
      if n = 0 then
        (file ^ ".pub", file)
      else
        (Printf.sprintf "%s%d.pub" file n,
         Printf.sprintf "%s%d" file n)
    in
    if not (Sys.file_exists pk_f) && not (Sys.file_exists sk_f) then
      (pk_f,sk_f)
    else
      loop (n+1)
  in
  loop 0

let combine files =
  let res =
    List.map read_signature files
    |> Sign.combine
    |> Sign.to_bytes
    |> Bytes.to_string
    |> Base64.encode in
  match res with
    | Ok s -> output_result s
    | Error (`Msg s) ->
      Printf.eprintf "Error during base64 encoding: %s" s;
      exit 1

let sign msg_f pk_f sk_f pk_fs =
  let m = read_file msg_f |> Bytes.of_string in
  let pk = read_pk pk_f in
  let sk = read_sk sk_f in
  let pks = List.map read_pk pk_fs in
  Sign.sign sk pk pks m
  |> Sign.to_bytes
  |> output_encode

let keygen () =
  let pk, sk = Key.generate () in
  let (pk_f, sk_f) = match !output with
    | None -> select_key_files ()
    | Some file -> (file ^ ".pub", file)
  in
  write_pk pk_f pk;
  write_sk sk_f sk

let aggregate pk_fs =
  List.map read_pk pk_fs
  |> Key.aggregate
  |> Key.pk_to_bytes
  |> output_encode

let verify msg_f sign_f apk_f =
  let m = read_file msg_f |> Bytes.of_string in
  let s = read_signature sign_f in
  let apk = read_pk apk_f in
  match Sign.verify apk m s with
   | Ok v ->
      let result = if v then "GOOD" else "BAD" in
      Printf.sprintf "%s signature [%s] of file %s for key %s" result sign_f msg_f
        apk_f
      |> output_result
   | Error s ->
       Printf.eprintf "Error when verifying signature: %s\n" s;
       exit 1

let args_at_least n action =
  if (Queue.length args) < n then (
    Printf.eprintf "%s: %s: not enough arguments\n" Sys.argv.(0) action;
    print_usage_and_exit ())

let args_as_list () =
  Queue.fold (fun acc x -> x::acc) [] args
  |> List.rev

let () =
  Arg.parse speclist push_arg usage_msg;
  let () = if !help then (
    Printf.eprintf "%s" usage_msg;
    exit 0) in
  let () = if Queue.is_empty args then
    print_usage_and_exit () in
  match Queue.pop args with
  | "combine" as action ->
      args_at_least 1 action;
      combine (args_as_list ())
  | "sign" as action ->
      args_at_least 4 action;
      let msg_f = Queue.pop args in
      let pk_f = Queue.pop args in
      let sk_f = Queue.pop args in
      sign msg_f pk_f sk_f (args_as_list ())
  | "keygen" ->
      let () = if not (Queue.is_empty args) then (
        Printf.eprintf "%s: keygen: too many arguments\n" Sys.argv.(0);
        print_usage_and_exit ()) in
      keygen ()
  | "aggregate" as action ->
      args_at_least 1 action;
      aggregate (args_as_list ())
  | "verify" ->
      let () = if Queue.length args <> 3 then (
        Printf.eprintf "%s: verify: wrong number of arguments (need exactly
          3)\n" Sys.argv.(0);
        print_usage_and_exit ()) in
      let msg_f = Queue.pop args in
      let sign_f = Queue.pop args in
      let apk_f = Queue.pop args in
      verify msg_f sign_f apk_f
  | action ->
      Printf.eprintf "%s: Unknown action %s\n" Sys.argv.(0) action;
      Printf.eprintf "%s" usage_msg;
      exit 2
