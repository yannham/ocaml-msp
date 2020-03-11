module R = Nocrypto.Rng.Z

let () = Nocrypto_entropy_unix.initialize ()

let random z = R.gen z
let random_bits k = R.gen_bits k
