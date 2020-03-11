# MSP

This is an implementation of the pairing-based signature scheme described at
section 3.1 of [this paper](https://eprint.iacr.org/2018/483.pdf).

The implementation is functorized such that it can be based over different
pairing schemes and parameters. An implementation is provided for the
elliptic curve bls12-386, using this [ocaml binding](https://gitlab.com/dannywillems/ocaml-bls12-381/)
to the original [zcash library](https://github.com/zcash/librustzcash/tree/master/pairing) written in Rust.

> :warning: **current implementation is not safe**: the hash functions provided
> for the bls12-386 implementation are currently not safe, and should NOT be
> used in real cryptographic application, although they should behave
> reasonnably well.  Future work should include cryptograhically safe hash
> functions, such as provided in [this library](https://github.com/kwantam/bls12-381_hash)

There are two components in MSP:

### msp_lib
  The implementation of the signature scheme, that exposes an interface usable
  by third-parties.

### msp_cli.exe
  A simple command-line tool to experiment with the bls12-386 implementation,
  allowing to sign, combine, verify, etc.

## Build

You should start a fresh switch of ocaml 4.07.1:
```
$ opam switch create 4.07-msp 4.07.1
```

Then, follow the instructions to build the [ocaml binding](https://gitlab.com/dannywillems/ocaml-bls12-381/) of bls12-381 (but ignore the local switch creation instruction).
When everything is set, install it through opam to make it accessible to msp:

```
$ cd ocaml-bls12-381
$ opam install .
```

Install the different depencies of msp:
```
$ opam install base64 zarith sha nocrypto
```

Build the msp_cli executable:
```
$ dune build msp-cli/msp_cli.exe
```

Toy with the library in utop:
```
$ cd msp-lib
$ dune utop
```

Run tests (beware: these may take a bit of time, up to a few minutes):
```
$ dune runtest
```

## Usage

`msp_cli -h` prints a help message with all available commands and options

Example of a simple workflow with one signer:
```
$ msp_cli.exe keygen
$ echo "My message" > msg.txt
$ msp_cli.exe sign msg.txt id_msp.pub id_msp id_msp.pub -o sign.o
$ msp_cli.exe combine sign.o -o sign_final.o
$ msp_cli.exe aggregate id_msp.pub -o apk.pub
$ msp_cli.exe verify msg.txt sign_final.o apk.pub
GOOD signature [sign_final.o] of file msg.txt for key apk.pub
$ echo "Bad message" > msg_bad.txt
$ msp_cli.exe verify msg.txt sign_final.o apk.pub
BAD signature [sign_final.o] of file msg_bad.txt for key apk.pub
```

## Performance
Benchmarks are left for future development. In general we made the assumption
that the bottleneck is the computations done on the pairing scheme, in particular for
bls12-381, which are handled by third-party code. The additionnal operations
done by MSP should be highly neglectable, as hinted by the time taken by the
tests.

Thus, we did not focus on writing high-performance code, but rather on
writing readable one.

## Caveats

Although this code aims to be a serious implementation, please be aware of the
following caveats:
 - as mentionned in the introduction, the hash function are currently not proved
 safe for real usage
 - no protection is provided against timing attacks or more generally
 side-channel attacks
 - no particular care has been taken when handling private keys in memory, such
 as limiting their persistence
 - msp_client is mainly for testing purpose. For example, the private key is
 generated in a file with permissive permissions. It should not be used as an
 actual signature tool as it is
 - when signing, the list of public keys (pk1,..,pkn) is order-sensitive, as the public keys are just
 concatenated. Thus each signer must provide exactly the same list. If this is a
 problem, it can be mitigated by just sorting the list of keys in the Sign.sign function,
 or just by always sorting the list prior to calling msp_lib functions.
