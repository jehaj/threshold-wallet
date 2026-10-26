# A Threshold Wallet from BeDOZ

Educational two-party threshold signing protocols for a cryptocurrency wallet, built with arithmetic BeDOZa MPC in the trusted-dealer model.

A signing key kept in one place is a single point of failure, and every
extra copy is another target. In a threshold wallet, several parties share
the key and jointly produce an ordinary signature without ever
reconstructing the actual key.

The project covers two schemes:

- **Schnorr**: the parties jointly create the nonce point R and the
  signature response without revealing the key x or the nonce k. The core
  technique is lifting shares of a scalar a to the public group element aG
  (see Dalskov et al., threshold DNSSEC).
- **ECDSA** (planned)

The goal is signatures that libsecp256k1's standard verifier accepts.

> ⚠️ Educational only. Security is passive (honest-but-curious parties) with
> trusted preprocessing. Do not use this for real funds.

## Layout

- `src/simple_schnorr`: public parameters, the hash, and `sign`, which
  sets up the parties and runs them on separate threads.
- `src/simple_schnorr`: one party's state and its local computations.

## Run

    cargo run
