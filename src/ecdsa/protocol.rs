use std::sync::mpsc;
use std::thread;

use k256::{ProjectivePoint, Scalar};
use k256::elliptic_curve::PrimeField;
use num_bigint::BigUint;
use secp256k1::PublicKey;
use secp256k1::ecdsa::Signature;
use sha2::{Digest, Sha256};
use crate::ecdsa::party::{BeaverTriple, Party};

/// One message per protocol round, so a party can check it got the round it expected.
pub enum Msg {
    PkShare(ProjectivePoint),
    CShare(Scalar),
    DShare(Scalar),
    EShare(Scalar),
    RShare(ProjectivePoint),
    NonceShare(ProjectivePoint),
    Z(Scalar),
}

pub fn tagged_sha256_hash(name: &str, x: &[u8]) -> [u8; 32] {
    let tag = name.as_bytes();
    let h1 = sha256_hash(tag);
    sha256_hash(&[&h1, &h1, x].concat())
}

pub fn challenge_hash(x: &[u8]) -> [u8; 32] {
    // TODO is this the correct name ???
    tagged_sha256_hash("BIP0340/challenge", x)
}

fn sha256_hash(x: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(x);
    hasher.finalize().into()
}

fn random_scalar() -> Scalar {
    let bytes: [u8; 32] = rand::random();
    Option::from(Scalar::from_repr(bytes.into())).unwrap_or_else(|| random_scalar())
}

pub fn sign(m : &str) -> (Signature, PublicKey) {
    // Cross-wire: what p1 sends, p2 receives, and vice versa.
    let (from_p2, to_p1) = mpsc::channel();
    let (from_p1, to_p2) = mpsc::channel();
    let p1 = Party::new(challenge_hash, to_p1, from_p1);
    let p2 = Party::new(challenge_hash, to_p2, from_p2);

    let mut triples_p1 = vec![];
    let mut triples_p2 = vec![];

    for _ in 0..2 {
        let u_0 = random_scalar();
        let u_1 = random_scalar();
        let u = u_0 + u_1;

        let v_0 = random_scalar();
        let v_1 = random_scalar();
        let v = v_0 + v_1;

        let w = u * v;
        let w_0 = random_scalar();
        let w_1 = w - w_0;

        let triple0 = BeaverTriple{
            a: u_0,
            b: v_0,
            c: w_0,
        };
        let triple1 = BeaverTriple{
            a: u_1,
            b: v_1,
            c: w_1,
        };
        triples_p1.push(triple0);
        triples_p2.push(triple1);
    }

    // output the signatures
    // Run each party on its own thread so their send/recv calls can interleave.
    let ((sig1, pk1), (sig2, pk2)) = thread::scope(|s| {
        let h1 = s.spawn(move || p1.run(m.as_bytes(), triples_p1, true));
        let h2 = s.spawn(move || p2.run(m.as_bytes(), triples_p2, false));
        (h1.join().unwrap(), h2.join().unwrap())
    });

    // Check they use the same key
    assert_eq!(pk1, pk2);
    // Check sigs are the same
    assert_eq!(sig1, sig2);

    (sig1, pk1)
}