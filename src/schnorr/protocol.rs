use std::sync::mpsc;
use std::thread;

use num_bigint::BigUint;
use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use secp256k1::schnorr::Signature;
use sha2::{Digest, Sha256};
use crate::schnorr::party::Party;

/// One message per protocol round, so a party can check it got the round it expected.
pub enum Msg {
    PkShare(PublicKey),
    NonceShare(PublicKey),
    Z(SecretKey),
}

/// Public parameters fixed when the protocol is initialized.
#[derive(Clone)]
pub struct ProtocolParams {
    pub p: BigUint,
    pub n: BigUint,
    pub h: fn(&[u8]) -> [u8; 32],
}

impl ProtocolParams {
    pub fn new(p: BigUint, n: BigUint, h: fn(&[u8]) -> [u8; 32]) -> Self {
        Self { p, n, h}
    }
}

pub fn tagged_sha256_hash(name: &str, x: &[u8]) -> [u8; 32] {
    let tag = name.as_bytes();
    let h1 = sha256_hash(tag);
    sha256_hash(&[&h1, &h1, x].concat())
}

pub fn challenge_hash(x: &[u8]) -> [u8; 32] {
    tagged_sha256_hash("BIP0340/challenge", x)
}

fn sha256_hash(x: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(x);
    hasher.finalize().into()
}

pub fn sign(p: ProtocolParams, m : &str) -> (Signature, XOnlyPublicKey) {
    // Cross-wire: what p1 sends, p2 receives, and vice versa.
    let (from_p2, to_p1) = mpsc::channel();
    let (from_p1, to_p2) = mpsc::channel();
    let p1 = Party::new(p.clone(), to_p1, from_p1);
    let p2 = Party::new(p.clone(), to_p2, from_p2);

    // output the signatures
    // Run each party on its own thread so their send/recv calls can interleave.
    let ((sig1, pk1), (sig2, pk2)) = thread::scope(|s| {
        let h1 = s.spawn(move || p1.run(m.as_bytes()));
        let h2 = s.spawn(move || p2.run(m.as_bytes()));
        (h1.join().unwrap(), h2.join().unwrap())
    });

    // Check they use the same key
    assert_eq!(pk1, pk2);
    // Check sigs are the same
    assert_eq!(sig1, sig2);

    (sig1, pk1)
}