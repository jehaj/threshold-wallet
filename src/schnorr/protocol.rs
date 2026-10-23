use std::sync::mpsc;
use std::thread;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use crate::schnorr::party::Party;

pub type SchnorrSignature = (BigUint, BigUint);

/// Public parameters fixed when the protocol is initialized.
#[derive(Clone)]
pub struct ProtocolParams {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub h: fn(BigUint, BigUint) -> BigUint,
}

impl ProtocolParams {
    pub fn new(p: BigUint, q: BigUint, g: BigUint, h: fn(BigUint, BigUint) -> BigUint) -> Self {
        Self { p, q, g, h}
    }
}

fn sha256_hash(a: BigUint, b: BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(a.to_bytes_be());
    hasher.update(b.to_bytes_be());
    BigUint::from_bytes_be(&hasher.finalize())
}

pub fn sign(m : BigUint) -> SchnorrSignature {
    // Toy Schnorr group: q = 17 divides p - 1 = 102, and g = 2^6 mod 103 has order q.
    let p = ProtocolParams::new(
        BigUint::from(103u32),
        BigUint::from(17u32),
        BigUint::from(64u32),
        sha256_hash,
    );
    
    // Cross-wire: what p1 sends, p2 receives, and vice versa.
    let (from_p2, to_p1) = mpsc::channel();
    let (from_p1, to_p2) = mpsc::channel();
    let p1 = Party::new(p.clone(), to_p1, from_p1);
    let p2 = Party::new(p.clone(), to_p2, from_p2);

    // output the signatures
    // Run each party on its own thread so their send/recv calls can interleave.
    let (m1, m2) = (m.clone(), m.clone());
    let h1 = thread::spawn(move || p1.run(m1));
    let h2 = thread::spawn(move || p2.run(m2));
    let sig1 = h1.join().unwrap();
    let sig2 = h2.join().unwrap();

    // check sigs are the same
    assert_eq!(sig1.0, sig2.0);
    assert_eq!(sig1.1, sig2.1);

    sig1
}