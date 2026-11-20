use std::sync::mpsc;
use std::thread;

use num_bigint::BigUint;

use super::party::Party;
use super::protocol::{sign, sha256_hash, ProtocolParams};
use super::verify::verify;

#[test]
fn sign_then_verify() {
    // Given a Toy Schnorr group: q = 17 divides p - 1 = 102, and g = 2^6 mod 103 has order q.
    let p = ProtocolParams::new(
        BigUint::from(103u32),
        BigUint::from(17u32),
        BigUint::from(64u32),
        sha256_hash,
    );
    // When I ask for a signature on m
    let m = BigUint::from(42u32);
    let (sig, pk) = sign(p.clone(), m.clone());
    // Then it should be valid
    assert!(verify(pk, p, sig.clone(), m.clone()), "{sig:?} is not a valid signature on {m}");
}

#[test]
#[should_panic]
fn mismatched_messages_between_parties() {
    // q = 4294962299 divides p - 1 = 8589924598, and g = 4 has order q mod p.
    let p = ProtocolParams::new(
        BigUint::from(8589924599u64),
        BigUint::from(4294962299u32),
        BigUint::from(4u32),
        sha256_hash,
    );

    let (from_p2, to_p1) = mpsc::channel();
    let (from_p1, to_p2) = mpsc::channel();
    let p1 = Party::new(p.clone(), to_p1, from_p1);
    let p2 = Party::new(p.clone(), to_p2, from_p2);

    let (m1, m2) = (BigUint::from(42u32), BigUint::from(43u32));
    let ((sig1, pk1), (sig2, pk2)) = thread::scope(|s| {
        let (m1_for_p1, m2_for_p2) = (m1.clone(), m2.clone());
        let h1 = s.spawn(move || p1.run(m1_for_p1));
        let h2 = s.spawn(move || p2.run(m2_for_p2));
        (h1.join().unwrap(), h2.join().unwrap())
    });

    // above does not panic, since they never verify the signature
    // but the other protocols we've implemented do
    // TODO: should behavior be the same?

    /*
    assert_eq!(pk1, pk2);
    assert_ne!(sig1, sig2);
    assert!(!verify(pk1.clone(), p.clone(), sig1.clone(), m1));
    assert!(!verify(pk1, p, sig2, m2));
     */
}
