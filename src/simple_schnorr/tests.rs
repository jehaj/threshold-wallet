use num_bigint::BigUint;

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
