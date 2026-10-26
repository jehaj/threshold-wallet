use num_bigint::BigUint;
use super::protocol::{sign, challenge_hash, ProtocolParams};

#[test]
fn sign_then_verify() {
    let p = ProtocolParams::new(
        // p: field size
        BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap(),
        // n: curve order
        BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap(),
        challenge_hash,
    );
    // When I ask for a signature on m
    let m = "HELLO WORLD";
    let (sig, pk) = sign(p.clone(), m);
    // Then it should be valid
    sig.verify(m.as_bytes(), &pk).expect("Verify failed");

}
