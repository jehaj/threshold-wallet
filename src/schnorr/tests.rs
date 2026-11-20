use std::sync::mpsc;
use std::thread;

use num_bigint::BigUint;

use super::party::Party;
use super::protocol::{sign, challenge_hash, ProtocolParams};

fn protocol_params() -> ProtocolParams {
    ProtocolParams::new(
        // p: field size
        BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap(),
        // n: curve order
        BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap(),
        challenge_hash,
    )
}

#[test]
fn sign_then_verify() {
    let p = protocol_params();
    // When I ask for a signature on m
    let m = "HELLO WORLD";
    let (sig, pk) = sign(p.clone(), m);
    // Then it should be valid
    sig.verify(m.as_bytes(), &pk).expect("Verify failed");

}

#[test]
#[should_panic]
fn mismatched_messages_between_parties() {
    let p = protocol_params();
    
    let (from_p2, to_p1) = mpsc::channel();
    let (from_p1, to_p2) = mpsc::channel();
    let p1 = Party::new(p.clone(), to_p1, from_p1);
    let p2 = Party::new(p, to_p2, from_p2);

    thread::scope(|s| {
        s.spawn(move || p1.run(b"hello"));
        s.spawn(move || p2.run(b"world"));
    });
}
