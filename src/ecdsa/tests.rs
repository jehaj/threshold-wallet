use secp256k1::Message;
use crate::ecdsa::protocol::{sign, challenge_hash};

#[test]
fn sign_then_verify() {
    // When I ask for a signature on m
    let m = "HELLO WORLD";
    let (sig, pk) = sign(m);
    let hash = challenge_hash(m.as_ref());
    let msg = Message::from_digest(hash);
    // Then it should be valid
    sig.verify(msg, &pk).expect("Verify failed");
}
