mod simple_schnorr;
mod schnorr;
mod ecdsa;

use num_bigint::BigUint;
use secp256k1::Message;

fn main() {
    println!("=== Threshold Wallet Protocols Demo ===\n");

    // 1. Simple Schnorr (Toy Group)
    println!("--- 1. Simple Schnorr (2-Party) ---");
    let toy_params = simple_schnorr::protocol::ProtocolParams::new(
        BigUint::from(103u32),
        BigUint::from(17u32),
        BigUint::from(64u32),
        simple_schnorr::protocol::sha256_hash,
    );
    let m_simple = BigUint::from(42u32);
    let (sig_simple, pk_simple) = simple_schnorr::protocol::sign(toy_params.clone(), m_simple.clone());
    let valid_simple = simple_schnorr::verify::verify(pk_simple.clone(), toy_params, sig_simple.clone(), m_simple.clone());
    println!("Public key: {pk_simple}");
    println!("Signature: (e: {}, z: {})", sig_simple.0, sig_simple.1);
    println!("Verification: {}\n", if valid_simple { "SUCCESS" } else { "FAILED" });

    // 2. BIP-340 Schnorr (secp256k1)
    println!("--- 2. BIP-340 Schnorr (2-Party) ---");
    let schnorr_params = schnorr::protocol::ProtocolParams::new(
        BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap(),
        BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap(),
        schnorr::protocol::challenge_hash,
    );
    let msg_schnorr = "HELLO WORLD";
    let (sig_schnorr, pk_schnorr) = schnorr::protocol::sign(schnorr_params, msg_schnorr);
    sig_schnorr.verify(msg_schnorr.as_bytes(), &pk_schnorr).expect("Schnorr verification failed");
    println!("XOnly Public Key: {pk_schnorr}");
    println!("Signature: {sig_schnorr}");
    println!("Verification: SUCCESS\n");

    // 3. 2-Party ECDSA (secp256k1)
    println!("--- 3. 2-Party ECDSA (secp256k1) ---");
    let msg_ecdsa = "HELLO WORLD";
    let (sig_ecdsa, pk_ecdsa) = ecdsa::protocol::sign(msg_ecdsa);
    let hash = ecdsa::protocol::challenge_hash(msg_ecdsa.as_bytes());
    let msg = Message::from_digest(hash);
    sig_ecdsa.verify(msg, &pk_ecdsa).expect("ECDSA verification failed");
    println!("Public Key: {pk_ecdsa}");
    println!("Signature: {sig_ecdsa}");
    println!("Verification: SUCCESS\n");
}
