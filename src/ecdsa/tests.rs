use std::sync::mpsc;
use std::thread;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use secp256k1::ecdsa::Signature;
use secp256k1::Message;
use crate::ecdsa::party::{BeaverTriple, Party};
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

#[test]
fn sign_then_verify_another() {
    // given signatures on m and m'
    let m = "HELLO WORLD";
    let m_prime = "GOODBYE WORLD";

    let (sig, pk) = sign(m);

    // when verify the signature s for m with m'
    let hash = challenge_hash(m_prime.as_ref());
    let msg = Message::from_digest(hash);

    // then it fails
    assert!(sig.verify(msg, &pk).is_err())
}

#[test]
fn sign_then_verify_modified_signature() {
    // given signatures on m
    let m = "HELLO WORLD";

    let (sig, pk) = sign(m);

    // when verify the signature s modified to s' by changing the last byte
    let mut bytes = sig.serialize_compact();
    bytes[63] = bytes[63] ^ 1_u8;
    let sig = Signature::from_compact(&bytes).expect("Re-creating signature failed");
    let hash = challenge_hash(m.as_ref());
    let msg = Message::from_digest(hash);

    // then it fails
    assert!(sig.verify(msg, &pk).is_err())
}

#[test]
fn sign_then_verify_wrong_public_key() {
    let m = "HELLO WORLD";
    let (sig, _pk1) = sign(m);
    let (_sig2, pk2) = sign(m);

    let hash = challenge_hash(m.as_ref());
    let msg = Message::from_digest(hash);

    assert!(sig.verify(msg, &pk2).is_err());
}

#[test]
fn sign_then_verify_corrupted_r() {
    let m = "HELLO WORLD";
    let (sig, pk) = sign(m);

    let mut bytes = sig.serialize_compact();
    bytes[31] ^= 1_u8;
    let sig = Signature::from_compact(&bytes).expect("Re-creating signature failed");
    let hash = challenge_hash(m.as_ref());
    let msg = Message::from_digest(hash);

    assert!(sig.verify(msg, &pk).is_err());
}

#[test]
fn multiple_signs_are_different() {
    let m = "HELLO WORLD";
    let (sig1, _pk1) = sign(m);
    let (sig2, _pk2) = sign(m);

    let r1 = &sig1.serialize_compact()[..32];
    let r2 = &sig2.serialize_compact()[..32];
    assert_ne!(r1, r2);
    assert_ne!(sig1, sig2);
}

fn random_scalar() -> Scalar {
    let bytes: [u8; 32] = rand::random();
    Option::from(Scalar::from_repr(bytes.into())).unwrap_or_else(|| random_scalar())
}

#[test]
#[should_panic]
fn mismatched_messages_between_parties() {
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

        let triple0 = BeaverTriple {
            a: u_0,
            b: v_0,
            c: w_0,
        };
        let triple1 = BeaverTriple {
            a: u_1,
            b: v_1,
            c: w_1,
        };
        triples_p1.push(triple0);
        triples_p2.push(triple1);
    }

    thread::scope(|s| {
        s.spawn(move || p1.run(b"hello", triples_p1, true));
        s.spawn(move || p2.run(b"world", triples_p2, false));
    });
}
