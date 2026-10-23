mod schnorr;

use num_bigint::BigUint;

use crate::schnorr::protocol::{ProtocolParams, sha256_hash};

fn main() {
    // Toy Schnorr group: q = 17 divides p - 1 = 102, and g = 2^6 mod 103 has order q.
    let p = ProtocolParams::new(
        BigUint::from(103u32),
        BigUint::from(17u32),
        BigUint::from(64u32),
        sha256_hash,
    );
    let m = BigUint::from(42u32);
    let (sig, pk) = schnorr::protocol::sign(p.clone(), m.clone());
    println!("signature: {:?}", sig);
    let is_valid = schnorr::verify::verify(pk, p, sig.clone(), m.clone());
    let mf = if is_valid { "" } else { "not" };
    println!("{sig:?} is {mf} a valid signature on {m}");
}
