use num_bigint::BigUint;
use crate::simple_schnorr::protocol::{SimpleSchnorrSignature, ProtocolParams};

pub fn verify(pk: BigUint, params: ProtocolParams, sig: SimpleSchnorrSignature, m: BigUint) -> bool {
    let alpha = params.g;
    let (e, z) = sig;
    let left = alpha.modpow(&z, &params.p);

    let exponent = (&params.q - e.clone()) % &params.q;
    let right = pk.modpow(&exponent, &params.p);
    let comb = (left * right) % &params.p;
    // check
    let h = (params.h)(comb, m) % params.q;
    h == e
}
