use num_bigint::BigUint;

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
