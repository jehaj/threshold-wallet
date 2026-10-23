use num_bigint::{BigRng010, BigUint};

use super::protocol::ProtocolParams;

pub struct Party {
    params: ProtocolParams,
    private_key_share: BigUint,
}

impl Party {
    pub fn new(params: ProtocolParams) -> Self {
        // Generate random key share in [0, q-1]
        let private_key_share = rand::rng().random_biguint_below(&params.q);
        Self { params, private_key_share }
    }

    fn convert(&self, a: BigUint) -> BigUint {
        self.params.g.modpow(&a, &self.params.p)
    }

    fn compute_hash(&self, a: BigUint, b: BigUint) -> BigUint {
        (self.params.h)(a, b)
    }

    fn eval_add(&self, a: BigUint, b: BigUint) -> BigUint {
        (a + b) % &self.params.q
    }

    fn eval_mul_by_constant(&self, a: BigUint, b: BigUint) -> BigUint {
        (a * b) % &self.params.q
    }

    fn run(&self) -> BigUint {
        todo!()
    }
}
