use num_bigint::{BigRng010, BigUint};
use super::protocol::{ProtocolParams};

pub struct TrustedDealer {
    params: ProtocolParams,
    alpha: BigUint
}
#[derive(Clone)]
pub struct Key {
    pub alpha: BigUint,
    pub beta: BigUint
}

#[derive(Clone)]
pub struct Share {
    pub key: Key,
    pub tag: BigUint,
    pub share : BigUint
}

impl Share {
    pub fn new(
        key: Key,
        tag: BigUint,
        share: BigUint
    ) -> Self {
        Self { key, tag, share }
    }
}


impl TrustedDealer {
    pub fn new(
        params: ProtocolParams,
        alpha: BigUint
    ) -> Self {
        Self { params, alpha}
    }

    pub fn rand(&self) -> (Share,Share) {
        let r_a = rand::rng().random_biguint_below(&self.params.q);
        let r_b = rand::rng().random_biguint_below(&self.params.q);

        let beta_a = rand::rng().random_biguint_below(&self.params.p);
        let beta_b = rand::rng().random_biguint_below(&self.params.p);

        let t_a = tag(&self.alpha, &beta_b, &r_a,&self.params.q);
        let t_b = tag(&self.alpha, &beta_a, &r_b,&self.params.q);

        let key_a = Key{alpha: self.alpha.clone(),beta: beta_a.clone()};
        let key_b = Key{alpha: self.alpha.clone(),beta: beta_b.clone()};
        let share_a = Share::new(key_a, t_a, r_a);
        let share_b = Share::new(key_b, t_b, r_b);

        (share_a, share_b)
    }

}

fn tag(alpha: &BigUint, beta: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    alpha * x + beta % q
}

