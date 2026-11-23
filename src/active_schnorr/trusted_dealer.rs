use num_bigint::{BigRng010, BigUint};
use super::protocol::{ProtocolParams};

#[derive(Clone)]
pub struct Key {
    pub alpha: BigUint,
    pub beta: BigUint
}

impl Key {
    pub fn new(alpha: BigUint, beta: BigUint) -> Self {
        Self { alpha, beta }
    }
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

pub struct TrustedDealer {
    pub params: ProtocolParams,
    alpha_a: BigUint,
    alpha_b: BigUint
}

impl TrustedDealer {
    pub fn new(
        params: ProtocolParams,
    ) -> Self {
        let alpha_a = rand_param(&params.q);
        let alpha_b = rand_param(&params.q);
        Self { params, alpha_a, alpha_b }
    }

    pub fn rand(&self) -> (Share,Share) {
        let q = &self.params.q;

        let r_a = rand_param(q);
        let r_b = rand_param(q);

        let beta_a = rand_param(q);
        let beta_b = rand_param(q);

        let t_a = tag(&self.alpha_b, &beta_b, &r_a,q);
        let t_b = tag(&self.alpha_a, &beta_a, &r_b,q);

        let key_a = Key::new(self.alpha_a.clone(), beta_a.clone());
        let key_b = Key::new(self.alpha_b.clone(), beta_b.clone());
        let share_a = Share::new(key_a, t_a, r_a);
        let share_b = Share::new(key_b, t_b, r_b);

        (share_a, share_b)
    }

}

fn rand_param(param: &BigUint) -> BigUint {
    rand::rng().random_biguint_below(param)
}

fn tag(alpha: &BigUint, beta: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    (alpha * x + beta) % q
}

