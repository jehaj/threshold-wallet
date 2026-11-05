use std::sync::mpsc;
use num_bigint::{BigRng010, BigUint};

use super::protocol::{ProtocolParams, SimpleSchnorrSignature};

pub struct Party {
    params: ProtocolParams,
    private_key_share: BigUint,
    incoming: mpsc::Receiver<BigUint>,
    outgoing: mpsc::Sender<BigUint>,
}

#[allow(unused)]
impl Party {
    pub fn new(
        params: ProtocolParams,
        incoming: mpsc::Receiver<BigUint>,
        outgoing: mpsc::Sender<BigUint>,
    ) -> Self {
        // Generate random key share in [0, q-1]
        let private_key_share = rand::rng().random_biguint_below(&params.q);
        Self { params, private_key_share, incoming, outgoing }
    }

    fn convert(&self, a: &BigUint) -> BigUint {
        self.params.g.modpow(a, &self.params.p)
    }

    fn compute_hash(&self, a: BigUint, b: BigUint) -> BigUint {
        (self.params.h)(a, b) % &self.params.q
    }

    fn eval_add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.params.q
    }

    fn eval_mul_by_constant(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.params.q
    }

    fn rand(&self) -> BigUint {
        rand::rng().random_biguint_below(&self.params.q)
    }

    fn send_and_receive(&self, to_send: &BigUint) -> BigUint {
        self.outgoing.send(to_send.clone()).unwrap();
        self.incoming.recv().unwrap()
    }

    pub fn run(&self, m: BigUint) -> (SimpleSchnorrSignature, BigUint) {
        // Compute the public key
        let sk_local = &self.private_key_share;
        let pk_share = self.convert(sk_local);
        let pk_share_incoming = self.send_and_receive(&pk_share);

        let pk = (pk_share * pk_share_incoming) % &self.params.p;

        // Compute the signature
        // Step 1: generate k
        let box_k = self.rand();
        // Step 2: convert k
        let group_box_k = self.convert(&box_k);
        // Step 3: open group sharing
        let group_box_k_incoming = self.send_and_receive(&group_box_k);
        let r_point =  group_box_k * group_box_k_incoming % &self.params.p;
        // Step 4: Compute the hash function
        let e = self.compute_hash(r_point, m);
        // Step 5: Compute z
        let z_prime = self.eval_mul_by_constant(&e, &self.private_key_share);
        let z_local = self.eval_add(&box_k, &z_prime);
        // Step 6: Open z
        let incoming_z = self.send_and_receive(&z_local);
        let z =  (z_local + incoming_z) % &self.params.q;
        // Ship the signature
        ((e, z), pk)
    }
}
