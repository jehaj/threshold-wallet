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
    
    fn open_group(&self, share: &BigUint) -> BigUint {
        let inc_share = self.send_and_receive(share);
        (share * inc_share) % &self.params.p
    }

    fn open_scalar(&self, share: &BigUint) -> BigUint {
        let inc_share = self.send_and_receive(share);
        (share + inc_share) % &self.params.q
    }

    pub fn run(&self, m: BigUint) -> (SimpleSchnorrSignature, BigUint) {
        // Compute the public key
        let sk_local = &self.private_key_share;

        let pk = self.open_group(&self.convert(sk_local));

        // Compute the signature
        // Step 1: generate k
        let box_k = self.rand();
        // Step 2: convert k
        // Step 3: open group sharing
        let r =  self.open_group(&self.convert(&box_k));
        // Step 4: Compute the hash function
        let e = self.compute_hash(r, m);
        // Step 5: Compute z
        let z_prime = self.eval_mul_by_constant(&e, sk_local);
        let z_local = self.eval_add(&box_k, &z_prime);
        // Step 6: Open z
        let z =  self.open_scalar(&z_local);
        // Ship the signature
        ((e, z), pk)
    }
}
