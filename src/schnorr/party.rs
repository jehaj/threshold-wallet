use std::sync::mpsc;
use num_bigint::{BigRng010, BigUint};

use super::protocol::{ProtocolParams, SchnorrSignature};

pub struct Party {
    params: ProtocolParams,
    private_key_share: BigUint,
    incoming: mpsc::Receiver<BigUint>,
    outgoing: mpsc::Sender<BigUint>,
}

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

    fn convert(&self, a: BigUint) -> BigUint {
        self.params.g.modpow(&a, &self.params.p)
    }

    fn compute_hash(&self, a: BigUint, b: BigUint) -> BigUint {
        (self.params.h)(a, b) % &self.params.q
    }

    fn eval_add(&self, a: BigUint, b: BigUint) -> BigUint {
        (a + b) % &self.params.q
    }

    fn eval_mul_by_constant(&self, a: BigUint, b: BigUint) -> BigUint {
        (a * b) % &self.params.q
    }

    fn rand(&self) -> BigUint {
        rand::rng().random_biguint_below(&self.params.q)
    }

    pub fn run(&self, m: BigUint) -> (SchnorrSignature, BigUint) {
        // Compute the public key
        let pk_share = self.convert(self.private_key_share.clone());
        self.outgoing.send(pk_share.clone()).unwrap();
        let pk_share_incoming = self.incoming.recv().unwrap();
        let pk = (pk_share * pk_share_incoming) % &self.params.p;

        // Compute the signature
        // Step 1: generate k
        let box_k = self.rand();
        // Step 2: convert k
        let group_box_k = self.convert(box_k.clone());
        // Step 3: open group sharing
        self.outgoing.send(group_box_k.clone()).unwrap();
        let group_box_k_incoming = self.incoming.recv().unwrap();
        let k =  group_box_k * group_box_k_incoming % &self.params.p;
        // Step 4: Compute the hash function
        let e = self.compute_hash(k.clone(), m);
        // Step 5: Compute z
        let z_prime = self.eval_mul_by_constant(e.clone(), self.private_key_share.clone());
        let z_local = self.eval_add(box_k, z_prime);
        // Step 6: Open z
        self.outgoing.send(z_local.clone()).unwrap();
        let incoming_z = self.incoming.recv().unwrap();
        let z =  (z_local + incoming_z) % &self.params.q;
        // Ship the signature
        ((e, z), pk)
    }
}
