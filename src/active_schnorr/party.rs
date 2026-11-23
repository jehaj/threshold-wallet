use std::{sync::mpsc};
use num_bigint::{BigRng010, BigUint};
use crate::active_schnorr::trusted_dealer::{Key, Share};
use super::protocol::{ProtocolParams, ActiveSchnorrSignature};

pub struct Party {
    params: ProtocolParams,
    incoming: mpsc::Receiver<Share>,
    outgoing: mpsc::Sender<Share>,
}

#[allow(unused)]
impl Party {
    pub fn new(
        params: ProtocolParams,
        incoming: mpsc::Receiver<Share>,
        outgoing: mpsc::Sender<Share>,
    ) -> Self {
        // Generate random key share in [0, q-1]
        Self { params, incoming, outgoing }
    }

    fn convert(&self, a: &Share) -> Share {
        let Share { key, tag, share } = a;
        let (g, p) = (&self.params.g, &self.params.p);
        Share::new(
            Key { alpha: key.alpha.clone(), beta: g.modpow(&key.beta, p) },
            g.modpow(tag, p),
            g.modpow(share, p),
        )
    }

    fn compute_hash(&self, a: BigUint, b: BigUint) -> BigUint {
        (self.params.h)(a, b) % &self.params.q
    }

    fn eval_add(&self, a: &Share, b: &Share) -> Share {

        let Share { key:key_a , tag: tag_a, share: share_a } = a.clone();
        let Share { key:key_b , tag: tag_b, share: share_b } = b.clone();

        let new_key = Key{
            alpha : key_a.alpha.clone(), 
            beta: key_a.beta + key_b.beta
        };

        Share{
            key: new_key,
            tag: (tag_a + tag_b) % &self.params.q,
            share: (share_a + share_b) % &self.params.q
        }
    }

    fn eval_mul_by_constant(&self, a: &BigUint, b: Share) -> Share {
        let Share { key, tag, share } =b.clone();

        let new_key = Key{
            alpha :key.alpha.clone(), 
            beta: key.beta * a % &self.params.q
        };

        Share{
            key: new_key,
            tag: a * b.tag % &self.params.q,
            share:(a * b.share.clone()) % &self.params.q
        }
    }

    fn rand(&self) -> BigUint {
        rand::rng().random_biguint_below(&self.params.q)
    }

    fn send_and_receive(&self, to_send: &Share) -> Share {
        self.outgoing.send(to_send.clone()).unwrap();
        self.incoming.recv().unwrap()
    }
    
    fn open_group(&self, share: &Share) -> BigUint {
        let Share{key: inc_key, tag: inc_tag, share: inc_share} = self.send_and_receive(share);

        let Share { key, tag, share } = share.clone();

        // verify 
        let tmp = ( inc_share.modpow(&self.params.alpha,&self.params.p)).clone();
        let res = &tmp * key.beta % &self.params.p;

        assert_eq!(res,inc_tag.clone(), "Tag verification failed in open_group: expected {}, got {}",inc_tag,res);

        (share * inc_share) % &self.params.p
    }

    fn open_scalar(&self, share: &Share) -> BigUint {
        let Share{key: inc_key, tag: inc_tag, share: inc_share} = self.send_and_receive(share);

        let Share { key, tag, share } = share.clone();

        // verify 
        let res = (&self.params.alpha * &inc_share + key.beta )% &self.params.q;
        assert_eq!(res,inc_tag, "Tag verification failed in open_scalar: expected {inc_tag}, got {res}");

        (share + inc_share) % &self.params.q
    }

    pub fn run(&self, m: BigUint, k_share: Share, x_share: Share) -> (ActiveSchnorrSignature, BigUint) {
        let sk_local = x_share;
        
        // Compute the public key
        let pk = self.open_group(&self.convert(&sk_local));

        // Compute the signature
        // Step 1: generate k
        let box_k = k_share;
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
        // TODO: verify the signature on the message, to not complete with malformed shares?
        // Ship the signature
        ((e, z), pk)
    }
}
