use std::sync::mpsc;
use secp256k1::{Parity, PublicKey, Scalar, SecretKey, XOnlyPublicKey};
use secp256k1::schnorr::Signature;
use super::protocol::{Msg, ProtocolParams};

pub struct Party {
    params: ProtocolParams,
    private_key_share: SecretKey,
    incoming: mpsc::Receiver<Msg>,
    outgoing: mpsc::Sender<Msg>,
}

impl Party {
    pub fn new(
        params: ProtocolParams,
        incoming: mpsc::Receiver<Msg>,
        outgoing: mpsc::Sender<Msg>,
    ) -> Self {
        // Generate random key share in [0, n-1]
        let secret_bytes: [u8; 32] = rand::random();
        let private_key_share = SecretKey::from_secret_bytes(secret_bytes).expect("Invalid secret key share");
        Self { params, private_key_share, incoming, outgoing }
    }

    fn convert(&self, k: &SecretKey) -> PublicKey {
        PublicKey::from_secret_key(k)
    }

    fn compute_hash(&self, x: &[u8]) -> Scalar {
        Scalar::from_be_bytes((self.params.h)(x)).expect("challenge hash >= n (prob ~2^-128)")
    }

    fn rand(&self) -> SecretKey {
        let secret_bytes: [u8; 32] = rand::random();
         SecretKey::from_secret_bytes(secret_bytes).expect("Invalid secret key share")
    }

    pub fn run(&self, m: &[u8]) -> (Signature, XOnlyPublicKey) {
        // TODO: Start by checking that sk is not zero

        // Compute the public key
        let pk_share = PublicKey::from_secret_key(&self.private_key_share);

        self.outgoing.send(Msg::PkShare(pk_share)).unwrap();
        let pk_share_recv = self.incoming.recv().unwrap();
        let pk_share_incoming = match pk_share_recv {
            Msg::PkShare(p) => p,
            _ => panic!("expected PkShare"),
        };
        let pk = pk_share.combine(&pk_share_incoming).expect("invalid public key");

        // Compute the signature
        // Step 1: Create sharing of [d]
        let (_, parity) = pk.x_only_public_key();
        let d = match parity {
            Parity::Even => self.private_key_share,
            Parity::Odd => self.private_key_share.negate(),
        };

        // Step 1: generate k
        let box_k_prime = self.rand();
        // Step 2: convert k
        let group_box_k_prime = self.convert(&box_k_prime);
        // TODO: Step 3: perform zero check
        self.outgoing.send(Msg::NonceShare(group_box_k_prime.clone())).unwrap();
        let nonce_share_recv = self.incoming.recv().unwrap();
        let group_box_k_incoming = match nonce_share_recv {
            Msg::NonceShare(p) => p,
            _ => panic!("expected NonceShare"),
        };

        let r_point = group_box_k_prime.combine(&group_box_k_incoming).expect("invalid nonce");

        // Step 3: open group sharing

        // Step 4: Compute the nonce sharing representing the correct point:
        let (_, parity) = r_point.x_only_public_key();
        let k = match parity {
            Parity::Even => box_k_prime,
            Parity::Odd => box_k_prime.negate(),
        };

        // Step 5: Compute the hash function
        let e = self.compute_hash(&[&bytes(&r_point), &bytes(&pk), m].concat());
        // Step 5: Compute z
        let z_prime = d.mul_tweak(&e).expect("d·e is zero");
        let z_local = z_prime.add_tweak(&Scalar::from(k)).expect("k + d·e is zero");

        // Step 6: Open z
        self.outgoing.send(Msg::Z(z_local.clone())).unwrap();
        let msg_share_recv = self.incoming.recv().unwrap();
        let incoming_z = match msg_share_recv {
            Msg::Z(p) => p,
            _ => panic!("expected NonceShare"),
        };


        let z = z_local.add_tweak(&Scalar::from(incoming_z)).expect("z_0 + z_1 is zero");
        let sig_bytes: [u8; 64] = [bytes(&r_point), z.to_secret_bytes()].concat().try_into().unwrap();
        let sig = Signature::from_byte_array(sig_bytes);
        let pk_x = pk.x_only_public_key().0;
        sig.verify(m, &pk_x).expect("threshold signature does not verify");
        // Ship the signature
        (sig, pk_x)
    }
}

/// BIP340 bytes(P): the 32-byte big-endian encoding of x(P).
fn bytes(p: &PublicKey) -> [u8; 32] {
    p.x_only_public_key().0.to_byte_array()
}


