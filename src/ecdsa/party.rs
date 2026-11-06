use crate::ecdsa::protocol::Msg;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::{ToEncodedPoint, ToSec1Point};
use k256::{ProjectivePoint, Scalar};
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey};
use std::sync::mpsc;

pub struct Party {
    private_key_share: Scalar,
    h: fn(&[u8]) -> [u8; 32],
    incoming: mpsc::Receiver<Msg>,
    outgoing: mpsc::Sender<Msg>,
}

pub struct BeaverTriple {
    pub a: Scalar, // u
    pub b: Scalar, // v
    pub c: Scalar, // w
}

impl Party {
    pub fn new(
        h: fn(&[u8]) -> [u8; 32],
        incoming: mpsc::Receiver<Msg>,
        outgoing: mpsc::Sender<Msg>,
    ) -> Self {
        // Generate random key share in [0, n-1]
        let secret_bytes: [u8; 32] = rand::random();
        let private_key_share =
            Option::from(Scalar::from_repr(secret_bytes.into())).expect("Invalid secret key share");
        Self {
            private_key_share,
            h,
            incoming,
            outgoing,
        }
    }

    fn convert(&self, k: &Scalar) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * k
    }

    fn compute_hash(&self, x: &[u8]) -> Scalar {
        Option::from(Scalar::from_repr((self.h)(x).into()))
            .expect("challenge hash >= n (prob ~2^-128)")
    }

    fn open<F>(&self, my_share: Scalar, wrap: F) -> Scalar
    where
        F: Fn(Scalar) -> Msg,
    {
        self.outgoing.send(wrap(my_share)).unwrap();
        let incoming_share = match self.incoming.recv().unwrap() {
            Msg::CShare(s) | Msg::DShare(s) | Msg::EShare(s) | Msg::Z(s) => s,
            _ => panic!("unexpected message when opening scalar share"),
        };
        my_share + incoming_share
    }

    pub fn run(&self, m: &[u8], beaver_triples: Vec<BeaverTriple>, is_alice: bool) -> (Signature, PublicKey) {
        let pk_share = self.convert(&self.private_key_share);

        self.outgoing.send(Msg::PkShare(pk_share)).unwrap();
        let pk_share_recv = self.incoming.recv().unwrap();
        let pk_share_incoming = match pk_share_recv {
            Msg::PkShare(p) => p,
            _ => panic!("expected PkShare"),
        };
        let pk = pk_share + pk_share_incoming;

        // open c
        let c = self.open(beaver_triples[0].c, Msg::CShare);

        // convert b
        let b_share = beaver_triples[0].b;
        let c_inv = Option::<Scalar>::from(c.invert()).expect("c has no inverse");
        let k_group_box = self.convert(&b_share) * c_inv;

        // [k^(-1) = a
        let k_inv = beaver_triples[0].a;
        // compute sk' <-- Mul([a], [sk])
        let (u, v, w) = (beaver_triples[1].a, beaver_triples[1].b, beaver_triples[1].c);
        let d_share = k_inv + u;
        let e_share = self.private_key_share + v;

        // open d and e
        let d = self.open(d_share, Msg::DShare);
        let e = self.open(e_share, Msg::EShare);


        let mut sk_prime = w + e * k_inv + d * self.private_key_share ;
        if is_alice {
            sk_prime -= d * e;
        }

        self.outgoing.send(Msg::RShare(k_group_box)).unwrap();
        let k_group_box_recv = self.incoming.recv().unwrap();
        let k_group_box_incoming = match k_group_box_recv {
            Msg::RShare(r) => r,
            _ => panic!("expected PkShare"),
        };
        #[allow(non_snake_case)]
        let R = k_group_box + k_group_box_incoming;
        let r_affine = R.to_affine();
        let r_encoded = r_affine.to_sec1_point(false);
        let rx_bytes = *r_encoded.x().unwrap();
        let rx = Option::<Scalar>::from(Scalar::from_repr(rx_bytes)).expect("rx < n");
        let s_share = self.compute_hash(m) * k_inv + rx * sk_prime;
        let s = self.open(s_share, Msg::Z);

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&rx.to_bytes());
        sig_bytes[32..].copy_from_slice(&s.to_bytes());

        let mut sig = Signature::from_compact(&sig_bytes).expect("invalid signature format");

        sig.normalize_s();

        let pk_encoded = pk.to_affine().to_encoded_point(true); // compressed SEC1 (33 bytes)
        let pk_secp = secp256k1::PublicKey::from_slice(pk_encoded.as_bytes()).expect("invalid public key");

        let msg = Message::from_digest(self.compute_hash(m).to_bytes().into());
        sig.verify(msg, &pk_secp).expect("signature verification failed");

        (sig, pk_secp)
    }
}


