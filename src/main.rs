mod schnorr;

use num_bigint::BigUint;

fn main() {
    let (sig, pk) = schnorr::protocol::sign(BigUint::from(42u32));
    println!("signature: {:?}", sig);
}
