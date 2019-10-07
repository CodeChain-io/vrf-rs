//! # Basic example
//!
//! This example shows a basic usage of the `vrf-rs` crate:
//!
//! 1. Instantiate the `ECVRF` by specifying the `CipherSuite`
//! 2. Generate a VRF proof by using the `prove()` function
//! 3. (Optional) Convert the VRF proof to a hash (e.g. to be used as pseudo-random value)
//! 4. Verify the VRF proof by using `verify()` function

use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

use std::fs::File;
use std::io::prelude::*;

fn main() {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_SVDW).unwrap();
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let message: &[u8] = b"sample";

    let pi = vrf.prove(&secret_key, &message).unwrap();
    let mut seed = vrf.proof_to_hash(&pi).unwrap();
    let mut output = File::create("foo.txt").unwrap();

    for _ in 0..1_000_000 {
        let pi = vrf.prove(&secret_key, &seed.to_vec()).unwrap();
        seed = vrf.proof_to_hash(&pi).unwrap();
        output.write(&seed).unwrap();
    }
}
