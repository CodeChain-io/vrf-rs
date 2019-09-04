// This is a test code to run benchmarks
// based on basic example in examples/basic.rs
// 1. Run prove() on b"sample"
// 2. Run prove() on random bytes, length from 10 to 16384
// 3. Run verify() on proof of b"sample"

#![feature(test)]

extern crate test;
use test::Bencher;
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

#[bench]
fn bench_prove(b: &mut Bencher) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let message: &[u8] = b"sample";
    b.iter(|| {
        vrf.prove(&secret_key, &message).unwrap();
    });
}

#[bench]
fn bench_prove_rand_message(b: &mut Bencher) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let message_len = rand::random::<usize>() % 16375 + 10;
    let message: Vec<u8> = (0..message_len).map(|_| rand::random::<u8>()).collect();
    b.iter(|| {
        vrf.prove(&secret_key, &message).unwrap();
    });
}

#[bench]
fn bench_verify(b: &mut Bencher) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    let message: &[u8] = b"sample";
    let pi = vrf.prove(&secret_key, &message).unwrap();
    b.iter(|| {
        vrf.verify(&public_key, &pi, &message).unwrap();
    });
}
