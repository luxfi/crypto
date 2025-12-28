// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Banderwagon spec-vector integration test.
//
// Vectors are taken from luxfi/crypto/ipa/banderwagon/element_test.go
// (originally from crate-crypto/go-ipa, Apache-2.0). Each entry is the
// canonical 32-byte compressed encoding of `2^i * G` for i in 0..15.
// Reference output is byte-equal across go-ipa, gnark-crypto, and
// ethereum/banderwagon-py per the published spec.

use lux_crypto_banderwagon::{
    add, decode, double, encode, equal, generator, identity, msm, msm_compressed,
    neg, scalar_mul, COMPRESSED_LEN, SCALAR_LEN, UNCOMPRESSED_LEN,
};

fn from_hex<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * N);
    let mut out = [0u8; N];
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    for i in 0..N {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

// 16 published vectors: encode(2^i * G) for i in 0..15.
const ENCODED_DOUBLINGS: [&str; 16] = [
    "4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9", // G
    "43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5", // 2G
    "5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126", // 4G
    "0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c", // 8G
    "14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a", // 16G
    "6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d",
    "26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf",
    "37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35",
    "2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d",
    "297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07",
    "5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce",
    "1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626",
    "3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8",
    "35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed",
    "00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0",
    "3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f",
];

#[test]
fn encode_g_matches_published_vector() {
    let g_uncompressed = generator();
    let got = encode(&g_uncompressed).expect("encode generator");
    let want: [u8; COMPRESSED_LEN] = from_hex(ENCODED_DOUBLINGS[0]);
    assert_eq!(got, want);
}

#[test]
fn encode_doublings_2_through_2_pow_15() {
    // Decode generator, double 15 times, check each encoding matches the
    // published canonical Banderwagon vectors.
    let mut pt = generator();
    for (i, want_hex) in ENCODED_DOUBLINGS.iter().enumerate() {
        let want: [u8; COMPRESSED_LEN] = from_hex(want_hex);
        let got = encode(&pt).expect("encode doubling");
        assert_eq!(
            got, want,
            "doubling {i}: encode mismatch (want {want_hex})"
        );
        pt = double(&pt).expect("double");
    }
}

#[test]
fn decode_then_encode_round_trip_all_vectors() {
    for (i, hex) in ENCODED_DOUBLINGS.iter().enumerate() {
        let want: [u8; COMPRESSED_LEN] = from_hex(hex);
        let pt = decode(&want).expect("decode published vector");
        let got = encode(&pt).expect("encode after decode");
        assert_eq!(got, want, "vector {i}: round-trip not byte-equal");
    }
}

#[test]
fn add_g_g_equals_double_g() {
    let g = generator();
    let sum = add(&g, &g).expect("G+G");
    let dbl = double(&g).expect("2G");
    assert!(equal(&sum, &dbl).expect("equal"));
}

#[test]
fn g_plus_neg_g_is_identity() {
    let g = generator();
    let ng = neg(&g).expect("-G");
    let zero = add(&g, &ng).expect("G + (-G)");
    let id = identity();
    assert!(equal(&zero, &id).expect("equal"));
}

#[test]
fn scalar_mul_two_equals_double() {
    // scalar = 2 (big-endian)
    let mut two = [0u8; SCALAR_LEN];
    two[31] = 2;
    let g = generator();
    let smul = scalar_mul(&two, &g).expect("2*G");
    let dbl = double(&g).expect("2G");
    assert!(equal(&smul, &dbl).expect("equal"));
}

#[test]
fn scalar_mul_one_equals_identity_op() {
    let mut one = [0u8; SCALAR_LEN];
    one[31] = 1;
    let g = generator();
    let s = scalar_mul(&one, &g).expect("1*G");
    assert!(equal(&s, &g).expect("equal"));
}

#[test]
fn scalar_mul_zero_is_identity() {
    let zero = [0u8; SCALAR_LEN];
    let g = generator();
    let s = scalar_mul(&zero, &g).expect("0*G");
    assert!(equal(&s, &identity()).expect("equal"));
}

#[test]
fn msm_two_points_equal_to_addition() {
    // MSM(G, 1; G, 1) = G + G = 2G
    let g = generator();
    let mut points = Vec::with_capacity(2 * UNCOMPRESSED_LEN);
    points.extend_from_slice(&g);
    points.extend_from_slice(&g);
    let mut scalars = Vec::with_capacity(2 * SCALAR_LEN);
    let mut one = [0u8; SCALAR_LEN];
    one[31] = 1;
    scalars.extend_from_slice(&one);
    scalars.extend_from_slice(&one);
    let got = msm(&points, &scalars).expect("MSM");
    let want = double(&g).expect("2G");
    assert!(equal(&got, &want).expect("equal"));
}

#[test]
fn msm_compressed_matches_uncompressed_msm() {
    let g = generator();
    let g_c = encode(&g).expect("encode G");
    let mut points_u = Vec::new();
    let mut points_c = Vec::new();
    let mut scalars = Vec::new();
    for i in 1u8..=4u8 {
        points_u.extend_from_slice(&g);
        points_c.extend_from_slice(&g_c);
        let mut s = [0u8; SCALAR_LEN];
        s[31] = i;
        scalars.extend_from_slice(&s);
    }
    let want_u = msm(&points_u, &scalars).expect("MSM uncompressed");
    let want_c_raw = encode(&want_u).expect("encode result");
    let got_c = msm_compressed(&points_c, &scalars).expect("MSM compressed");
    assert_eq!(got_c, want_c_raw);
}

#[test]
fn msm_empty_input_is_identity() {
    let got = msm(&[], &[]).expect("MSM zero-length");
    assert!(equal(&got, &identity()).expect("equal"));
}

#[test]
fn msm_compressed_empty_input_is_identity() {
    let got = msm_compressed(&[], &[]).expect("MSM compressed zero-length");
    let id_compressed = encode(&identity()).expect("encode identity");
    assert_eq!(got, id_compressed);
}

#[test]
fn equal_independent_of_uncompressed_representation() {
    // Two encoders of G should produce equal points.
    let g = generator();
    let g2 = decode(&encode(&g).unwrap()).unwrap();
    assert!(equal(&g, &g2).expect("equal"));
}

#[test]
fn lengths_match_constants() {
    assert_eq!(COMPRESSED_LEN, 32);
    assert_eq!(UNCOMPRESSED_LEN, 64);
    assert_eq!(SCALAR_LEN, 32);
}
