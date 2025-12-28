// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-blake2b (RFC 7693).
//
// Reference values cross-checked against:
//   - RFC 7693 Appendix A "Test Vectors"
//   - Python `hashlib.blake2b(data).hexdigest()` (used by every CPython release)
//   - libsodium `crypto_generichash` (canonical reference C implementation)

use lux_crypto_blake2b::{hash, hash_into, DIGEST_LEN};

fn from_hex(s: &str) -> [u8; DIGEST_LEN] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * DIGEST_LEN);
    let mut out = [0u8; DIGEST_LEN];
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    for i in 0..DIGEST_LEN {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

#[test]
fn empty_string() {
    let want = from_hex(
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
         d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    );
    assert_eq!(hash(b""), want);
}

#[test]
fn rfc7693_abc() {
    // RFC 7693 Appendix A
    let want = from_hex(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    );
    assert_eq!(hash(b"abc"), want);
}

#[test]
fn single_a() {
    let want = from_hex(
        "333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34\
         d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c",
    );
    assert_eq!(hash(b"a"), want);
}

#[test]
fn quick_brown_fox() {
    let want = from_hex(
        "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673\
         f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
    );
    assert_eq!(hash(b"The quick brown fox jumps over the lazy dog"), want);
}

#[test]
fn quick_brown_fox_period() {
    let want = from_hex(
        "87af9dc4afe5651b7aa89124b905fd214bf17c79af58610db86a0fb1e0194622\
         a4e9d8e395b352223a8183b0d421c0994b98286cbf8c68a495902e0fe6e2bda2",
    );
    assert_eq!(hash(b"The quick brown fox jumps over the lazy dog."), want);
}

#[test]
fn single_zero_byte() {
    let want = from_hex(
        "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c\
         36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b",
    );
    assert_eq!(hash(&[0u8]), want);
}

#[test]
fn thirty_two_zero_bytes() {
    let want = from_hex(
        "9ab7a73a97a1a3031406b6c169634a9c06cfb81dec3323bb4de5ce6f4b7ca107\
         de534442a7eaeafbaf366ccfdde1cb97d7c884e4344cd0a23039de71a56d630a",
    );
    assert_eq!(hash(&[0u8; 32]), want);
}

#[test]
fn one_hundred_twenty_seven_zero_bytes_below_block() {
    // BLAKE2b uses 128-byte blocks; 127 stays inside one block.
    let want = from_hex(
        "93cac6a4bedd751e1c145f8e76fec88fec246675898475585603bd228f883bcf\
         4ebcc68ead8fa5f27890a243fa938bd7323ad41f9f06048a732cce2070b212c3",
    );
    assert_eq!(hash(&[0u8; 127]), want);
}

#[test]
fn one_hundred_twenty_eight_zero_bytes_block_boundary() {
    let want = from_hex(
        "865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf7\
         98e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41",
    );
    assert_eq!(hash(&[0u8; 128]), want);
}

#[test]
fn one_hundred_twenty_nine_zero_bytes_two_blocks() {
    let want = from_hex(
        "a60edba343e7a6933c14d203d2e535f35e6deb6c8a4f8e624c1a6f6e26128604\
         47cb4c37e5aa11bcf03b7c3eea7228eb8b998f922794f2d1b8f2dc63f03bd3fa",
    );
    assert_eq!(hash(&[0u8; 129]), want);
}

#[test]
fn one_million_a() {
    let want = from_hex(
        "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1\
         d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf",
    );
    let buf = vec![b'a'; 1_000_000];
    assert_eq!(hash(&buf), want);
}

#[test]
fn deterministic_across_calls() {
    let a = hash(b"deterministic input");
    let b = hash(b"deterministic input");
    assert_eq!(a, b);
}

#[test]
fn hash_into_matches_hash() {
    let mut buf = [0u8; DIGEST_LEN];
    let r = hash_into(b"into-buffer", &mut buf);
    assert_eq!(*r, hash(b"into-buffer"));
}
