// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-secp256k1.
//
// Each vector below was generated with the production `eth_keys` Python
// library (the canonical reference for Ethereum-style ECDSA / ecrecover) and
// independently round-tripped through the same library to confirm that
// recover(hash, r, s, v) yields the expected uncompressed public key.
// `eth_keys` calls into the audited `coincurve` / libsecp256k1 backend and is
// the reference used by every Python Ethereum client (web3.py, py-evm).
//
// Reference:
//   - SEC1 v2, sec. 4.1.6 ("Public Key Recovery Operation")
//   - EVM Yellow Paper, Appendix E (`ECREC` precompile at 0x...01)
//   - EIP-2: signature malleability rule (s in lower half of n)

use lux_crypto_secp256k1::{
    ecrecover, ecrecover_batch, BATCH_INPUT_STRIDE, HASH_LEN, PUBKEY_LEN, SCALAR_LEN,
};

fn from_hex<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * N, "expected {}-byte hex", N);
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex byte {c:#x}"),
        }
    };
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
    }
    out
}

struct Vec1 {
    name: &'static str,
    hash: [u8; HASH_LEN],
    r: [u8; SCALAR_LEN],
    s: [u8; SCALAR_LEN],
    v: u8,
    pk: [u8; PUBKEY_LEN],
}

fn vectors() -> Vec<Vec1> {
    vec![
        Vec1 {
            // sk = 0x4646...46, message = "Hello, ecrecover!"
            name: "vec1_sk_46",
            hash: from_hex(
                "0fcadf6cdc36ba0c69ca8904608b865a73a23c533aba7dcf775c097edbcc330b",
            ),
            r: from_hex(
                "6db81c13f1099b6dc7288b18a19a9bcf309981373b19fb491fa32ee1fb923806",
            ),
            s: from_hex(
                "0e5d13c97d7d588313e2c547a93358f795d7797e4e7c6a730c9f03fbaf112c83",
            ),
            v: 0,
            pk: from_hex(
                "4bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382\
                 ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a",
            ),
        },
        Vec1 {
            // sk = 0x1010...10, message = "second test vector for lux secp256k1"
            name: "vec2_sk_10",
            hash: from_hex(
                "2c13e6c5029dd31fa4530b9c813000b3988625a7d08c2658fb3b4030574cac55",
            ),
            r: from_hex(
                "fde944994f602178d95906c207c5739820469222dc7430fd80445831d10cfa9c",
            ),
            s: from_hex(
                "3516edf2413eefe20393880a2a183b35d946ff9158fcfbaf29480ed10273a9c8",
            ),
            v: 1,
            pk: from_hex(
                "a92c9b7cac68758de5783ed8e5123598e4ad137091e42987d3bad8a08e35bf3d\
                 06cb29b6bf80c6c009f584c32bbb934ba9acd303c47c9cd6512d96ae800289cb",
            ),
        },
        Vec1 {
            // sk = 0xcafe1234..., message = "" (keccak("") used as hash)
            name: "vec3_empty_msg",
            hash: from_hex(
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ),
            r: from_hex(
                "50aef128c03cdf45d0f4a0420b86922f84b8e8a6c2e9aa86a90b32e4288fb843",
            ),
            s: from_hex(
                "5aa1d8f6905c04695aaf4bde29037d8a34c96928dc66603b5c050a5b465d3645",
            ),
            v: 0,
            pk: from_hex(
                "9670b5d17c351fcd4812aa003b785aa526e2c88e3ee59595fd7e6f579cf844fd\
                 60aee238b247f95e1c5fc96cc279c304e7786266b20e69e4fc45a0934c4f0552",
            ),
        },
    ]
}

#[test]
fn ecrecover_known_vectors() {
    for v in vectors() {
        let got = ecrecover(&v.hash, &v.r, &v.s, v.v)
            .unwrap_or_else(|e| panic!("ecrecover({}) failed: {e:?}", v.name));
        assert_eq!(
            got, v.pk,
            "ecrecover({}) produced wrong public key",
            v.name
        );
    }
}

#[test]
fn ecrecover_v_low_bit_selects_recid() {
    // The C-ABI treats `v` as a recovery id and takes only its low bit
    // (matching libsecp256k1's recid convention). v=0 and v=2 should yield
    // identical public keys; v=1 and v=3 should also match each other but
    // differ from v=0/2. Strict EIP-2 / EIP-155 v rejection happens at the
    // EVM precompile layer above this primitive, not in the C-ABI itself.
    let v = vectors().into_iter().next().unwrap();
    let pk0 = ecrecover(&v.hash, &v.r, &v.s, 0).expect("v=0");
    let pk1 = ecrecover(&v.hash, &v.r, &v.s, 1).expect("v=1");
    let pk2 = ecrecover(&v.hash, &v.r, &v.s, 2).expect("v=2");
    let pk3 = ecrecover(&v.hash, &v.r, &v.s, 3).expect("v=3");
    assert_eq!(pk0, pk2, "v=0 and v=2 must match (low-bit selects recid)");
    assert_eq!(pk1, pk3, "v=1 and v=3 must match (low-bit selects recid)");
    assert_ne!(pk0, pk1, "v=0 and v=1 must differ");
}

#[test]
fn ecrecover_batch_round_trip() {
    let vs = vectors();
    let n = vs.len();
    let mut input = vec![0u8; n * BATCH_INPUT_STRIDE];
    for (i, v) in vs.iter().enumerate() {
        let off = i * BATCH_INPUT_STRIDE;
        input[off..off + HASH_LEN].copy_from_slice(&v.hash);
        input[off + HASH_LEN..off + HASH_LEN + SCALAR_LEN].copy_from_slice(&v.r);
        input[off + HASH_LEN + SCALAR_LEN..off + HASH_LEN + 2 * SCALAR_LEN]
            .copy_from_slice(&v.s);
        input[off + HASH_LEN + 2 * SCALAR_LEN] = v.v;
    }

    let (pubkeys, statuses) = ecrecover_batch(&input).expect("batch ecrecover");
    assert_eq!(pubkeys.len(), n * PUBKEY_LEN);
    assert_eq!(statuses.len(), n);
    for (i, v) in vs.iter().enumerate() {
        assert_eq!(statuses[i], 0, "vector {i} status non-zero");
        let got = &pubkeys[i * PUBKEY_LEN..(i + 1) * PUBKEY_LEN];
        assert_eq!(got, &v.pk, "vector {} wrong pk in batch", v.name);
    }
}

#[test]
fn ecrecover_batch_rejects_misaligned_input() {
    // Exactly one byte short of a complete record -> BadInput.
    let bad = vec![0u8; BATCH_INPUT_STRIDE - 1];
    let res = ecrecover_batch(&bad);
    assert!(res.is_err());
}
