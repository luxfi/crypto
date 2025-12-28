// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// RFC 8032 §7.1 Known-Answer Tests for Ed25519 (PureEdDSA over Curve25519).
//
// Vectors 1, 2, 3, 1024, SHA(abc) come straight from the RFC.
// Vectors 4, 5, 6 come from the Bernstein/Lange `sign.input` corpus that
// ed25519-donna's regression suite uses.
//
// Each vector is checked four ways:
//   1. keygen(seed)          -> pk byte-equals the published public key
//   2. sign(sk, msg)         -> sig byte-equals the published signature
//   3. verify(pk, msg, sig)  -> accepts the published signature
//   4. verify with mutated sig and mutated pk -> InvalidSignature

use lux_crypto_ed25519::{
    keygen, sign, verify, Error, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN,
};

fn from_hex_var(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex must be even length");
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex byte: {:#x}", c),
        }
    };
    let b = s.as_bytes();
    let mut out = vec![0u8; b.len() / 2];
    for i in 0..out.len() {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
    }
    out
}

fn from_hex_n<const N: usize>(s: &str) -> [u8; N] {
    let v = from_hex_var(s);
    assert_eq!(v.len(), N, "expected {} bytes, got {}", N, v.len());
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    a
}

struct Vector {
    name: &'static str,
    seed: &'static str,
    pk: &'static str,
    sig: &'static str,
    msg: &'static str,
}

// RFC 8032 §7.1 — TEST 1, TEST 2, TEST 3, TEST 1024, TEST SHA(abc).
// Bernstein/Lange sign.input #4, #5, #6.
const VECTORS: &[Vector] = &[
    Vector {
        name: "RFC8032 TEST 1 (empty)",
        seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        sig: concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        msg: "",
    },
    Vector {
        name: "RFC8032 TEST 2 (1-byte 0x72)",
        seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        sig: concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        msg: "72",
    },
    Vector {
        name: "RFC8032 TEST 3 (2-byte af82)",
        seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        pk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        sig: concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        msg: "af82",
    },
    Vector {
        name: "donna sign.input #4 (3-byte cbc77b)",
        seed: "0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9",
        pk: "e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057",
        sig: concat!(
            "d9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8",
            "e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00c",
        ),
        msg: "cbc77b",
    },
    Vector {
        name: "donna sign.input #5 (4-byte 5f4c8989)",
        seed: "6df9340c138cc188b5fe4464ebaa3f7fc206a2d55c3434707e74c9fc04e20ebb",
        pk: "c0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7",
        sig: concat!(
            "124f6fc6b0d100842769e71bd530664d888df8507df6c56dedfdb509aeb93416",
            "e26b918d38aa06305df3095697c18b2aa832eaa52edc0ae49fbae5a85e150c07",
        ),
        msg: "5f4c8989",
    },
    Vector {
        name: "donna sign.input #6 (5-byte 18b6bec097)",
        seed: "b780381a65edf8b78f6945e8dbec7941ac049fd4c61040cf0c324357975a293c",
        pk: "e253af0766804b869bb1595be9765b534886bbaab8305bf50dbc7f899bfb5f01",
        sig: concat!(
            "b2fc46ad47af464478c199e1f8be169f1be6327c7f9a0a6689371ca94caf0406",
            "4a01b22aff1520abd58951341603faed768cf78ce97ae7b038abfe456aa17c09",
        ),
        msg: "18b6bec097",
    },
    Vector {
        name: "RFC8032 TEST 1024 (1023-byte msg)",
        seed: "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        pk: "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        sig: concat!(
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350",
            "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        ),
        msg: concat!(
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98",
            "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8",
            "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d",
            "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc",
            "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
            "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e",
            "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef",
            "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7",
            "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1",
            "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
            "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24",
            "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270",
            "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc",
            "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07",
            "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
            "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a",
            "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e",
            "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7",
            "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c",
            "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
            "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df",
            "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08",
            "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649",
            "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4",
            "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
            "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e",
            "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f",
            "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5",
            "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1",
            "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
            "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c",
            "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        ),
    },
    Vector {
        name: "RFC8032 TEST SHA(abc) (64-byte SHA-512(abc) msg)",
        seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        pk: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        sig: concat!(
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589",
            "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
        msg: concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    },
];

#[test]
fn rfc8032_section_7_1_vectors_byte_equal() {
    let mut passed = 0;
    for v in VECTORS {
        let seed = from_hex_n::<SEED_LEN>(v.seed);
        let want_pk = from_hex_n::<PUBLIC_KEY_LEN>(v.pk);
        let want_sig = from_hex_n::<SIGNATURE_LEN>(v.sig);
        let msg = from_hex_var(v.msg);

        // 1. keygen reproduces the published public key.
        let (sk, pk) = keygen(&seed);
        assert_eq!(pk, want_pk, "{}: keygen pk mismatch", v.name);
        // sk in the C ABI is the canonical 32-byte seed.
        assert_eq!(
            sk, seed,
            "{}: secret_key should byte-equal seed (RFC 8032 §5.1.5)",
            v.name
        );

        // 2. sign reproduces the published signature byte-for-byte.
        let sig = sign(&sk, &msg);
        assert_eq!(sig, want_sig, "{}: sign sig mismatch", v.name);

        // 3. verify accepts the published signature.
        verify(&want_pk, &msg, &want_sig)
            .unwrap_or_else(|e| panic!("{}: verify(published) failed: {:?}", v.name, e));

        // 4a. verify rejects a bit-flipped signature.
        let mut bad_sig = want_sig;
        bad_sig[0] ^= 0x01;
        assert_eq!(
            verify(&want_pk, &msg, &bad_sig),
            Err(Error::InvalidSignature),
            "{}: verify(corrupted-sig) should fail",
            v.name
        );

        // 4b. verify rejects when the public key is wrong.
        let mut bad_pk = want_pk;
        bad_pk[0] ^= 0x01;
        assert_eq!(
            verify(&bad_pk, &msg, &want_sig),
            Err(Error::InvalidSignature),
            "{}: verify(wrong-pk) should fail",
            v.name
        );

        passed += 1;
    }
    assert_eq!(passed, VECTORS.len(), "all vectors must pass");
    assert!(passed >= 8, "RFC 8032 §7.1 requires at least 8 vectors");
}

#[test]
fn deterministic_signing() {
    // RFC 8032 §5.1.6: signatures are deterministic. The same (sk, msg) input
    // must produce byte-equal signatures across calls.
    let seed = [0x42u8; SEED_LEN];
    let (sk, _pk) = keygen(&seed);
    let msg = b"deterministic ed25519 (RFC 8032 5.1.6)";
    let sig1 = sign(&sk, msg);
    let sig2 = sign(&sk, msg);
    assert_eq!(sig1, sig2, "signing must be deterministic");
}

#[test]
fn random_roundtrip() {
    // Deterministic xorshift64* PRNG so a failure reproduces on any host.
    let mut state: u64 = 0xC0DE_BEEF_CAFE_F00D;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    for i in 0..16 {
        let mut seed = [0u8; SEED_LEN];
        for chunk in seed.chunks_mut(8) {
            chunk.copy_from_slice(&next().to_le_bytes());
        }
        let msg_len = (next() as usize) % 257; // 0..=256
        let mut msg = vec![0u8; msg_len];
        for chunk in msg.chunks_mut(8) {
            let n = next();
            for (j, b) in chunk.iter_mut().enumerate() {
                *b = (n >> (8 * j)) as u8;
            }
        }

        let (sk, pk) = keygen(&seed);
        let sig = sign(&sk, &msg);
        verify(&pk, &msg, &sig)
            .unwrap_or_else(|e| panic!("random#{i}: verify(self-signed) failed: {e:?}"));

        // Mutating the signature must cause verify to fail.
        for byte_idx in [0usize, 31, 32, 63] {
            let mut bad = sig;
            bad[byte_idx] ^= 0x80;
            assert_eq!(
                verify(&pk, &msg, &bad),
                Err(Error::InvalidSignature),
                "random#{i}: verify must reject mutated sig (byte {byte_idx})"
            );
        }
    }
}
