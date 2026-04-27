// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Spec-vector integration test for lux-crypto-blake3.
//
// Walks the upstream `test_vectors.json` (BLAKE3-team/BLAKE3 v1.5.0,
// vendored under luxcpp/crypto/blake3/test/vectors/test_vectors.json) and
// asserts byte-equality across all 35 cases x 4 modes = 140 assertions:
//
//   hash         -- first 32 bytes of "hash" XOF stream
//   keyed_hash   -- first 32 bytes of "keyed_hash" XOF stream
//   derive_key   -- first 32 bytes of "derive_key" XOF stream
//   hash_xof     -- full extended length of "hash" stream
//
// The synthetic input per upstream README is a 251-byte ramp (0..250)
// repeated to reach `input_len`.

use lux_crypto_blake3::{derive_key, hash, hash_xof, keyed_hash, KEY_LEN, OUT_LEN};

const VECTORS: &str =
    include_str!("../../../../../luxcpp/crypto/blake3/test/vectors/test_vectors.json");

fn from_hex_var(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex must be even length");
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex"),
        }
    };
    let b = s.as_bytes();
    let mut out = vec![0u8; b.len() / 2];
    for i in 0..out.len() {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
    }
    out
}

fn from_hex32(s: &str) -> [u8; OUT_LEN] {
    let v = from_hex_var(s);
    let mut a = [0u8; OUT_LEN];
    a.copy_from_slice(&v[..OUT_LEN]);
    a
}

fn make_input(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

// Tiny purpose-built JSON reader: walks `"<name>": <value>` pairs in the
// known schema. NOT a general parser.
struct Reader<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn find_field(&mut self, name: &str) -> Option<usize> {
        let needle = format!("\"{}\"", name);
        let nb = needle.as_bytes();
        let hay = &self.s[self.pos..];
        let mut i = 0;
        while i + nb.len() <= hay.len() {
            if &hay[i..i + nb.len()] == nb {
                let p = self.pos + i + nb.len();
                let mut q = p;
                while q < self.s.len() && (self.s[q] == b' ' || self.s[q] == b':') {
                    q += 1;
                }
                return Some(q);
            }
            i += 1;
        }
        None
    }
    fn read_string_at(&mut self, p: usize) -> Option<String> {
        if self.s.get(p) != Some(&b'"') {
            return None;
        }
        let start = p + 1;
        let mut q = start;
        while q < self.s.len() && self.s[q] != b'"' {
            q += 1;
        }
        if q >= self.s.len() {
            return None;
        }
        self.pos = q + 1;
        Some(String::from_utf8(self.s[start..q].to_vec()).ok()?)
    }
    fn read_uint_at(&mut self, mut p: usize) -> Option<u64> {
        while p < self.s.len() && (self.s[p] == b' ' || self.s[p] == b':') {
            p += 1;
        }
        let mut v: u64 = 0;
        let mut any = false;
        while p < self.s.len() && self.s[p].is_ascii_digit() {
            v = v * 10 + (self.s[p] - b'0') as u64;
            p += 1;
            any = true;
        }
        self.pos = p;
        if any {
            Some(v)
        } else {
            None
        }
    }
}

#[test]
fn upstream_test_vectors_byte_equal() {
    let mut r = Reader {
        s: VECTORS.as_bytes(),
        pos: 0,
    };

    let p_key = r.find_field("key").expect("key field missing");
    let key_str = r.read_string_at(p_key).expect("key string malformed");
    let p_ctx = r
        .find_field("context_string")
        .expect("context_string missing");
    let ctx_str = r
        .read_string_at(p_ctx)
        .expect("context_string malformed");

    assert_eq!(
        key_str.len(),
        KEY_LEN,
        "key has unexpected length {}",
        key_str.len()
    );
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(key_str.as_bytes());

    // NUL-terminate context for the C ABI.
    let mut ctx_z = ctx_str.into_bytes();
    ctx_z.push(0);

    let mut n_cases = 0;
    let mut passed = 0;
    let mut total = 0;

    loop {
        let p_in = match r.find_field("input_len") {
            Some(p) => p,
            None => break,
        };
        let in_len = r.read_uint_at(p_in).expect("malformed input_len") as usize;
        let p_h = r.find_field("hash").expect("missing hash");
        let hash_hex = r.read_string_at(p_h).expect("hash malformed");
        let p_k = r.find_field("keyed_hash").expect("missing keyed_hash");
        let keyed_hex = r.read_string_at(p_k).expect("keyed_hash malformed");
        let p_d = r.find_field("derive_key").expect("missing derive_key");
        let dk_hex = r.read_string_at(p_d).expect("derive_key malformed");

        n_cases += 1;
        let input = make_input(in_len);

        // Mode 1: default-length hash (first 32 bytes of "hash").
        total += 1;
        let want = from_hex32(&hash_hex);
        let got = hash(&input);
        assert_eq!(got, want, "hash32 mismatch at in_len={}", in_len);
        passed += 1;

        // Mode 2: keyed_hash, default-length (first 32 bytes).
        total += 1;
        let want = from_hex32(&keyed_hex);
        let got = keyed_hash(&key, &input);
        assert_eq!(got, want, "keyed_hash mismatch at in_len={}", in_len);
        passed += 1;

        // Mode 3: derive_key, default-length (first 32 bytes).
        total += 1;
        let want = from_hex32(&dk_hex);
        let got = derive_key(&ctx_z, &input);
        assert_eq!(got, want, "derive_key mismatch at in_len={}", in_len);
        passed += 1;

        // Mode 4: XOF, full extended length per upstream `hash` field.
        total += 1;
        let want = from_hex_var(&hash_hex);
        let mut got = vec![0u8; want.len()];
        hash_xof(&input, &mut got);
        assert_eq!(got, want, "hash_xof mismatch at in_len={}", in_len);
        passed += 1;
    }

    assert_eq!(n_cases, 35, "expected 35 cases, found {}", n_cases);
    assert_eq!(total, 140);
    assert_eq!(passed, 140);
    println!("blake3 spec vectors: {}/{} PASS", passed, total);
}
