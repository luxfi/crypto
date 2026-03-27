//! FFI bindings to libluxcrypto — ML-KEM-768 and ML-DSA-65.
//!
//! One library, one implementation: libluxcrypto (cloudflare/circl via Go).
//! Same PQ crypto from Lux blockchain to AI agents.
//!
//! # Example
//!
//! ```rust,ignore
//! use luxcrypto_sys::{mlkem768, mldsa65};
//!
//! // ML-KEM-768 key exchange
//! let (pk, sk) = mlkem768::keypair().unwrap();
//! let (ct, ss_enc) = mlkem768::encapsulate(&pk).unwrap();
//! let ss_dec = mlkem768::decapsulate(&sk, &ct).unwrap();
//! assert_eq!(ss_enc, ss_dec);
//!
//! // ML-DSA-65 signatures
//! let (pk, sk) = mldsa65::keypair().unwrap();
//! let sig = mldsa65::sign(&sk, b"hello").unwrap();
//! assert!(mldsa65::verify(&pk, b"hello", &sig));
//! ```

use std::os::raw::{c_char, c_int};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("libluxcrypto operation failed: {0} (rc={1})")]
    FFIError(&'static str, i32),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

// ── Raw FFI ──────────────────────────────────────────────────────────

extern "C" {
    fn lux_mlkem768_keypair(pk: *mut c_char, pk_len: *mut c_int, sk: *mut c_char, sk_len: *mut c_int) -> c_int;
    fn lux_mlkem768_encapsulate(pk: *const c_char, pk_len: c_int, ct: *mut c_char, ct_len: *mut c_int, ss: *mut c_char, ss_len: *mut c_int) -> c_int;
    fn lux_mlkem768_decapsulate(sk: *const c_char, sk_len: c_int, ct: *const c_char, ct_len: c_int, ss: *mut c_char, ss_len: *mut c_int) -> c_int;
    fn lux_mlkem768_pk_size() -> c_int;
    fn lux_mlkem768_sk_size() -> c_int;
    fn lux_mlkem768_ct_size() -> c_int;

    fn lux_mldsa65_keypair(pk: *mut c_char, pk_len: *mut c_int, sk: *mut c_char, sk_len: *mut c_int) -> c_int;
    fn lux_mldsa65_sign(sk: *const c_char, sk_len: c_int, msg: *const c_char, msg_len: c_int, sig: *mut c_char, sig_len: *mut c_int) -> c_int;
    fn lux_mldsa65_verify(pk: *const c_char, pk_len: c_int, msg: *const c_char, msg_len: c_int, sig: *const c_char, sig_len: c_int) -> c_int;
    fn lux_mldsa65_pk_size() -> c_int;
    fn lux_mldsa65_sk_size() -> c_int;
    fn lux_mldsa65_sig_size() -> c_int;
}

// ── ML-KEM-768 (FIPS 203) ───────────────────────────────────────────

pub mod mlkem768 {
    use super::*;

    /// ML-KEM-768 public key size in bytes.
    pub fn pk_size() -> usize {
        unsafe { lux_mlkem768_pk_size() as usize }
    }

    /// ML-KEM-768 secret key size in bytes.
    pub fn sk_size() -> usize {
        unsafe { lux_mlkem768_sk_size() as usize }
    }

    /// ML-KEM-768 ciphertext size in bytes.
    pub fn ct_size() -> usize {
        unsafe { lux_mlkem768_ct_size() as usize }
    }

    /// Generate an ML-KEM-768 key pair.
    ///
    /// Returns `(public_key, secret_key)`.
    pub fn keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let pk_sz = pk_size();
        let sk_sz = sk_size();

        let mut pk = vec![0u8; pk_sz];
        let mut sk = vec![0u8; sk_sz];
        let mut pk_len: c_int = 0;
        let mut sk_len: c_int = 0;

        let rc = unsafe {
            lux_mlkem768_keypair(
                pk.as_mut_ptr() as *mut c_char, &mut pk_len,
                sk.as_mut_ptr() as *mut c_char, &mut sk_len,
            )
        };
        if rc != 0 {
            return Err(CryptoError::FFIError("lux_mlkem768_keypair", rc));
        }

        pk.truncate(pk_len as usize);
        sk.truncate(sk_len as usize);
        Ok((pk, sk))
    }

    /// Encapsulate a shared secret for the given public key.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let ct_sz = ct_size();

        let mut ct = vec![0u8; ct_sz];
        let mut ss = vec![0u8; 32];
        let mut ct_len: c_int = 0;
        let mut ss_len: c_int = 0;

        let rc = unsafe {
            lux_mlkem768_encapsulate(
                public_key.as_ptr() as *const c_char, public_key.len() as c_int,
                ct.as_mut_ptr() as *mut c_char, &mut ct_len,
                ss.as_mut_ptr() as *mut c_char, &mut ss_len,
            )
        };
        if rc != 0 {
            return Err(CryptoError::FFIError("lux_mlkem768_encapsulate", rc));
        }

        ct.truncate(ct_len as usize);
        ss.truncate(ss_len as usize);
        Ok((ct, ss))
    }

    /// Decapsulate a shared secret from ciphertext.
    ///
    /// Returns the shared secret.
    pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut ss = vec![0u8; 32];
        let mut ss_len: c_int = 0;

        let rc = unsafe {
            lux_mlkem768_decapsulate(
                secret_key.as_ptr() as *const c_char, secret_key.len() as c_int,
                ciphertext.as_ptr() as *const c_char, ciphertext.len() as c_int,
                ss.as_mut_ptr() as *mut c_char, &mut ss_len,
            )
        };
        if rc != 0 {
            return Err(CryptoError::FFIError("lux_mlkem768_decapsulate", rc));
        }

        ss.truncate(ss_len as usize);
        Ok(ss)
    }
}

// ── ML-DSA-65 (FIPS 204) ────────────────────────────────────────────

pub mod mldsa65 {
    use super::*;

    /// ML-DSA-65 public key size in bytes.
    pub fn pk_size() -> usize {
        unsafe { lux_mldsa65_pk_size() as usize }
    }

    /// ML-DSA-65 secret key size in bytes.
    pub fn sk_size() -> usize {
        unsafe { lux_mldsa65_sk_size() as usize }
    }

    /// ML-DSA-65 signature size in bytes.
    pub fn sig_size() -> usize {
        unsafe { lux_mldsa65_sig_size() as usize }
    }

    /// Generate an ML-DSA-65 key pair.
    ///
    /// Returns `(public_key, secret_key)`.
    pub fn keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let pk_sz = pk_size();
        let sk_sz = sk_size();

        let mut pk = vec![0u8; pk_sz];
        let mut sk = vec![0u8; sk_sz];
        let mut pk_len: c_int = 0;
        let mut sk_len: c_int = 0;

        let rc = unsafe {
            lux_mldsa65_keypair(
                pk.as_mut_ptr() as *mut c_char, &mut pk_len,
                sk.as_mut_ptr() as *mut c_char, &mut sk_len,
            )
        };
        if rc != 0 {
            return Err(CryptoError::FFIError("lux_mldsa65_keypair", rc));
        }

        pk.truncate(pk_len as usize);
        sk.truncate(sk_len as usize);
        Ok((pk, sk))
    }

    /// Sign a message with ML-DSA-65.
    ///
    /// Returns the signature.
    pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sig_sz = sig_size();

        let mut sig = vec![0u8; sig_sz];
        let mut sig_len: c_int = 0;

        let rc = unsafe {
            lux_mldsa65_sign(
                secret_key.as_ptr() as *const c_char, secret_key.len() as c_int,
                message.as_ptr() as *const c_char, message.len() as c_int,
                sig.as_mut_ptr() as *mut c_char, &mut sig_len,
            )
        };
        if rc != 0 {
            return Err(CryptoError::FFIError("lux_mldsa65_sign", rc));
        }

        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    /// Verify an ML-DSA-65 signature.
    ///
    /// Returns `true` if valid, `false` otherwise.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let rc = unsafe {
            lux_mldsa65_verify(
                public_key.as_ptr() as *const c_char, public_key.len() as c_int,
                message.as_ptr() as *const c_char, message.len() as c_int,
                signature.as_ptr() as *const c_char, signature.len() as c_int,
            )
        };
        rc == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem768_roundtrip() {
        let (pk, sk) = mlkem768::keypair().unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let (ct, ss_enc) = mlkem768::encapsulate(&pk).unwrap();
        assert!(!ct.is_empty());
        assert_eq!(ss_enc.len(), 32);

        let ss_dec = mlkem768::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_mldsa65_sign_verify() {
        let (pk, sk) = mldsa65::keypair().unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let message = b"The quick brown fox jumps over the lazy dog";
        let sig = mldsa65::sign(&sk, message).unwrap();
        assert!(!sig.is_empty());

        assert!(mldsa65::verify(&pk, message, &sig));
        assert!(!mldsa65::verify(&pk, b"wrong message", &sig));
    }
}
