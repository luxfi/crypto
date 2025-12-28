"""ML-DSA-65 (FIPS 204) — digital signatures via libluxcrypto."""

from __future__ import annotations

import ctypes

from luxcrypto._ffi import get_lib

_PK_SIZE: int | None = None
_SK_SIZE: int | None = None
_SIG_SIZE: int | None = None


def _sizes() -> tuple[int, int, int]:
    global _PK_SIZE, _SK_SIZE, _SIG_SIZE
    if _PK_SIZE is None:
        lib = get_lib()
        _PK_SIZE = lib.mldsa65_pk_size()
        _SK_SIZE = lib.mldsa65_sk_size()
        _SIG_SIZE = lib.mldsa65_sig_size()
    return _PK_SIZE, _SK_SIZE, _SIG_SIZE


def keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 key pair.

    Returns (public_key, secret_key).
    """
    pk_size, sk_size, _ = _sizes()
    lib = get_lib()

    pk_buf = ctypes.create_string_buffer(pk_size)
    sk_buf = ctypes.create_string_buffer(sk_size)
    pk_len = ctypes.c_int(0)
    sk_len = ctypes.c_int(0)

    rc = lib.mldsa65_keypair(pk_buf, ctypes.byref(pk_len), sk_buf, ctypes.byref(sk_len))
    if rc != 0:
        raise RuntimeError(f"mldsa65_keypair failed: {rc}")

    return pk_buf.raw[: pk_len.value], sk_buf.raw[: sk_len.value]


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message with ML-DSA-65.

    Returns signature bytes.
    """
    _, _, sig_size = _sizes()
    lib = get_lib()

    sig_buf = ctypes.create_string_buffer(sig_size)
    sig_len = ctypes.c_int(0)

    rc = lib.mldsa65_sign(
        secret_key, len(secret_key),
        message, len(message),
        sig_buf, ctypes.byref(sig_len),
    )
    if rc != 0:
        raise RuntimeError(f"mldsa65_sign failed: {rc}")

    return sig_buf.raw[: sig_len.value]


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature.

    Returns True if valid, False otherwise.
    """
    lib = get_lib()

    rc = lib.mldsa65_verify(
        public_key, len(public_key),
        message, len(message),
        signature, len(signature),
    )
    return rc == 0
