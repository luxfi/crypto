"""ML-KEM-768 (FIPS 203) — key encapsulation via libluxcrypto."""

from __future__ import annotations

import ctypes

from luxcrypto._ffi import get_lib

# Sizes (queried from lib at first call, cached)
_PK_SIZE: int | None = None
_SK_SIZE: int | None = None
_CT_SIZE: int | None = None
_SS_SIZE = 32


def _sizes() -> tuple[int, int, int]:
    global _PK_SIZE, _SK_SIZE, _CT_SIZE
    if _PK_SIZE is None:
        lib = get_lib()
        _PK_SIZE = lib.lux_mlkem768_pk_size()
        _SK_SIZE = lib.lux_mlkem768_sk_size()
        _CT_SIZE = lib.lux_mlkem768_ct_size()
    return _PK_SIZE, _SK_SIZE, _CT_SIZE


def keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 key pair.

    Returns (public_key, secret_key).
    """
    pk_size, sk_size, _ = _sizes()
    lib = get_lib()

    pk_buf = ctypes.create_string_buffer(pk_size)
    sk_buf = ctypes.create_string_buffer(sk_size)
    pk_len = ctypes.c_int(0)
    sk_len = ctypes.c_int(0)

    rc = lib.lux_mlkem768_keypair(pk_buf, ctypes.byref(pk_len), sk_buf, ctypes.byref(sk_len))
    if rc != 0:
        raise RuntimeError(f"lux_mlkem768_keypair failed: {rc}")

    return pk_buf.raw[: pk_len.value], sk_buf.raw[: sk_len.value]


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret for the given public key.

    Returns (ciphertext, shared_secret).
    """
    _, _, ct_size = _sizes()
    lib = get_lib()

    ct_buf = ctypes.create_string_buffer(ct_size)
    ss_buf = ctypes.create_string_buffer(_SS_SIZE)
    ct_len = ctypes.c_int(0)
    ss_len = ctypes.c_int(0)

    rc = lib.lux_mlkem768_encapsulate(
        public_key, len(public_key),
        ct_buf, ctypes.byref(ct_len),
        ss_buf, ctypes.byref(ss_len),
    )
    if rc != 0:
        raise RuntimeError(f"lux_mlkem768_encapsulate failed: {rc}")

    return ct_buf.raw[: ct_len.value], ss_buf.raw[: ss_len.value]


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate a shared secret from ciphertext.

    Returns shared_secret.
    """
    lib = get_lib()

    ss_buf = ctypes.create_string_buffer(_SS_SIZE)
    ss_len = ctypes.c_int(0)

    rc = lib.lux_mlkem768_decapsulate(
        secret_key, len(secret_key),
        ciphertext, len(ciphertext),
        ss_buf, ctypes.byref(ss_len),
    )
    if rc != 0:
        raise RuntimeError(f"lux_mlkem768_decapsulate failed: {rc}")

    return ss_buf.raw[: ss_len.value]
