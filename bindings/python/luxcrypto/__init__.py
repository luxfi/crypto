"""luxcrypto — Python bindings for Lux post-quantum cryptography.

One library, one implementation. Uses libluxcrypto (Go/circl) via ctypes.
Same PQ crypto from blockchain to AI agents.

    from luxcrypto import mlkem768, mldsa65

    pk, sk = mlkem768.keypair()
    ct, ss_enc = mlkem768.encapsulate(pk)
    ss_dec = mlkem768.decapsulate(sk, ct)
    assert ss_enc == ss_dec

    pk, sk = mldsa65.keypair()
    sig = mldsa65.sign(sk, b"hello")
    assert mldsa65.verify(pk, b"hello", sig)
"""

from luxcrypto._ffi import crypto_available
from luxcrypto import mlkem768, mldsa65

__version__ = "0.1.0"
__all__ = ["mlkem768", "mldsa65", "crypto_available"]
