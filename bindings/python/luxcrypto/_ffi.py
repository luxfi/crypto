"""FFI layer — loads libluxcrypto shared library."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path

_LIB: ctypes.CDLL | None = None
LUX_CRYPTO_AVAILABLE = False


def _find_lib() -> str | None:
    """Find libluxcrypto on the system."""
    # 1. Env var override
    env = os.environ.get("LUX_CRYPTO_LIB")
    if env and os.path.isfile(env):
        return env

    # 2. Adjacent to this package (e.g. wheel ships the .dylib/.so)
    here = Path(__file__).parent
    for name in ("libluxcrypto.dylib", "libluxcrypto.so", "libluxcrypto.dll"):
        p = here / name
        if p.exists():
            return str(p)

    # 3. In the lux/crypto/dist build output
    dist = Path.home() / "work" / "lux" / "crypto" / "dist"
    for name in ("libluxcrypto.dylib", "libluxcrypto.so", "libluxcrypto.dll"):
        p = dist / name
        if p.exists():
            return str(p)

    # 4. System library path
    found = ctypes.util.find_library("luxcrypto")
    return found


def _load() -> ctypes.CDLL | None:
    path = _find_lib()
    if path is None:
        return None
    try:
        return ctypes.CDLL(path)
    except OSError:
        return None


_LIB = _load()
LUX_CRYPTO_AVAILABLE = _LIB is not None


def get_lib() -> ctypes.CDLL:
    """Get the loaded library, raising if unavailable."""
    if _LIB is None:
        raise RuntimeError(
            "libluxcrypto not found. Build it with: "
            "cd ~/work/lux/crypto && make lib"
        )
    return _LIB
