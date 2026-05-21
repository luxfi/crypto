//go:build hqc_pqclean

/*
 * randombytes_shim.c — single canonical PQClean randombytes() bridge.
 *
 * PQClean's HQC reference calls `randombytes(out, n)` for every byte
 * of entropy it needs. We provide a single strong definition that
 * dispatches between two sources, in order:
 *
 *   1. If a TLS seed buffer is installed via lux_hqc_install_seed(),
 *      bytes are served from there. This is the accel/ops/code batch
 *      path — the C++ batch kernel pre-installs a per-slot seed
 *      slice before each inner PQClean call.
 *
 *   2. Otherwise, bytes are read from a Go-side io.Reader via the
 *      cgo-exported hqcGoRandombytes callback. This is the direct
 *      single-op path (backend_pqclean.go's installRNG + lock).
 *
 * Determinism contract: every call consumes exactly `n` bytes from
 * the active source, in call order. Two KeyGen/Encapsulate
 * invocations seeded from byte-identical streams produce byte-
 * identical outputs. This is load-bearing for the HQC precompile.
 *
 * Note: this shim deliberately uses the SAME `randombytes` symbol
 * as the luxgpu_hqc static library (which marks its definition
 * weak). At link time, this strong definition wins. The luxgpu_hqc
 * library's `lux_hqc_install_seed` / `lux_hqc_clear_seed` symbols
 * are reachable from this TU via the externs below.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Forward declaration of the cgo-exported Go callback. */
extern int hqcGoRandombytes(uint8_t *buf, size_t n);

/*
 * The luxgpu_hqc library exposes a TLS seed buffer plus accessors.
 * When the batch kernel runs, it installs the seed via
 * lux_hqc_install_seed; PQClean then calls randombytes which we
 * forward to lux_hqc_randombytes (the buffer-reading helper).
 *
 * The crypto/hqc package never calls lux_hqc_install_seed directly
 * — that's done from the C++ host kernel in mlx/src/hqc_host.cpp.
 * What we DO check here is whether the seed buffer has any pending
 * bytes; if so we serve from it, otherwise we fall back to Go.
 *
 * The hqc_seed_has_bytes() helper is defined in
 * mlx/src/hqc_seed_rng.c and returns non-zero iff the TLS buffer
 * has unread bytes available.
 */
extern int  lux_hqc_randombytes(uint8_t *out, size_t n);
extern int  lux_hqc_seed_has_bytes(void);

int randombytes(uint8_t *output, size_t n) {
    if (lux_hqc_seed_has_bytes()) {
        return lux_hqc_randombytes(output, n);
    }
    return hqcGoRandombytes(output, n);
}
