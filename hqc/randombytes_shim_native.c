//go:build hqc_pqclean && lux_hqc_native

/*
 * randombytes_shim_native.c — PQClean randombytes() bridge (native build).
 *
 * Compiled only with the `lux_hqc_native` build tag, i.e. when the
 * luxgpu_hqc static library (built from luxfi/mlx) is linked in and
 * accel's native HQC batch kernels are active. It dispatches between
 * two entropy sources, in order:
 *
 *   1. If the C++ batch kernel has installed a per-slot TLS seed
 *      buffer (lux_hqc_install_seed), bytes are served from there via
 *      lux_hqc_randombytes. This keeps the batch path byte-identical
 *      to the direct path.
 *
 *   2. Otherwise, bytes are read from a Go-side io.Reader via the
 *      cgo-exported hqcGoRandombytes callback (the direct single-op
 *      path: backend_pqclean.go's installRNG + lock).
 *
 * lux_hqc_randombytes / lux_hqc_seed_has_bytes are provided by accel's
 * code_cpu_randombytes.go (which is itself gated on lux_hqc_native), so
 * the externs below resolve only in this tag combination.
 *
 * Determinism contract: every call consumes exactly `n` bytes from the
 * active source, in call order — load-bearing for the HQC precompile.
 *
 * Note: this shim deliberately uses the SAME `randombytes` symbol as
 * the luxgpu_hqc static library (which marks its definition weak). At
 * link time, this strong definition wins.
 */
#include <stdint.h>
#include <stddef.h>

/* Forward declaration of the cgo-exported Go callback. */
extern int hqcGoRandombytes(uint8_t *buf, size_t n);

/* Provided by the luxgpu_hqc library / accel native randombytes TU. */
extern int  lux_hqc_randombytes(uint8_t *out, size_t n);
extern int  lux_hqc_seed_has_bytes(void);

int randombytes(uint8_t *output, size_t n) {
    if (lux_hqc_seed_has_bytes()) {
        return lux_hqc_randombytes(output, n);
    }
    return hqcGoRandombytes(output, n);
}
