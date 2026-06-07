//go:build hqc_pqclean && !lux_hqc_native

/*
 * randombytes_shim.c — PQClean randombytes() bridge (non-native build).
 *
 * PQClean's HQC reference calls `randombytes(out, n)` for every byte
 * of entropy it needs. In the default (non-native) build there is no
 * luxgpu_hqc static library linked in, so the only entropy source is
 * the Go-side io.Reader, reached via the cgo-exported hqcGoRandombytes
 * callback (backend_pqclean.go's installRNG + lock).
 *
 * The native batch path (C++ host kernel installing a per-slot TLS
 * seed buffer, served by lux_hqc_randombytes) is compiled only under
 * the `lux_hqc_native` build tag — see randombytes_shim_native.c.
 * Referencing those symbols here would leave them undefined at link
 * time whenever the native library is absent (which is the common
 * case: CI, pure-Go deployments). So this default TU forwards
 * unconditionally to Go.
 *
 * Determinism contract: every call consumes exactly `n` bytes from
 * the Go reader, in call order. Two KeyGen/Encapsulate invocations
 * seeded from byte-identical streams produce byte-identical outputs.
 * This is load-bearing for the HQC precompile.
 */
#include <stdint.h>
#include <stddef.h>

/* Forward declaration of the cgo-exported Go callback. */
extern int hqcGoRandombytes(uint8_t *buf, size_t n);

int randombytes(uint8_t *output, size_t n) {
    return hqcGoRandombytes(output, n);
}
