//go:build hqc_pqclean

/*
 * randombytes_shim.c — bridge between PQClean HQC's randombytes()
 * contract and a Go-supplied io.Reader.
 *
 * The Go side (backend_pqclean.go) acquires a global mutex, installs
 * an io.Reader, then calls one of the three KEM entry points. Each
 * call into the C HQC library that needs entropy invokes randombytes(),
 * which forwards to hqcGoRandombytes() — a Go function exported via
 * cgo. Go reads exactly `n` bytes from the active reader and copies
 * them back into the output buffer.
 *
 * Determinism contract: every call consumes exactly `n` bytes from the
 * reader, in call order. Two KeyGen/Encapsulate invocations seeded
 * from byte-identical streams produce byte-identical outputs. This is
 * load-bearing for the HQC precompile.
 */
#include <stdint.h>
#include <stddef.h>

/* Forward declaration of the cgo-exported Go callback. */
extern int hqcGoRandombytes(uint8_t *buf, size_t n);

int randombytes(uint8_t *output, size_t n) {
    return hqcGoRandombytes(output, n);
}
