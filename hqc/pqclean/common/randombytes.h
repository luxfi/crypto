/*
 * randombytes.h — header used by PQClean HQC sources to declare the
 * randombytes() entry point. The actual implementation lives in
 * crypto/hqc/randombytes_shim.c and reads from a Go-supplied buffer
 * via a cgo callback (see backend_pqclean.go).
 *
 * This vendored header replaces PQClean's common/randombytes.h, which
 * pulls in OS entropy sources we don't want for the deterministic
 * KEM precompile.
 */
#ifndef PQCLEAN_HQC_RANDOMBYTES_H
#define PQCLEAN_HQC_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int randombytes(uint8_t *output, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* PQCLEAN_HQC_RANDOMBYTES_H */
