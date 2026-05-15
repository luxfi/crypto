//go:build hqc_pqclean

/*
 * fips202_amalg.c — single translation unit holding the SHA-3 / SHAKE
 * implementation used by all three HQC modes. fips202.c symbols are
 * NOT namespaced per-mode upstream, so compiling fips202.c into each
 * mode's amalgamation would create duplicate-symbol linker errors.
 * Pull it in exactly once here.
 */
#include "pqclean/common/fips202.c"
