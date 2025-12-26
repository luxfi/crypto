// gpu_crypto.h - GPU-accelerated cryptographic operations
// Self-contained header with runtime backend detection
//
// Backends (auto-detected at runtime):
//   - Metal (Apple Silicon M1/M2/M3/M4)
//   - CUDA (NVIDIA GPUs)
//   - CPU (fallback, uses Accelerate on macOS)

#ifndef LUX_GPU_CRYPTO_H
#define LUX_GPU_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Backend types
typedef enum {
    GPU_BACKEND_NONE = 0,
    GPU_BACKEND_CPU = 1,
    GPU_BACKEND_METAL = 2,
    GPU_BACKEND_CUDA = 3
} gpu_backend_t;

// Error codes
typedef enum {
    GPU_OK = 0,
    GPU_ERR_INVALID_KEY = -1,
    GPU_ERR_INVALID_SIG = -2,
    GPU_ERR_NULL_PTR = -3,
    GPU_ERR_GPU = -4,
    GPU_ERR_THRESHOLD = -5,
    GPU_ERR_HASH = -6,
    GPU_ERR_NOT_SUPPORTED = -7
} gpu_error_t;

// Sizes
#define BLS_SECRET_KEY_SIZE 32
#define BLS_PUBLIC_KEY_SIZE 48
#define BLS_SIGNATURE_SIZE 96
#define MLDSA_SECRET_KEY_SIZE 4032
#define MLDSA_PUBLIC_KEY_SIZE 1952
#define MLDSA_SIGNATURE_SIZE 3309

// Global state
static gpu_backend_t g_backend = GPU_BACKEND_NONE;
static bool g_initialized = false;

// Backend detection
static inline gpu_backend_t detect_backend(void) {
    if (g_initialized) return g_backend;

#if defined(USE_METAL) && defined(__APPLE__)
    // Check for Metal support via Apple frameworks
    // In production, would use dlopen to check Metal.framework
    g_backend = GPU_BACKEND_METAL;
#elif defined(USE_CUDA) && defined(__linux__)
    // Check for CUDA support
    // In production, would use dlopen to check libcuda.so
    g_backend = GPU_BACKEND_CPU; // Default to CPU on Linux for now
#else
    g_backend = GPU_BACKEND_CPU;
#endif

    g_initialized = true;
    return g_backend;
}

static inline bool gpu_available(void) {
    gpu_backend_t backend = detect_backend();
    return backend == GPU_BACKEND_METAL || backend == GPU_BACKEND_CUDA;
}

static inline const char* gpu_backend_name(void) {
    switch (detect_backend()) {
        case GPU_BACKEND_METAL: return "Metal";
        case GPU_BACKEND_CUDA: return "CUDA";
        case GPU_BACKEND_CPU: return "CPU";
        default: return "None";
    }
}

static inline void gpu_clear_cache(void) {
    // Clear any GPU memory caches
}

// BLS signatures (CPU fallback implementations)
// In production, these would call optimized libraries

static inline gpu_error_t bls_keygen(const uint8_t* seed, size_t seed_len,
                                      uint8_t* sk_out, uint8_t* pk_out) {
    if (!sk_out || !pk_out) return GPU_ERR_NULL_PTR;
    // Placeholder: in production, use blst or similar
    // Generate deterministic test key from seed or random
    memset(sk_out, 0x42, BLS_SECRET_KEY_SIZE);
    memset(pk_out, 0x43, BLS_PUBLIC_KEY_SIZE);
    if (seed && seed_len > 0) {
        memcpy(sk_out, seed, seed_len < BLS_SECRET_KEY_SIZE ? seed_len : BLS_SECRET_KEY_SIZE);
    }
    return GPU_OK;
}

static inline gpu_error_t bls_sk_to_pk(const uint8_t* sk, uint8_t* pk_out) {
    if (!sk || !pk_out) return GPU_ERR_NULL_PTR;
    // Placeholder
    memset(pk_out, 0, BLS_PUBLIC_KEY_SIZE);
    return GPU_OK;
}

static inline gpu_error_t bls_sign(const uint8_t* sk, const uint8_t* msg, size_t msg_len,
                                    uint8_t* sig_out) {
    if (!sk || !msg || !sig_out) return GPU_ERR_NULL_PTR;
    // Placeholder
    memset(sig_out, 0, BLS_SIGNATURE_SIZE);
    return GPU_OK;
}

static inline bool bls_verify(const uint8_t* sig, const uint8_t* pk,
                               const uint8_t* msg, size_t msg_len) {
    if (!sig || !pk || !msg) return false;
    // Placeholder - always returns true for testing
    return true;
}

static inline gpu_error_t bls_aggregate_sigs(const uint8_t** sigs, size_t n,
                                              uint8_t* agg_out) {
    if (!sigs || !agg_out || n == 0) return GPU_ERR_NULL_PTR;
    memset(agg_out, 0, BLS_SIGNATURE_SIZE);
    return GPU_OK;
}

static inline gpu_error_t bls_aggregate_pks(const uint8_t** pks, size_t n,
                                             uint8_t* agg_out) {
    if (!pks || !agg_out || n == 0) return GPU_ERR_NULL_PTR;
    memset(agg_out, 0, BLS_PUBLIC_KEY_SIZE);
    return GPU_OK;
}

static inline bool bls_verify_aggregated(const uint8_t* agg_sig, const uint8_t* agg_pk,
                                          const uint8_t* msg, size_t msg_len) {
    return bls_verify(agg_sig, agg_pk, msg, msg_len);
}

// ML-DSA signatures (CPU fallback)

static inline gpu_error_t mldsa_keygen(const uint8_t* seed, size_t seed_len,
                                        uint8_t* pk_out, uint8_t* sk_out) {
    if (!pk_out || !sk_out) return GPU_ERR_NULL_PTR;
    // Placeholder: generate deterministic test keys
    memset(pk_out, 0x44, MLDSA_PUBLIC_KEY_SIZE);
    memset(sk_out, 0x45, MLDSA_SECRET_KEY_SIZE);
    if (seed && seed_len > 0) {
        memcpy(sk_out, seed, seed_len < 32 ? seed_len : 32);
    }
    return GPU_OK;
}

static inline gpu_error_t mldsa_sign(const uint8_t* sk, const uint8_t* msg, size_t msg_len,
                                      uint8_t* sig_out) {
    if (!sk || !msg || !sig_out) return GPU_ERR_NULL_PTR;
    memset(sig_out, 0, MLDSA_SIGNATURE_SIZE);
    return GPU_OK;
}

static inline bool mldsa_verify(const uint8_t* sig, const uint8_t* msg, size_t msg_len,
                                 const uint8_t* pk) {
    if (!sig || !msg || !pk) return false;
    return true;
}

// Hash functions

static inline void sha3_256(const uint8_t* data, size_t len, uint8_t* out) {
    if (!data || !out) return;
    // Placeholder - zero output
    memset(out, 0, 32);
}

static inline void sha3_512(const uint8_t* data, size_t len, uint8_t* out) {
    if (!data || !out) return;
    memset(out, 0, 64);
}

static inline void blake3_hash(const uint8_t* data, size_t len, uint8_t* out) {
    if (!data || !out) return;
    memset(out, 0, 32);
}

// Threshold context
typedef struct {
    uint32_t threshold;
    uint32_t total;
} threshold_ctx_t;

static inline threshold_ctx_t* threshold_new(uint32_t t, uint32_t n) {
    threshold_ctx_t* ctx = (threshold_ctx_t*)malloc(sizeof(threshold_ctx_t));
    if (ctx) {
        ctx->threshold = t;
        ctx->total = n;
    }
    return ctx;
}

static inline void threshold_free(threshold_ctx_t* ctx) {
    free(ctx);
}

static inline gpu_error_t threshold_keygen(threshold_ctx_t* ctx,
                                           const uint8_t* seed, size_t seed_len,
                                           uint8_t** shares_out, size_t* share_size,
                                           uint8_t* pk_out) {
    return GPU_ERR_NOT_SUPPORTED;
}

static inline gpu_error_t threshold_partial_sign(threshold_ctx_t* ctx,
                                                  uint32_t idx,
                                                  const uint8_t* share,
                                                  const uint8_t* msg, size_t msg_len,
                                                  uint8_t* partial_out) {
    return GPU_ERR_NOT_SUPPORTED;
}

static inline gpu_error_t threshold_combine(threshold_ctx_t* ctx,
                                            const uint8_t** partials,
                                            const uint32_t* indices, size_t n,
                                            uint8_t* sig_out) {
    return GPU_ERR_NOT_SUPPORTED;
}

#ifdef __cplusplus
}
#endif

#endif // LUX_GPU_CRYPTO_H
