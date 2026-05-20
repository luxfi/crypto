/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_keygen.c -- dudect main loop driving mlkem.GenerateKeyPair
 * through the cgo bridge in keygen_ct.go.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int    mlkem_keygen_ct_setup(void);
extern size_t mlkem_keygen_ct_input_size(void);
extern void   mlkem_keygen_ct(uint8_t *data);

static size_t g_chunk_size = 0;

void prepare_inputs(dudect_config_t *cfg, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < cfg->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *slot = input_data + (size_t)i * cfg->chunk_size;
        if (classes[i] == 0) {
            memset(slot, 0, cfg->chunk_size);
        } else {
            randombytes(slot, cfg->chunk_size);
        }
    }
}

uint8_t do_one_computation(uint8_t *data) {
    mlkem_keygen_ct(data);
    uint8_t acc = 0;
    for (size_t i = 0; i < g_chunk_size; i++) acc ^= data[i];
    return acc;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int rc = mlkem_keygen_ct_setup();
    if (rc != 0) {
        fprintf(stderr, "mlkem_keygen_ct_setup failed: rc=%d\n", rc);
        return 1;
    }
    g_chunk_size = mlkem_keygen_ct_input_size();

    const char *env_samples = getenv("DUDECT_SAMPLES");
    const char *env_batches = getenv("DUDECT_MAX_BATCHES");
    size_t samples = env_samples ? (size_t)atoll(env_samples) : 10000;
    size_t batches = env_batches ? (size_t)atoll(env_batches) : 100;

    dudect_config_t cfg = {
        .chunk_size          = g_chunk_size,
        .number_measurements = samples,
        
    };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &cfg);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }
    dudect_free(&ctx);

    if (state == DUDECT_LEAKAGE_FOUND) {
        fprintf(stderr, "VERDICT: leakage detected in mlkem.Keygen\n");
        return 2;
    }
    fprintf(stdout, "VERDICT: no leakage detected within budget\n");
    return 0;
}
