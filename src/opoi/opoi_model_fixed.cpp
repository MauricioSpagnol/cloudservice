// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license.
//
// F8-A: opoi_model_fixed.cpp — Tiny deterministic MLP (int32 only, no float).
//
// Weight generation via LCG (Linear Congruential Generator):
//   next = a * current + c  (mod 2^64)
//   a = 6364136223846793005  (Knuth)
//   c = 1442695040888963407  (Knuth)
// Each weight = (int32_t)(lcg_next() >> 33)   — takes high 31 bits, sign-extends
// This maps uniformly to approximately [-1073741824, +1073741823].

#include "opoi_model_fixed.h"
#include <string.h>

// ── LCG weight generator ──────────────────────────────────────────────────────

static uint64_t lcg_state;

static void lcg_init(uint64_t seed) {
    lcg_state = seed;
}

static uint64_t lcg_next(void) {
    lcg_state = 6364136223846793005ULL * lcg_state + 1442695040888963407ULL;
    return lcg_state;
}

static int32_t lcg_weight(void) {
    // Take bits [62:32] — 31 bits — interpret as signed int32
    uint64_t v = lcg_next();
    uint32_t raw = (uint32_t)((v >> 32) & 0x7FFFFFFF);
    // Sign-extend: if bit 30 is set, make it negative
    if (raw & 0x40000000)
        return (int32_t)(raw | 0x80000000u);
    return (int32_t)raw;
}

// ── Static weight tables (generated at first call, then reused) ───────────────

// W1: IN×H1 = 32×256 = 8192 weights
// b1: H1     = 256 biases
// W2: H1×H2  = 256×128 = 32768 weights
// b2: H2     = 128 biases
// W3: H2×OUT = 128×32 = 4096 weights
// b3: OUT    = 32 biases

static int32_t W1[OPOI_MF_IN][OPOI_MF_H1];
static int32_t b1[OPOI_MF_H1];
static int32_t W2[OPOI_MF_H1][OPOI_MF_H2];
static int32_t b2[OPOI_MF_H2];
static int32_t W3[OPOI_MF_H2][OPOI_MF_OUT];
static int32_t b3[OPOI_MF_OUT];
static int     weights_initialized = 0;

static void ensure_weights(void) {
    if (weights_initialized) return;
    lcg_init(OPOI_MODEL_FIXED_SEED);

    for (int i = 0; i < OPOI_MF_IN;  i++)
        for (int j = 0; j < OPOI_MF_H1; j++)
            W1[i][j] = lcg_weight();
    for (int j = 0; j < OPOI_MF_H1; j++)
        b1[j] = lcg_weight();

    for (int i = 0; i < OPOI_MF_H1; i++)
        for (int j = 0; j < OPOI_MF_H2; j++)
            W2[i][j] = lcg_weight();
    for (int j = 0; j < OPOI_MF_H2; j++)
        b2[j] = lcg_weight();

    for (int i = 0; i < OPOI_MF_H2; i++)
        for (int j = 0; j < OPOI_MF_OUT; j++)
            W3[i][j] = lcg_weight();
    for (int j = 0; j < OPOI_MF_OUT; j++)
        b3[j] = lcg_weight();

    weights_initialized = 1;
}

// ── ReLU activation (int32 — simply clamp negatives to 0) ────────────────────

static int32_t relu32(int32_t x) {
    return x < 0 ? 0 : x;
}

// ── Forward pass ──────────────────────────────────────────────────────────────

void opoi_model_fixed_forward(const uint8_t input[32], uint8_t output[32]) {
    ensure_weights();

    // Convert 32 input bytes to int32 (unsigned byte → int32)
    int32_t in[OPOI_MF_IN];
    for (int i = 0; i < OPOI_MF_IN; i++)
        in[i] = (int32_t)(uint32_t)input[i];

    // Layer 1: IN → H1
    // Accumulate in int64 to avoid overflow, then right-shift 10 and clamp to int32
    int32_t h1[OPOI_MF_H1];
    for (int j = 0; j < OPOI_MF_H1; j++) {
        int64_t acc = (int64_t)b1[j];
        for (int i = 0; i < OPOI_MF_IN; i++)
            acc += (int64_t)W1[i][j] * (int64_t)in[i];
        acc >>= 10; // normalize
        h1[j] = relu32((int32_t)acc);
    }

    // Layer 2: H1 → H2
    int32_t h2[OPOI_MF_H2];
    for (int j = 0; j < OPOI_MF_H2; j++) {
        int64_t acc = (int64_t)b2[j];
        for (int i = 0; i < OPOI_MF_H1; i++)
            acc += (int64_t)W2[i][j] * (int64_t)h1[i];
        acc >>= 10; // normalize
        h2[j] = relu32((int32_t)acc);
    }

    // Layer 3: H2 → OUT (no activation — raw output)
    int64_t out64[OPOI_MF_OUT];
    for (int j = 0; j < OPOI_MF_OUT; j++) {
        int64_t acc = (int64_t)b3[j];
        for (int i = 0; i < OPOI_MF_H2; i++)
            acc += (int64_t)W3[i][j] * (int64_t)h2[i];
        out64[j] = acc;
    }

    // XOR-fold: each output byte = XOR of all 8 bytes of out64[i] folded together,
    // then XOR with the previous byte for mixing
    // Specifically: output[i] = low_byte(out64[i]) XOR folded_high_bytes
    uint8_t prev = 0;
    for (int j = 0; j < OPOI_MF_OUT; j++) {
        uint64_t v = (uint64_t)out64[j];
        // XOR all 8 bytes of v
        uint8_t folded = 0;
        for (int b = 0; b < 8; b++)
            folded ^= (uint8_t)(v >> (b * 8));
        // Mix with previous output byte for diffusion
        output[j] = folded ^ prev;
        prev = output[j];
    }
}
