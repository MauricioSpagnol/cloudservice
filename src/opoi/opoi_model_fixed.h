// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license.
//
// F8-A: Deterministic tiny MLP for request acknowledgment commitment (Gate 2).
//
// Architecture: 32 → 256 → 128 → 32 neurons
// Arithmetic:   pure int32_t / int64_t — ZERO float
// Weights:      generated from LCG seed 0xDEADBEEFCAFE (reproducible, public)
// Normalization: right-shift 10 bits after each hidden layer (keeps magnitudes bounded)
// Output:       32 bytes via XOR-fold of the 32 int64 output neurons
//
// USAGE:
//   opoi_model_fixed_forward(input_32_bytes, output_32_bytes);
//
// GUARANTEES:
//   - Identical output on x86_64 and ARM given same input
//   - Identical output with -O0 and -O2
//   - Identical output between gcc and clang
//   - Identical output between C++ (this file) and Rust port (cs-miner/model_fixed.rs)
//
// PURPOSE (per spec F8):
//   opoiCommitment = model_fixed_forward(request_hash || response_hash)
//   This proves the miner committed to a specific (request, response) pair BEFORE
//   seeing other miners' responses (anti-equivocation). It does NOT prove the LLM
//   was executed — that requires TEE or ZKML (future work).

#ifndef CSCOIN_OPOI_MODEL_FIXED_H
#define CSCOIN_OPOI_MODEL_FIXED_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// MLP dimensions
static const int OPOI_MF_IN  = 32;
static const int OPOI_MF_H1  = 256;
static const int OPOI_MF_H2  = 128;
static const int OPOI_MF_OUT = 32;

// LCG seed used to deterministically generate all weights
static const uint64_t OPOI_MODEL_FIXED_SEED = 0xDEADBEEFCAFEULL;

// Compute the MLP commitment.
// input  : exactly 32 bytes (e.g., SHA256(request_hash || response_hash))
// output : exactly 32 bytes (commitment value)
void opoi_model_fixed_forward(const uint8_t input[32], uint8_t output[32]);

#ifdef __cplusplus
}
#endif

#endif // CSCOIN_OPOI_MODEL_FIXED_H
