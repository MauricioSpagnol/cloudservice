// Copyright (c) 2026 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// F10-D / F15-C: ECVRF over secp256k1 ("SECP256K1_SHA256_TAI" ciphersuite),
// built ONLY from the public, stable API of the vanilla secp256k1 already
// vendored in this project (src/secp256k1/) — no fork, no modified internals.
//
// Why hand-rolled instead of vendoring an existing secp256k1-vrf fork: the
// two public forks evaluated (aergoio and koinos) both fail their own
// ECDSA DER-parsing test suite (run_ecdsa_der_parse, reproducible 100% of
// the time), which the vanilla library passes cleanly. That is too large a
// trust regression for a consensus-critical dependency, so this module
// instead follows RFC 9381's generic ECVRF construction (the same skeleton
// as ECVRF-EDWARDS25519-SHA512-TAI, ported to secp256k1/SHA256) using only
// secp256k1_ec_pubkey_{create,tweak_mul,negate,combine,parse,serialize} and
// secp256k1_ec_privkey_tweak_{add,mul} — all long-stable, audited, public API.
//
// Proof format (81 bytes): Gamma (33-byte compressed point) || c (16 bytes)
// || s (32 bytes). This matches the layout used by the (independently
// untrustworthy, but structurally standard) forks above, which is itself
// just the generic ECVRF proof shape from RFC 9381 §5.1.

#ifndef CSCOIN_OPOI_VRF_H
#define CSCOIN_OPOI_VRF_H

#include <cstdint>
#include <cstddef>
#include <vector>

static const size_t OPOI_VRF_PROOF_SIZE  = 81; // Gamma(33) || c(16) || s(32)
static const size_t OPOI_VRF_PK_SIZE     = 33; // compressed pubkey
static const size_t OPOI_VRF_OUTPUT_SIZE = 32;

// Must be called once at daemon startup (after ECC_Start()) and OPoIVRFStop()
// at shutdown. Owns its own secp256k1 context (SIGN|VERIFY) independent of
// key.cpp/pubkey.cpp's globals, so this module has no init-order coupling.
void OPoIVRFStart();
void OPoIVRFStop();

// Generates a VRF proof for message alpha under secret key sk (32 bytes),
// whose corresponding compressed public key is pk (33 bytes). Returns false
// if sk is invalid or pk does not match sk (defensive check).
bool OPoIVRFProve(const unsigned char sk[32], const unsigned char pk[OPOI_VRF_PK_SIZE],
                   const unsigned char* alpha, size_t alphaLen,
                   std::vector<unsigned char>& proofOut);

// Verifies proof (81 bytes) against pk and alpha. On success, fills
// output[32] with the VRF hash and returns true. Returns false if the proof
// is malformed or invalid — output is left untouched in that case.
bool OPoIVRFVerify(const unsigned char pk[OPOI_VRF_PK_SIZE],
                    const unsigned char* alpha, size_t alphaLen,
                    const std::vector<unsigned char>& proof,
                    unsigned char output[OPOI_VRF_OUTPUT_SIZE]);

#endif // CSCOIN_OPOI_VRF_H
