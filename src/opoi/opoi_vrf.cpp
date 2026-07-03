// Copyright (c) 2026 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "opoi_vrf.h"
#include "crypto/sha256.h"
#include <secp256k1.h>
#include <cstring>
#include <cassert>

namespace {

secp256k1_context* g_vrfCtx = nullptr;

// Suite byte: this is NOT an IANA-registered RFC 9381 ciphersuite (secp256k1
// has none) — it is a project-local domain-separation tag so hash_to_curve /
// challenge_generation / proof_to_hash / nonce_generate can never collide
// with each other even for identical input bytes.
const unsigned char SUITE = 0xC5;
const unsigned char DOM_HASH_TO_CURVE = 0x01;
const unsigned char DOM_CHALLENGE     = 0x02;
const unsigned char DOM_PROOF_TO_HASH = 0x03;
const unsigned char DOM_NONCE         = 0x04;

void Sha256(std::initializer_list<std::pair<const unsigned char*, size_t>> parts,
            unsigned char out[32]) {
    CSHA256 hasher;
    for (const auto& p : parts) hasher.Write(p.first, p.second);
    hasher.Finalize(out);
}

// ECVRF_hash_to_curve (try-and-increment, RFC 9381 §5.4.1.2 style).
// Expected number of iterations ~2 (each candidate x-coordinate is on the
// curve with probability ~1/2). 255 tries makes total failure probability
// negligible (~2^-255) rather than a hard cap that could plausibly bite.
bool HashToCurve(const unsigned char pk[OPOI_VRF_PK_SIZE],
                  const unsigned char* alpha, size_t alphaLen,
                  secp256k1_pubkey& hOut) {
    unsigned char candidate[33];
    candidate[0] = 0x02; // even-y compressed point prefix
    for (unsigned int ctr = 0; ctr < 255; ctr++) {
        unsigned char ctrByte = (unsigned char)ctr;
        unsigned char zero = 0x00;
        unsigned char h[32];
        Sha256({ {&SUITE, 1}, {&DOM_HASH_TO_CURVE, 1}, {pk, OPOI_VRF_PK_SIZE},
                 {alpha, alphaLen}, {&ctrByte, 1}, {&zero, 1} }, h);
        memcpy(candidate + 1, h, 32);
        if (secp256k1_ec_pubkey_parse(g_vrfCtx, &hOut, candidate, 33)) return true;
    }
    return false;
}

void SerializeCompressed(const secp256k1_pubkey& pk, unsigned char out[33]) {
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(g_vrfCtx, out, &len, &pk, SECP256K1_EC_COMPRESSED);
    assert(len == 33);
}

// ECVRF_challenge_generation (RFC 9381 §5.4.3 style) — truncated to 16 bytes,
// matching the widely-used TAI-variant convention (half the group's byte size).
void Challenge(const secp256k1_pubkey& H, const secp256k1_pubkey& Gamma,
               const secp256k1_pubkey& U, const secp256k1_pubkey& V,
               unsigned char c[16]) {
    unsigned char hB[33], gB[33], uB[33], vB[33];
    SerializeCompressed(H, hB); SerializeCompressed(Gamma, gB);
    SerializeCompressed(U, uB); SerializeCompressed(V, vB);
    unsigned char zero = 0x00;
    unsigned char full[32];
    Sha256({ {&SUITE, 1}, {&DOM_CHALLENGE, 1}, {hB, 33}, {gB, 33},
             {uB, 33}, {vB, 33}, {&zero, 1} }, full);
    memcpy(c, full, 16);
}

// Deterministic nonce, RFC6979-flavored: rehash until pubkey_create accepts
// it as a valid nonzero scalar < group order (that check is exactly what
// secp256k1_ec_pubkey_create's return value already gives us for free).
bool GenerateNonce(const unsigned char sk[32], const secp256k1_pubkey& H,
                    unsigned char k[32]) {
    unsigned char hB[33];
    SerializeCompressed(H, hB);
    unsigned char zero = 0x00;
    Sha256({ {&SUITE, 1}, {&DOM_NONCE, 1}, {sk, 32}, {hB, 33}, {&zero, 1} }, k);
    secp256k1_pubkey dummy;
    for (int i = 0; i < 16; i++) {
        if (secp256k1_ec_pubkey_create(g_vrfCtx, &dummy, k)) return true;
        Sha256({ {k, 32} }, k); // extremely unlikely path — rehash and retry
    }
    return false;
}

// c is 128 bits; left-pad to a 32-byte big-endian scalar for tweak_mul/add.
void PadChallenge(const unsigned char c[16], unsigned char out[32]) {
    memset(out, 0, 16);
    memcpy(out + 16, c, 16);
}

} // namespace

void OPoIVRFStart() {
    assert(g_vrfCtx == nullptr);
    g_vrfCtx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

void OPoIVRFStop() {
    if (g_vrfCtx) {
        secp256k1_context_destroy(g_vrfCtx);
        g_vrfCtx = nullptr;
    }
}

bool OPoIVRFProve(const unsigned char sk[32], const unsigned char pk[OPOI_VRF_PK_SIZE],
                   const unsigned char* alpha, size_t alphaLen,
                   std::vector<unsigned char>& proofOut) {
    // Defensive: reject if pk doesn't actually correspond to sk.
    secp256k1_pubkey derivedPk;
    if (!secp256k1_ec_pubkey_create(g_vrfCtx, &derivedPk, sk)) return false;
    unsigned char derivedPkBytes[33];
    SerializeCompressed(derivedPk, derivedPkBytes);
    if (memcmp(derivedPkBytes, pk, 33) != 0) return false;

    secp256k1_pubkey H;
    if (!HashToCurve(pk, alpha, alphaLen, H)) return false;

    secp256k1_pubkey Gamma = H;
    if (!secp256k1_ec_pubkey_tweak_mul(g_vrfCtx, &Gamma, sk)) return false;

    unsigned char k[32];
    if (!GenerateNonce(sk, H, k)) return false;

    secp256k1_pubkey U;
    if (!secp256k1_ec_pubkey_create(g_vrfCtx, &U, k)) return false;

    secp256k1_pubkey V = H;
    if (!secp256k1_ec_pubkey_tweak_mul(g_vrfCtx, &V, k)) return false;

    unsigned char c[16];
    Challenge(H, Gamma, U, V, c);

    unsigned char cScalar[32];
    PadChallenge(c, cScalar);

    unsigned char tmp[32];
    memcpy(tmp, sk, 32);
    if (!secp256k1_ec_privkey_tweak_mul(g_vrfCtx, tmp, cScalar)) return false;
    unsigned char s[32];
    memcpy(s, k, 32);
    if (!secp256k1_ec_privkey_tweak_add(g_vrfCtx, s, tmp)) return false;

    proofOut.resize(OPOI_VRF_PROOF_SIZE);
    unsigned char gammaBytes[33];
    SerializeCompressed(Gamma, gammaBytes);
    memcpy(proofOut.data(), gammaBytes, 33);
    memcpy(proofOut.data() + 33, c, 16);
    memcpy(proofOut.data() + 49, s, 32);
    return true;
}

bool OPoIVRFVerify(const unsigned char pk[OPOI_VRF_PK_SIZE],
                    const unsigned char* alpha, size_t alphaLen,
                    const std::vector<unsigned char>& proof,
                    unsigned char output[OPOI_VRF_OUTPUT_SIZE]) {
    if (proof.size() != OPOI_VRF_PROOF_SIZE) return false;

    secp256k1_pubkey Gamma;
    if (!secp256k1_ec_pubkey_parse(g_vrfCtx, &Gamma, proof.data(), 33)) return false;
    unsigned char c[16];
    memcpy(c, proof.data() + 33, 16);
    unsigned char s[32];
    memcpy(s, proof.data() + 49, 32);

    secp256k1_pubkey pkParsed;
    if (!secp256k1_ec_pubkey_parse(g_vrfCtx, &pkParsed, pk, OPOI_VRF_PK_SIZE)) return false;

    secp256k1_pubkey H;
    if (!HashToCurve(pk, alpha, alphaLen, H)) return false;

    unsigned char cScalar[32];
    PadChallenge(c, cScalar);

    // U = s*G - c*pk
    secp256k1_pubkey sG;
    if (!secp256k1_ec_pubkey_create(g_vrfCtx, &sG, s)) return false;
    secp256k1_pubkey cPk = pkParsed;
    if (!secp256k1_ec_pubkey_tweak_mul(g_vrfCtx, &cPk, cScalar)) return false;
    if (!secp256k1_ec_pubkey_negate(g_vrfCtx, &cPk)) return false;
    secp256k1_pubkey U;
    {
        const secp256k1_pubkey* ins[2] = { &sG, &cPk };
        if (!secp256k1_ec_pubkey_combine(g_vrfCtx, &U, ins, 2)) return false;
    }

    // V = s*H - c*Gamma
    secp256k1_pubkey sH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(g_vrfCtx, &sH, s)) return false;
    secp256k1_pubkey cGamma = Gamma;
    if (!secp256k1_ec_pubkey_tweak_mul(g_vrfCtx, &cGamma, cScalar)) return false;
    if (!secp256k1_ec_pubkey_negate(g_vrfCtx, &cGamma)) return false;
    secp256k1_pubkey V;
    {
        const secp256k1_pubkey* ins[2] = { &sH, &cGamma };
        if (!secp256k1_ec_pubkey_combine(g_vrfCtx, &V, ins, 2)) return false;
    }

    unsigned char cPrime[16];
    Challenge(H, Gamma, U, V, cPrime);
    if (memcmp(c, cPrime, 16) != 0) return false;

    unsigned char gammaBytes[33];
    SerializeCompressed(Gamma, gammaBytes);
    unsigned char zero = 0x00;
    Sha256({ {&SUITE, 1}, {&DOM_PROOF_TO_HASH, 1}, {gammaBytes, 33}, {&zero, 1} }, output);
    return true;
}
