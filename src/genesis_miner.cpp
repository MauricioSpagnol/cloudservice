// Genesis block miner for CS Coin
// Computes a valid Equihash(200,9) solution for the genesis block header.
//
// Build: g++ -O2 -std=c++11 -I. -I../depends/x86_64-unknown-linux-gnu/include \
//            genesis_miner.cpp crypto/equihash.cpp -L../depends/x86_64-unknown-linux-gnu/lib \
//            -lsodium -o genesis_miner
//
// Run:   ./genesis_miner

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <openssl/sha.h>
#include <sodium.h>

#include "crypto/equihash.h"

// Stubs for logging functions used by equihash.cpp
bool LogAcceptCategory(const char*) { return false; }
void LogPrintStr(const std::string&) {}

// ── Helpers ──────────────────────────────────────────────────────────────────

static void writeLE32(uint8_t* p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}

static void writeLE64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) { p[i] = v & 0xff; v >>= 8; }
}

static std::string toHex(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        s += hex[(data[i] >> 4) & 0xf];
        s += hex[data[i] & 0xf];
    }
    return s;
}

// Parse 64-char little-endian hex into 32-byte array (reversed for display)
static void parseHashLE(const char* hex_be, uint8_t out[32]) {
    // Input is big-endian display hex; store as little-endian bytes
    uint8_t tmp[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(hex_be + i * 2, "%02x", &byte);
        tmp[i] = (uint8_t)byte;
    }
    // reverse for LE storage
    for (int i = 0; i < 32; i++) out[i] = tmp[31 - i];
}

// arith comparison: does hash (LE 32 bytes) satisfy target (compact nBits)?
static bool meetsTarget(const uint8_t* hash_le, uint32_t nBits) {
    uint32_t nSize = nBits >> 24;
    uint32_t nWord = nBits & 0x007fffff;
    // target bytes (LE), 32 bytes
    uint8_t target[32] = {};
    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        target[0] = nWord & 0xff;
        target[1] = (nWord >> 8) & 0xff;
        target[2] = (nWord >> 16) & 0xff;
    } else {
        int pos = nSize - 3;
        if (pos < 32) target[pos]     =  nWord & 0xff;
        if (pos+1 < 32) target[pos+1] = (nWord >> 8) & 0xff;
        if (pos+2 < 32) target[pos+2] = (nWord >> 16) & 0xff;
    }
    // compare big-endian (hash[31] is most significant byte in LE)
    for (int i = 31; i >= 0; i--) {
        if (hash_le[i] < target[i]) return true;
        if (hash_le[i] > target[i]) return false;
    }
    return true; // equal
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main() {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    // ── Genesis parameters (CS Coin mainnet) ──────────────────────────────
    const uint32_t nVersion  = 4;
    const uint32_t nTime     = 1735430400;   // Dez 2025
    const uint32_t nBits     = 0x200f0f0f; // dificuldade facil para genesis CPU

    // hashPrevBlock = 0
    uint8_t hashPrevBlock[32]      = {};

    // hashMerkleRoot (big-endian display → LE storage)
    uint8_t hashMerkleRoot[32];
    parseHashLE("7386f05bb7b294e209b582dd3f2f4e307b45b96441da9e3b6bc2531fe38612d4",
                hashMerkleRoot);

    // hashFinalSaplingRoot = 0
    uint8_t hashFinalSaplingRoot[32] = {};

    // Equihash parameters for mainnet
    const unsigned int N = 200, K = 9;

    printf("CS Coin Genesis Miner\n");
    printf("Equihash(%u,%u)  nBits=0x%08x  nTime=%u\n\n", N, K, nBits, nTime);
    fflush(stdout);

    // Build fixed part of the equihash input (108 bytes, without nNonce)
    // Serialization order (LE): nVersion | hashPrevBlock | hashMerkleRoot |
    //                           hashFinalSaplingRoot | nTime | nBits
    uint8_t header_fixed[108];
    uint8_t* p = header_fixed;
    writeLE32(p, nVersion);          p += 4;
    memcpy(p, hashPrevBlock, 32);    p += 32;
    memcpy(p, hashMerkleRoot, 32);   p += 32;
    memcpy(p, hashFinalSaplingRoot, 32); p += 32;
    writeLE32(p, nTime);             p += 4;
    writeLE32(p, nBits);             p += 4;
    // p == header_fixed + 108

    // Iterate nNonce values until we find a valid block
    uint64_t nonce_counter = 0;
    uint8_t nNonce[32] = {};

    while (true) {
        // encode nonce_counter into nNonce bytes 0..7 (LE)
        writeLE64(nNonce, nonce_counter);

        // Initialize Blake2b state with the 108-byte fixed header
        crypto_generichash_blake2b_state base_state;
        EhInitialiseState(N, K, base_state);
        crypto_generichash_blake2b_update(&base_state, header_fixed, 108);

        // Append nNonce
        crypto_generichash_blake2b_state curr_state = base_state;
        crypto_generichash_blake2b_update(&curr_state, nNonce, 32);

        bool found = false;

        // validBlock callback: validates equihash solution AND block hash vs target
        std::function<bool(std::vector<unsigned char>)> validBlock =
            [&](std::vector<unsigned char> soln) -> bool {
                // Full serialized header for SHA256d block hash:
                // header_fixed(108) | nNonce(32) | compact_size | soln
                std::vector<uint8_t> ser;
                ser.reserve(108 + 32 + 3 + soln.size());
                ser.insert(ser.end(), header_fixed, header_fixed + 108);
                ser.insert(ser.end(), nNonce, nNonce + 32);
                size_t slen = soln.size();
                if (slen < 253) {
                    ser.push_back((uint8_t)slen);
                } else {
                    ser.push_back(253);
                    ser.push_back(slen & 0xff);
                    ser.push_back((slen >> 8) & 0xff);
                }
                ser.insert(ser.end(), soln.begin(), soln.end());
                // SHA256d
                uint8_t h1[32], h2[32];
                SHA256(ser.data(), ser.size(), h1);
                SHA256(h1, 32, h2);
                // h2 is LE; check against nBits target
                if (!meetsTarget(h2, nBits)) return false;

                printf("\n[!] VALID GENESIS FOUND!\n");
                printf("Block hash (LE): %s\n", toHex(h2, 32).c_str());
                printf("nNonce (hex LE): %s\n", toHex(nNonce, 32).c_str());
                printf("nSolution (hex): ");
                for (auto b : soln) printf("%02x", (unsigned char)b);
                printf("\n");
                fflush(stdout);
                found = true;
                return true;
            };

        std::function<bool(EhSolverCancelCheck)> cancelled =
            [](EhSolverCancelCheck) -> bool { return false; };

        EhOptimisedSolve(N, K, curr_state, validBlock, cancelled);

        if (found) break;

        nonce_counter++;
        if (nonce_counter % 100 == 0) {
            printf("\rTrying nonce %llu...", (unsigned long long)nonce_counter);
            fflush(stdout);
        }
    }

    return 0;
}
