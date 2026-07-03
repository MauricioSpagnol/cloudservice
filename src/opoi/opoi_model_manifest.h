// Copyright (c) 2026 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// F15-A: Model Manifest — generic on-chain registration of an OPoI-minable
// model (dense, MoE or hybrid). Generalizes the old F9-A single-pomRoot-per-tier
// scheme so that new models (including architectures that don't exist yet) can
// be added via stake-weighted vote instead of a hard-fork per model.
//
// F15-A2: governance — proposal + stake-weighted voting window before a
// manifest can activate.

#ifndef CSCOIN_OPOI_MODEL_MANIFEST_H
#define CSCOIN_OPOI_MODEL_MANIFEST_H

#include <string>
#include <vector>
#include "serialize.h"
#include "uint256.h"
#include "amount.h"

// Architecture types
static const uint8_t OPOI_ARCH_DENSE  = 0; // sequential dense transformer (original F9 tiers)
static const uint8_t OPOI_ARCH_MOE    = 1; // Mixture-of-Experts — needs expert shards (F15-E)
static const uint8_t OPOI_ARCH_HYBRID = 2; // dense backbone + some MoE layers

// Governance status
static const int8_t OPOI_MODEL_STATUS_VOTING   = 1; // voting window open
static const int8_t OPOI_MODEL_STATUS_APPROVED = 2; // approved, waiting for activationHeight
static const int8_t OPOI_MODEL_STATUS_ACTIVE   = 3; // activationHeight reached — minable
static const int8_t OPOI_MODEL_STATUS_REJECTED = 4; // quorum/approval not reached

struct ModelManifest {
    std::string modelId;
    uint8_t     archType;
    uint64_t    totalParams;             // informative — total parameter count
    uint64_t    activeParamsPerToken;    // determines reward tier
    uint32_t    numLayers;
    uint32_t    numDenseShards;          // F15-B: how many pipeline stages split numLayers into
    uint32_t    numExperts;              // 0 if DENSE
    uint32_t    topKExperts;             // experts active per token (0 if DENSE)
    uint256     backbonePomRoot;         // Merkle root of dense/backbone weights
    std::vector<uint256> expertPomRoots; // one root per expert (empty if DENSE)
    CAmount     minRewardPerToken;
    std::string proposer;
    uint32_t    proposedHeight;
    uint32_t    voteWindowEndHeight;
    uint32_t    activationHeight;        // 0 until APPROVED
    uint256     txHash;
    int8_t      status;
    // F15-B: NOT read from the tx — always recomputed from the fields above via
    // ComputeShardTopologyHash() (opoi_shard.h) so no proposer input is trusted.
    // Cached here purely so RPCs don't need to recompute it on every read.
    uint256     shardTopologyHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(modelId); READWRITE(archType);
        READWRITE(totalParams); READWRITE(activeParamsPerToken);
        READWRITE(numLayers); READWRITE(numDenseShards);
        READWRITE(numExperts); READWRITE(topKExperts);
        READWRITE(backbonePomRoot); READWRITE(expertPomRoots);
        READWRITE(minRewardPerToken);
        READWRITE(proposer); READWRITE(proposedHeight);
        READWRITE(voteWindowEndHeight); READWRITE(activationHeight);
        READWRITE(txHash); READWRITE(status); READWRITE(shardTopologyHash);
    }

    void SetNull() {
        modelId.clear(); archType = OPOI_ARCH_DENSE;
        totalParams = 0; activeParamsPerToken = 0;
        numLayers = 0; numDenseShards = 0; numExperts = 0; topKExperts = 0;
        backbonePomRoot.SetNull(); expertPomRoots.clear();
        minRewardPerToken = 0;
        proposer.clear(); proposedHeight = 0;
        voteWindowEndHeight = 0; activationHeight = 0;
        txHash.SetNull(); status = OPOI_MODEL_STATUS_VOTING;
        shardTopologyHash.SetNull();
    }
    bool IsNull()     const { return modelId.empty(); }
    bool IsMoE()      const { return archType == OPOI_ARCH_MOE || archType == OPOI_ARCH_HYBRID; }
    bool IsVoting()   const { return status == OPOI_MODEL_STATUS_VOTING; }
    bool IsApproved() const { return status == OPOI_MODEL_STATUS_APPROVED; }
    bool IsActive()   const { return status == OPOI_MODEL_STATUS_ACTIVE; }
    bool IsRejected() const { return status == OPOI_MODEL_STATUS_REJECTED; }
};

// One vote cast on a ModelManifest. Weight = voter's ACTIVE OPoI stake amount
// at the time the vote was cast (re-voting overwrites the previous record).
struct ModelVoteRecord {
    std::string voterAddress;
    bool        approve;
    CAmount     weight;
    uint32_t    blockHeight;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(voterAddress); READWRITE(approve); READWRITE(weight); READWRITE(blockHeight);
    }
};

#endif // CSCOIN_OPOI_MODEL_MANIFEST_H
