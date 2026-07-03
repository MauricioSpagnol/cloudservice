// Copyright (c) 2026 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// F15-B: Model Execution Graph (MEG) — generalizes the old fixed pipeline
// ("camadas 1-135 / 136-270 / ...") to cover both dense pipeline-parallelism
// and MoE expert-parallelism.
//
// The MEG is never transmitted on-chain shard-by-shard: it is fully
// deterministic given a ModelManifest, so every node (and every miner)
// computes the identical graph locally via BuildModelExecutionGraph().
// Only shardTopologyHash — a commitment to that graph — is cached on-chain
// (in ModelManifest), so any node can verify a given implementation used the
// canonical split rather than inventing its own.

#ifndef CSCOIN_OPOI_SHARD_H
#define CSCOIN_OPOI_SHARD_H

#include <string>
#include <vector>
#include "uint256.h"
#include "hash.h"
#include "utilstrencodings.h"
#include "opoi_model_manifest.h"

static const uint8_t OPOI_SHARD_DENSE  = 0;
static const uint8_t OPOI_SHARD_EXPERT = 1;

// One node of the Model Execution Graph.
// DENSE shard  : always executed, covers layers [layerStart, layerEnd).
// EXPERT shard : only executed if the preceding DENSE shard's router selects
//                expertId for a given token (see F15-E).
struct ShardDescriptor {
    uint32_t shardIndex;   // position in the graph (dense shards ordered first, then experts)
    uint8_t  shardType;    // OPOI_SHARD_DENSE or OPOI_SHARD_EXPERT
    uint32_t layerStart;   // inclusive — valid for DENSE
    uint32_t layerEnd;     // exclusive — valid for DENSE
    uint32_t expertId;     // valid for EXPERT (0 for DENSE)
};

// Splits numLayers as evenly as possible across numDenseShards stages.
// e.g. numLayers=56, numDenseShards=4 -> [0,14) [14,28) [28,42) [42,56)
//      numLayers=10, numDenseShards=3 -> [0,4) [4,7) [7,10)  (remainder to earlier shards)
inline std::vector<ShardDescriptor> BuildModelExecutionGraph(const ModelManifest& m)
{
    std::vector<ShardDescriptor> graph;
    if (m.numLayers == 0 || m.numDenseShards == 0) return graph;

    uint32_t base      = m.numLayers / m.numDenseShards;
    uint32_t remainder = m.numLayers % m.numDenseShards;
    uint32_t cursor    = 0;
    for (uint32_t i = 0; i < m.numDenseShards; i++) {
        uint32_t size = base + (i < remainder ? 1 : 0); // distribute remainder to the first shards
        ShardDescriptor d;
        d.shardIndex = i;
        d.shardType  = OPOI_SHARD_DENSE;
        d.layerStart = cursor;
        d.layerEnd   = cursor + size;
        d.expertId   = 0;
        graph.push_back(d);
        cursor += size;
    }

    if (m.IsMoE()) {
        for (uint32_t e = 0; e < m.numExperts; e++) {
            ShardDescriptor d;
            d.shardIndex = m.numDenseShards + e;
            d.shardType  = OPOI_SHARD_EXPERT;
            d.layerStart = 0;
            d.layerEnd   = 0;
            d.expertId   = e;
            graph.push_back(d);
        }
    }
    return graph;
}

// Deterministic commitment to the graph shape. Any node with the same
// ModelManifest fields computes the identical hash — nothing here depends on
// data supplied only by the proposer, so there is nothing to "fake".
inline uint256 ComputeShardTopologyHash(const ModelManifest& m)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << m.archType << m.numLayers << m.numDenseShards << m.numExperts << m.topKExperts;
    return ss.GetHash();
}

#endif // CSCOIN_OPOI_SHARD_H
