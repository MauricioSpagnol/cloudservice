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

#include <algorithm>
#include <array>
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
//
// MoE/HYBRID (m.IsMoE()): a real MoE forward pass routes per-layer, per-token
// (see cs-miner's shard_model_moe.rs doc comment) — there is no way to split
// that across network boundaries into "N dense shards + one shard per
// expert" the way the DENSE case above does; a static per-expert shard node
// can only ever gate on a proxy for what the real router picked (see the old
// SelectTopKExperts placeholder below), never the real per-token decision.
// Current scope (interim, until a real per-layer distributed MoE redesign):
// one miner runs the ENTIRE MoE model — embedding through every layer's real
// router+experts through the output — as a single DENSE-typed shard covering
// [0, numLayers). numDenseShards/numExperts/topKExperts stay on the
// manifest (still validated at MODEL_REGISTER) but are unused here; N-of-M
// consensus over this one shard is the exact same mechanism a DENSE model's
// shard already uses, so no new consensus code path was needed for this.
// This does give up the "MoE hardware doesn't scale with total model size"
// thesis for MoE specifically (a MoE checkpoint must now fit one miner) —
// dense pipeline-parallelism above is unaffected and still delivers that for
// dense architectures. SelectTopKExperts/OPOI_SHARD_EXPERT below are now
// unreachable via this function (kept, not deleted: real, tested consensus
// code a future per-layer MoE redesign would build on, not dead weight).
// F9-G/F15-M: `collapseToTitanSingleNode` — computed by the caller via
// opoi.h's ShouldCollapseToTitanSingleNode(manifest, params) — makes a DENSE
// model with a real multi-shard split collapse to the same single
// whole-model shard the MoE branch below already always uses, when a titan
// host is preferred over a distributed constellation (see that function's
// doc comment for the exact conditions and consensus-safety reasoning).
// Default false keeps every existing call site's behavior byte-identical
// unless it explicitly opts in.
inline std::vector<ShardDescriptor> BuildModelExecutionGraph(const ModelManifest& m,
                                                              bool collapseToTitanSingleNode = false)
{
    std::vector<ShardDescriptor> graph;
    if (m.numLayers == 0) return graph;

    if (m.IsMoE() || collapseToTitanSingleNode) {
        ShardDescriptor d;
        d.shardIndex = 0;
        d.shardType  = OPOI_SHARD_DENSE;
        d.layerStart = 0;
        d.layerEnd   = m.numLayers;
        d.expertId   = 0;
        graph.push_back(d);
        return graph;
    }

    if (m.numDenseShards == 0) return graph;
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

// F15-H (real MoE routing, first slice): deterministically selects which
// `topK` of `numExperts` are "active" for a given (requestId, promptHash).
//
// Currently unreachable: BuildModelExecutionGraph no longer emits
// OPOI_SHARD_EXPERT nodes (see its doc comment — MoE now runs whole-model on
// one miner as a single DENSE-typed shard), so CheckOPoITransaction's
// `d.shardType == OPOI_SHARD_EXPERT` branch below that calls this can never
// trigger via that path. Left in place, not deleted: real, cross-verified
// (Rust expert_router.rs) consensus code a future per-layer distributed MoE
// redesign would need again, not unused debris from an abandoned attempt.
//
// This stands in for a real router (a DenseShard boundary computing actual
// top-k logits over model weights) — no such runtime exists yet on either
// side of this codebase. It is still consensus-relevant: every node MUST
// compute the identical selection, because it gates which EXPERT shard
// submissions are valid (see F15-E's hosting gate, extended here to also
// require the expert be selected, not merely hosted). cs-miner mirrors this
// exact algorithm in Rust (expert_router.rs) so it only attempts shards that
// will actually be accepted.
//
// Algorithm: hash (requestId || promptHash || "EXPERT"+i) for each candidate
// expert i, sort ascending by the raw 32-byte digest (plain lexicographic
// byte comparison — deliberately NOT uint256::operator<, whose internal byte
// order is an implementation detail; a fixed-size byte array's ordering is
// trivial to replicate identically in Rust), take the first topK.
inline std::vector<uint32_t> SelectTopKExperts(const std::string& requestId, const uint256& promptHash,
                                                uint32_t numExperts, uint32_t topK)
{
    std::vector<std::pair<std::array<unsigned char, 32>, uint32_t>> scored;
    scored.reserve(numExperts);
    for (uint32_t i = 0; i < numExperts; i++) {
        CSHA256 hasher;
        hasher.Write((const unsigned char*)requestId.data(), requestId.size());
        hasher.Write(promptHash.begin(), 32);
        std::string suffix = "EXPERT" + std::to_string(i);
        hasher.Write((const unsigned char*)suffix.data(), suffix.size());
        std::array<unsigned char, 32> digest;
        hasher.Finalize(digest.data());
        scored.push_back({digest, i});
    }
    typedef std::pair<std::array<unsigned char, 32>, uint32_t> ScoredExpert;
    std::sort(scored.begin(), scored.end(),
              [](const ScoredExpert& a, const ScoredExpert& b) { return a.first < b.first; });

    std::vector<uint32_t> result;
    uint32_t n = std::min(topK, numExperts);
    result.reserve(n);
    for (uint32_t i = 0; i < n; i++) result.push_back(scored[i].second);
    return result;
}

#endif // CSCOIN_OPOI_SHARD_H
