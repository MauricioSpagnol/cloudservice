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
#include <utility>
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
static inline std::vector<std::pair<uint32_t, uint32_t>> SplitLayerRanges(uint32_t numLayers,
                                                                           uint32_t numShards)
{
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    if (numShards == 0) return ranges;
    ranges.reserve(numShards);
    uint32_t base      = numLayers / numShards;
    uint32_t remainder = numLayers % numShards;
    uint32_t cursor    = 0;
    for (uint32_t i = 0; i < numShards; i++) {
        uint32_t size = base + (i < remainder ? 1 : 0); // distribute remainder to the first shards
        ranges.push_back({cursor, cursor + size});
        cursor += size;
    }
    return ranges;
}

// D2 (2026-07-26): MoE/HYBRID (m.IsMoE()) real per-(layer_range, expert_id)
// dispatch. Earlier interim scope (B1, 2026-07-24/25) ran the ENTIRE MoE
// model on one miner as a single DENSE-typed shard, because a static
// per-expert shard node can only ever gate on a proxy for what the real
// router picked (see the old SelectTopKExperts placeholder below) — no way
// existed yet to verify a distributed per-expert split was honest. That gap
// is closed by moving routing-choice verification OFF-CHAIN: an Auditor
// replica re-runs its own router over the same input and checks the
// primary's committed choice (routerLogitsHash) is within an acceptable
// margin (routing-trace-pinned model — see CS COIN OPoI MELHOR
// IMPLEMENTAÇÃO.txt, "ESCOPO DE IMPLEMENTAÇÃO DO D2"), the exact same
// margin/quantization scheme already used for the B1/B3-lite dense path.
// Disputes resolve via the existing AuditorVerification/
// ComputeAuditorMajority majority mechanism (opoi.h ~604-631) — no new
// on-chain consensus primitive was needed.
//
// Layout: split numLayers into layer ranges exactly like the DENSE-only
// branch below (a MoE model still runs attention/router/norms per layer
// range as ordinary DENSE compute — only the FFN is expert-routed); then,
// for each range in order, emit one EXPERT node per expert (0..numExperts)
// scoped to that range. Dense shards are ordered first across all ranges
// (matching ShardDescriptor's doc comment above), then experts grouped by
// range in the same order as their enclosing dense shard. Total nodes =
// numDenseShards + numDenseShards * numExperts.
//
// numDenseShards==0 is possible for a manifest registered before this
// change (the field went unused for MoE previously) — treated as 1 range
// covering the whole model rather than silently returning an empty graph,
// so an old registration doesn't regress to "no shards at all".
//
// SelectTopKExperts/OPOI_SHARD_EXPERT below are no longer unreachable via
// this function, but SelectTopKExperts itself is NOT called from
// CheckOPoITransaction's EXPERT branch anymore (see opoi.cpp) — routing
// selection is verified off-chain now, as above.
// F9-G/F15-M: `collapseToTitanSingleNode` — computed by the caller via
// opoi.h's ShouldCollapseToTitanSingleNode(manifest, params) — makes a DENSE
// model with a real multi-shard split collapse to a single whole-model
// shard when a titan host is preferred over a distributed constellation
// (see that function's doc comment for the exact conditions and
// consensus-safety reasoning). ShouldCollapseToTitanSingleNode always
// returns false for MoE/HYBRID manifests (archType != DENSE), so real call
// sites never pass true for a MoE model — this parameter is honored as-is
// (still collapses if a caller ever does) purely for parity with the DENSE
// path. Default false keeps every existing call site's behavior
// byte-identical unless it explicitly opts in.
inline std::vector<ShardDescriptor> BuildModelExecutionGraph(const ModelManifest& m,
                                                              bool collapseToTitanSingleNode = false)
{
    std::vector<ShardDescriptor> graph;
    if (m.numLayers == 0) return graph;

    if (collapseToTitanSingleNode) {
        ShardDescriptor d;
        d.shardIndex = 0;
        d.shardType  = OPOI_SHARD_DENSE;
        d.layerStart = 0;
        d.layerEnd   = m.numLayers;
        d.expertId   = 0;
        graph.push_back(d);
        return graph;
    }

    if (m.IsMoE()) {
        uint32_t denseShards = (m.numDenseShards > 0) ? m.numDenseShards : 1;
        auto ranges = SplitLayerRanges(m.numLayers, denseShards);

        uint32_t shardIndex = 0;
        for (uint32_t i = 0; i < denseShards; i++) {
            ShardDescriptor d;
            d.shardIndex = shardIndex++;
            d.shardType  = OPOI_SHARD_DENSE;
            d.layerStart = ranges[i].first;
            d.layerEnd   = ranges[i].second;
            d.expertId   = 0;
            graph.push_back(d);
        }
        for (uint32_t i = 0; i < denseShards; i++) {
            for (uint32_t e = 0; e < m.numExperts; e++) {
                ShardDescriptor d;
                d.shardIndex = shardIndex++;
                d.shardType  = OPOI_SHARD_EXPERT;
                d.layerStart = ranges[i].first;
                d.layerEnd   = ranges[i].second;
                d.expertId   = e;
                graph.push_back(d);
            }
        }
        return graph;
    }

    if (m.numDenseShards == 0) return graph;
    auto ranges = SplitLayerRanges(m.numLayers, m.numDenseShards);
    for (uint32_t i = 0; i < m.numDenseShards; i++) {
        ShardDescriptor d;
        d.shardIndex = i;
        d.shardType  = OPOI_SHARD_DENSE;
        d.layerStart = ranges[i].first;
        d.layerEnd   = ranges[i].second;
        d.expertId   = 0;
        graph.push_back(d);
    }
    return graph;
}

// D2: defense-in-depth bounds check for an EXPERT ShardDescriptor against
// its manifest. `d` is always derived straight from `m` by
// BuildModelExecutionGraph above (expertId is always < m.numExperts,
// layerStart/layerEnd always fall inside [0, m.numLayers) by construction),
// so this should never fail in practice — but CheckOPoITransaction is
// consensus-critical code, and it consumes `d` at a distance from where it
// was built (via g_opoiCache.GetModelManifest + a freshly recomputed MEG),
// so it re-validates the invariant explicitly here rather than silently
// trusting it forever. Only meaningful for shardType == OPOI_SHARD_EXPERT.
inline bool IsExpertShardWithinManifestBounds(const ShardDescriptor& d, const ModelManifest& m)
{
    if (d.expertId >= m.numExperts) return false;
    if (d.layerEnd > m.numLayers) return false;
    if (d.layerStart >= d.layerEnd) return false;
    return true;
}

// D2 routing-trace dispute (2026-07-26): bounds-check a shard-scoped
// AuditorVerification's target shardIndex against a model's MEG — the exact
// same "does this index exist in the graph" check CheckOPoITransaction's
// SHARD_RESULT branch already does inline (`tx.opoiShardIndex >= meg.size()`
// in opoi.cpp), extracted into its own pure function here so
// AUDITOR_VERIFY_TX_TYPE's new shard-scoped branch can reuse it verbatim —
// and, just as importantly, so it is directly unit-testable
// (src/test/opoi_tests.cpp) the same way IsExpertShardWithinManifestBounds
// above already is: CheckOPoITransaction itself needs a live
// chain/mempool/signature setup this test file deliberately doesn't build
// (see its header comment on scope).
//
// Deliberately has no opinion on OPOI_AUDITOR_VERIFY_NO_SHARD (the
// whole-response sentinel, declared in primitives/transaction.h) — that
// branch belongs at the call site (CheckOPoITransaction's AUDITOR_VERIFY
// case), not here, so this function stays a plain "is this index in range"
// check with no dependency on transaction.h.
inline bool IsAuditorVerificationShardIndexValid(uint32_t shardIndex, const ModelManifest& m,
                                                 bool collapseToTitanSingleNode)
{
    auto meg = BuildModelExecutionGraph(m, collapseToTitanSingleNode);
    return shardIndex < meg.size();
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
// B2 investigation (2026-07-24, see CS COIN OPoI MELHOR IMPLEMENTAÇÃO.txt)
// measured this hash-proxy's agreement with a real trained router at 7.2%
// token/layer exact-match — WORSE than the 16.7% random baseline for that
// experiment's (numExperts=4, topK=2) shape. It is not a usable stand-in for
// real routing. D2 (2026-07-26) made BuildModelExecutionGraph emit real
// OPOI_SHARD_EXPERT nodes again (see its doc comment), but deliberately does
// NOT call this function from CheckOPoITransaction's EXPERT branch to gate
// them — doing so would reject the overwhelming majority of legitimate
// EXPERT submissions. Routing-choice correctness is now verified OFF-CHAIN
// instead, by Auditor replicas re-running their own router and checking the
// primary's committed choice (routerLogitsHash) is within an acceptable
// margin (routing-trace-pinned model, same doc section); disputes resolve
// via the existing AuditorVerification/ComputeAuditorMajority mechanism.
// Left in place, not deleted: real, cross-verified (Rust expert_router.rs)
// consensus code a future per-layer distributed MoE redesign might still
// want, not unused debris from an abandoned attempt — just intentionally
// uncalled from the consensus validation path today.
//
// This stands in for a real router (a DenseShard boundary computing actual
// top-k logits over model weights) — no such runtime exists yet on either
// side of this codebase.
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
