// Copyright (c) 2026 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the OPoI (Optimistic Proof of Inference) payment/majority
// logic (opoi/opoi.h, opoi/opoi.cpp).
//
// Context: every OPoI feature in this codebase has, until now, only ever
// been exercised via live regtest (real blocks, real RPC calls, real
// wall-clock time). This file adds fast, in-process Boost.Test coverage for
// the PURE, testable-without-a-live-chain logic — primarily
// GetShardPaymentsForBlock (the F16 shard payment splitter, the specific
// gap named by the "CheckOPoIPayments: zero blocos aceitos com payment
// errado" checklist item in CS COIN OPoI MELHOR IMPLEMENTAÇÃO.txt) and
// ComputeShardMajority (the pure majority primitive it's built on).
//
// These tests call the real production functions declared in opoi.h
// directly, constructing real CMutableTransaction/OPoIRequest/ModelManifest
// objects and populating g_opoiCache for real (via a fixture that resets it
// before/after each test) — nothing here is a reimplementation or mock of
// the logic under test.

#include "opoi/opoi.h"
#include "opoi/opoi_shard.h"
#include "opoi/opoi_model_manifest.h"
#include "consensus/params.h"
#include "primitives/transaction.h"
#include "amount.h"
#include "uint256.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

// Fixture: g_opoiCache is a process-global (extern OPoICache g_opoiCache;),
// so every test gets a clean slate on entry and leaves a clean slate behind
// it for the next test, exactly what Boost.Test fixtures are for.
struct OPoIPaymentsFixture : public BasicTestingSetup {
    OPoIPaymentsFixture()  { g_opoiCache.SetNull(); }
    ~OPoIPaymentsFixture() { g_opoiCache.SetNull(); }
};

uint256 HashOf(const std::string& label)
{
    return Hash(label.begin(), label.end());
}

// Builds a real SHARD_RESULT CTransaction the way ProcessOPoITransaction /
// GetShardPaymentsForBlock actually expect to read one (nVersion/nType plus
// the exact fields GetShardPaymentsForBlock touches: opoiRequestId,
// opoiShardIndex, opoiMinerAddress, opoiResponseHash, opoiTokenCount).
CTransaction MakeShardResultTx(const std::string& requestId, uint32_t shardIndex,
                                const std::string& minerAddress, const uint256& boundaryHash,
                                uint32_t tokenCount)
{
    CMutableTransaction mtx;
    mtx.nVersion       = OPOI_TX_VERSION;
    mtx.nType          = OPOI_SHARD_RESULT_TX_TYPE;
    mtx.opoiRequestId  = requestId;
    mtx.opoiShardIndex = shardIndex;
    mtx.opoiMinerAddress = minerAddress;
    mtx.opoiResponseHash = boundaryHash;
    mtx.opoiTokenCount   = tokenCount;
    return CTransaction(mtx);
}

// A syntactically-plausible placeholder coinbase — GetShardPaymentsForBlock
// never reads vtx[0], it only ever iterates from index 1, exactly like
// CheckOPoIPayments does for the real coinbase.
CTransaction MakeDummyCoinbase()
{
    CMutableTransaction mtx;
    return CTransaction(mtx);
}

OPoIRequest MakeRequest(const std::string& requestId, const std::string& model,
                        CAmount payment, CAmount feePerToken = 0)
{
    OPoIRequest req;
    req.SetNull();
    req.requestId    = requestId;
    req.requester    = "requester1";
    req.model        = model;
    req.promptHash   = HashOf(requestId + ":prompt");
    req.maxTokens    = 1000;
    req.payment      = payment;
    req.feePerToken  = feePerToken;
    req.taskType     = OPOI_TASK_OPEN;
    req.blockHeight  = 100;
    req.sigTime      = 1234;
    req.txHash       = HashOf(requestId + ":tx");
    req.status       = OPOI_STATUS_FULFILLED;
    return req;
}

// A DENSE, ACTIVE, multi-shard manifest — mirrors the F15-J live-regtest
// scenario documented in CS COIN OPoI MELHOR IMPLEMENTAÇÃO.txt: 9 layers /
// 2 shards -> weights 5:4 (BuildModelExecutionGraph puts the remainder on
// the earlier shards).
ModelManifest MakeDenseManifest(const std::string& modelId, uint32_t numLayers, uint32_t numDenseShards)
{
    ModelManifest m;
    m.SetNull();
    m.modelId        = modelId;
    m.archType        = OPOI_ARCH_DENSE;
    m.totalParams     = 1;
    m.numLayers       = numLayers;
    m.numDenseShards  = numDenseShards;
    m.status          = OPOI_MODEL_STATUS_ACTIVE;
    m.activationHeight = 1;
    return m;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(opoi_tests, OPoIPaymentsFixture)

// ── ComputeShardMajority ──────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(shard_majority_clear_majority)
{
    uint256 hashA = HashOf("A"), hashB = HashOf("B");
    std::vector<ShardResultSubmission> subs;
    subs.push_back({"miner1", hashA, uint256(), 5, 0, uint256()});
    subs.push_back({"miner2", hashA, uint256(), 5, 0, uint256()});
    subs.push_back({"miner3", hashB, uint256(), 5, 0, uint256()});

    uint256 majHash; uint32_t majCount;
    std::vector<std::string> agreeing, divergent;
    bool resolved = ComputeShardMajority(subs, 3, majHash, majCount, agreeing, divergent);

    BOOST_CHECK(resolved);
    BOOST_CHECK(majHash == hashA);
    BOOST_CHECK_EQUAL(majCount, 5u);
    BOOST_CHECK_EQUAL(agreeing.size(), 2u);
    BOOST_CHECK_EQUAL(divergent.size(), 1u);
    BOOST_CHECK(std::find(agreeing.begin(), agreeing.end(), "miner1") != agreeing.end());
    BOOST_CHECK(std::find(agreeing.begin(), agreeing.end(), "miner2") != agreeing.end());
    BOOST_CHECK(std::find(divergent.begin(), divergent.end(), "miner3") != divergent.end());
}

BOOST_AUTO_TEST_CASE(shard_majority_exact_tie_no_winner)
{
    uint256 hashA = HashOf("A"), hashB = HashOf("B");
    std::vector<ShardResultSubmission> subs;
    subs.push_back({"miner1", hashA, uint256(), 1, 0, uint256()});
    subs.push_back({"miner2", hashB, uint256(), 1, 0, uint256()});

    uint256 majHash; uint32_t majCount;
    std::vector<std::string> agreeing, divergent;
    // minSubmissions=2 so the "not enough submissions" early-out doesn't mask
    // the tie logic itself: 1 vs 1 is bestCount*2(=2) <= size(=2), so this
    // must return false purely because there's no STRICT majority.
    bool resolved = ComputeShardMajority(subs, 2, majHash, majCount, agreeing, divergent);
    BOOST_CHECK(!resolved);
}

BOOST_AUTO_TEST_CASE(shard_majority_all_divergent_no_two_agree)
{
    std::vector<ShardResultSubmission> subs;
    subs.push_back({"miner1", HashOf("A"), uint256(), 1, 0, uint256()});
    subs.push_back({"miner2", HashOf("B"), uint256(), 1, 0, uint256()});
    subs.push_back({"miner3", HashOf("C"), uint256(), 1, 0, uint256()});

    uint256 majHash; uint32_t majCount;
    std::vector<std::string> agreeing, divergent;
    bool resolved = ComputeShardMajority(subs, 3, majHash, majCount, agreeing, divergent);
    BOOST_CHECK(!resolved); // bestCount=1, 1*2=2 <= 3
}

BOOST_AUTO_TEST_CASE(shard_majority_single_submission_is_its_own_majority)
{
    std::vector<ShardResultSubmission> subs;
    subs.push_back({"miner1", HashOf("A"), uint256(), 7, 0, uint256()});

    uint256 majHash; uint32_t majCount;
    std::vector<std::string> agreeing, divergent;
    bool resolved = ComputeShardMajority(subs, 1, majHash, majCount, agreeing, divergent);
    BOOST_CHECK(resolved); // bestCount=1, 1*2=2 > 1
    BOOST_CHECK(majHash == HashOf("A"));
    BOOST_CHECK_EQUAL(majCount, 7u);
    BOOST_REQUIRE_EQUAL(agreeing.size(), 1u);
    BOOST_CHECK_EQUAL(agreeing[0], "miner1");
    BOOST_CHECK(divergent.empty());
}

BOOST_AUTO_TEST_CASE(shard_majority_empty_input)
{
    std::vector<ShardResultSubmission> subs;
    uint256 majHash; uint32_t majCount;
    std::vector<std::string> agreeing, divergent;
    BOOST_CHECK(!ComputeShardMajority(subs, 1, majHash, majCount, agreeing, divergent));
    BOOST_CHECK(!ComputeShardMajority(subs, 0, majHash, majCount, agreeing, divergent));
}

BOOST_AUTO_TEST_CASE(shard_majority_below_min_submissions_never_resolves)
{
    std::vector<ShardResultSubmission> subs;
    subs.push_back({"miner1", HashOf("A"), uint256(), 1, 0, uint256()});
    subs.push_back({"miner2", HashOf("A"), uint256(), 1, 0, uint256()});
    // Two miners genuinely agree, but the configured floor requires 3.
    uint256 majHash; uint32_t majCount;
    std::vector<std::string> agreeing, divergent;
    BOOST_CHECK(!ComputeShardMajority(subs, 3, majHash, majCount, agreeing, divergent));
}

BOOST_AUTO_TEST_CASE(shard_majority_token_count_inflation_lands_in_its_own_bucket)
{
    // Same hash, but one miner inflates tokenCount — F16's anti-inflation
    // design keys the majority on (hash, tokenCount), so this must NOT be
    // treated as agreeing with the honest majority even though the hash matches.
    uint256 hash = HashOf("SAME_OUTPUT");
    std::vector<ShardResultSubmission> subs;
    subs.push_back({"honest1", hash, uint256(), 10, 0, uint256()});
    subs.push_back({"honest2", hash, uint256(), 10, 0, uint256()});
    subs.push_back({"liar",    hash, uint256(), 20, 0, uint256()}); // inflated tokenCount

    uint256 majHash; uint32_t majCount;
    std::vector<std::string> agreeing, divergent;
    bool resolved = ComputeShardMajority(subs, 3, majHash, majCount, agreeing, divergent);
    BOOST_CHECK(resolved);
    BOOST_CHECK_EQUAL(majCount, 10u);
    BOOST_REQUIRE_EQUAL(agreeing.size(), 2u);
    BOOST_CHECK(std::find(agreeing.begin(), agreeing.end(), "liar") == agreeing.end());
    BOOST_REQUIRE_EQUAL(divergent.size(), 1u);
    BOOST_CHECK_EQUAL(divergent[0], "liar");
}

// ── GetShardPaymentsForBlock ──────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(shard_payments_single_shard_dense_full_payment)
{
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 1; // only one miner will ever respond in this test

    const std::string reqId = "req-single";
    g_opoiCache.AddRequest(MakeRequest(reqId, "SINGLE_SHARD_MODEL", 5 * COIN));
    g_opoiCache.AddModelManifest(MakeDenseManifest("SINGLE_SHARD_MODEL", 10, 1));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner1", HashOf("out0"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_REQUIRE_EQUAL(payments.size(), 1u);
    BOOST_CHECK_EQUAL(payments[0].requestId, reqId);
    BOOST_CHECK_EQUAL(payments[0].shardIndex, 0u);
    BOOST_CHECK_EQUAL(payments[0].minerAddress, "miner1");
    BOOST_CHECK_EQUAL(payments[0].amount, 5 * COIN); // sole shard, sole miner -> full payment
}

BOOST_AUTO_TEST_CASE(shard_payments_weighted_multi_shard_matches_live_regtest_scenario)
{
    // Reproduces, as a fast unit test, the exact live-regtest scenario
    // documented for F15-J in CS COIN OPoI MELHOR IMPLEMENTAÇÃO.txt: DENSE
    // model, 9 layers / 2 shards (weight 5:4), request payment=9 CS ->
    // shard 0 pays 2.5 CS to each of 2 agreeing miners (divergent gets 0),
    // shard 1 pays 2.0 CS to each of 2 agreeing miners. Sum = 9 CS exact.
    Consensus::Params params; // default nOPoIShardMinSubmissions == 3

    const std::string reqId = "req-weighted";
    g_opoiCache.AddRequest(MakeRequest(reqId, "DENSE_9L_2S", 9 * COIN));
    g_opoiCache.AddModelManifest(MakeDenseManifest("DENSE_9L_2S", 9, 2));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    // shard 0: minerA/minerB agree, minerC diverges
    vtx.push_back(MakeShardResultTx(reqId, 0, "minerA", HashOf("shard0-out"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 0, "minerB", HashOf("shard0-out"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 0, "minerC", HashOf("shard0-DIFFERENT"), 0));
    // shard 1: minerD/minerE agree, minerF diverges
    vtx.push_back(MakeShardResultTx(reqId, 1, "minerD", HashOf("shard1-out"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 1, "minerE", HashOf("shard1-out"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 1, "minerF", HashOf("shard1-DIFFERENT"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_REQUIRE_EQUAL(payments.size(), 4u); // minerC/minerF excluded entirely

    CAmount total = 0;
    for (const auto& p : payments) {
        total += p.amount;
        if (p.minerAddress == "minerA" || p.minerAddress == "minerB")
            BOOST_CHECK_EQUAL(p.amount, 2.5 * COIN);
        else if (p.minerAddress == "minerD" || p.minerAddress == "minerE")
            BOOST_CHECK_EQUAL(p.amount, 2.0 * COIN);
        else
            BOOST_FAIL("unexpected payee: " + p.minerAddress);
    }
    BOOST_CHECK_EQUAL(total, 9 * COIN); // exact, no rounding leakage
}

BOOST_AUTO_TEST_CASE(shard_payments_majority_vs_minority_same_shard)
{
    // Standalone version of priority item 3: several miners submit for the
    // SAME shard with differing hashes — only the majority-hash group is
    // paid, the minority gets nothing (no fraud proof needed, TYPE B).
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 3;

    const std::string reqId = "req-majority";
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 3 * COIN));
    // No manifest registered -> implicit single-shard fallback (whole payment).

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "majA", HashOf("consensus"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 0, "majB", HashOf("consensus"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 0, "minC", HashOf("rogue"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_REQUIRE_EQUAL(payments.size(), 2u);
    for (const auto& p : payments) {
        BOOST_CHECK(p.minerAddress == "majA" || p.minerAddress == "majB");
        BOOST_CHECK_EQUAL(p.amount, CAmount(3 * COIN / 2));
    }
}

BOOST_AUTO_TEST_CASE(shard_payments_tie_pays_nobody)
{
    // No majority (a straight tie) -> the shard simply never resolves this
    // block; nobody is paid (not "split evenly", not "pay the first one" —
    // GetShardPaymentsForBlock's ComputeShardMajority call returns false and
    // the shard is skipped via `continue`).
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 2;

    const std::string reqId = "req-tie";
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 3 * COIN));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "minerX", HashOf("X"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 0, "minerY", HashOf("Y"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(shard_payments_fee_per_token_inflator_excluded)
{
    // Fee-per-token anti-inflation: a miner truthfully reporting tokenCount
    // vs one inflating it. The inflator lands in a bucket of one (per
    // ComputeShardMajority's (hash,tokenCount) key) and is excluded from
    // payment entirely, even though its hash is correct.
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 3;

    const std::string reqId = "req-feetoken";
    CAmount feePerToken = COIN / 10; // 0.1 CS/token
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 2 * COIN, feePerToken));

    uint256 outHash = HashOf("real-output");
    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "honest1", outHash, 10)); // truthful
    vtx.push_back(MakeShardResultTx(reqId, 0, "honest2", outHash, 10)); // truthful
    vtx.push_back(MakeShardResultTx(reqId, 0, "inflator", outHash, 20)); // same hash, lies about tokenCount

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_REQUIRE_EQUAL(payments.size(), 2u);
    // perShardTotal = 2 CS base + 10 tokens * 0.1 CS = 3 CS, split 2 ways = 1.5 CS each.
    for (const auto& p : payments) {
        BOOST_CHECK(p.minerAddress == "honest1" || p.minerAddress == "honest2");
        BOOST_CHECK_EQUAL(p.amount, CAmount(1.5 * COIN));
    }
}

BOOST_AUTO_TEST_CASE(shard_payments_zero_total_weight_pays_nothing)
{
    // Degenerate manifest (numLayers=0) -> BuildModelExecutionGraph returns
    // an empty graph -> the weighted-split loop never finds this shardIndex
    // -> GetShardPaymentsForBlock's `!found` guard skips the payment
    // entirely, even though the majority itself resolved cleanly.
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 1;

    const std::string reqId = "req-zeroweight";
    g_opoiCache.AddRequest(MakeRequest(reqId, "BROKEN_MODEL", 5 * COIN));
    g_opoiCache.AddModelManifest(MakeDenseManifest("BROKEN_MODEL", /*numLayers=*/0, /*numDenseShards=*/2));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner1", HashOf("out"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(shard_payments_zero_responses_no_shard_result_txs)
{
    // A block with no SHARD_RESULT txs at all touches nothing.
    Consensus::Params params;
    const std::string reqId = "req-noresponses";
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 5 * COIN));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(shard_payments_zero_payment_request_pays_nothing)
{
    // req.payment <= 0 -> explicitly skipped ("if (... || req.payment <= 0) continue;").
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 1;

    const std::string reqId = "req-zeropay";
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 0));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner1", HashOf("out"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(shard_payments_already_paid_shard_not_paid_again)
{
    // OPoICache::setPaidShards bookkeeping: a shard already marked paid must
    // never be returned again by GetShardPaymentsForBlock, even if its
    // majority still resolves cleanly against fresh submissions in this block.
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 1;

    const std::string reqId = "req-alreadypaid";
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 5 * COIN));
    g_opoiCache.MarkShardPaid(reqId, 0);

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner1", HashOf("out"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(shard_payments_unknown_request_id_ignored)
{
    // A SHARD_RESULT tx for a requestId that was never registered as a
    // REQUEST (g_opoiCache.GetRequest fails) must not crash or pay anything.
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 1;

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx("no-such-request", 0, "miner1", HashOf("out"), 0));

    auto payments = GetShardPaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

// ── ShouldCollapseToTitanSingleNode (F9-G/F15-M routing preference) ───────

BOOST_AUTO_TEST_CASE(titan_collapse_requires_all_conditions)
{
    Consensus::Params params;
    params.nOPoITitanOffloadThresholdGB = 200;
    uint64_t bigSizeBytes = 300ULL * 1024 * 1024 * 1024; // 300 GB > 200 GB threshold

    ModelManifest dense = MakeDenseManifest("BIG_DENSE", 100, 4); // numDenseShards > 1
    dense.totalSizeBytes = bigSizeBytes;

    // No titan staker yet -> false even though everything else qualifies.
    BOOST_CHECK(!ShouldCollapseToTitanSingleNode(dense, params));

    OPoIStake titanStake;
    titanStake.SetNull();
    titanStake.minerAddress = "titan-host";
    titanStake.amount = 1;
    titanStake.tier = OPOI_TIER_TITAN;
    titanStake.stakeStatus = OPOI_STAKE_ACTIVE;
    g_opoiCache.mapStakes["titan-host"] = titanStake;

    BOOST_CHECK(ShouldCollapseToTitanSingleNode(dense, params)); // now all conditions hold

    // MoE never collapses via this path (opoi_shard.h already always
    // collapses MoE to one shard) — must stay false regardless of staker/size.
    ModelManifest moe = dense;
    moe.archType = OPOI_ARCH_MOE;
    BOOST_CHECK(!ShouldCollapseToTitanSingleNode(moe, params));

    // A single-shard DENSE model has nothing to collapse.
    ModelManifest singleShard = dense;
    singleShard.numDenseShards = 1;
    BOOST_CHECK(!ShouldCollapseToTitanSingleNode(singleShard, params));

    // Below the size threshold -> false even with a titan staker present.
    ModelManifest small = dense;
    small.totalSizeBytes = 1ULL * 1024 * 1024 * 1024; // 1 GB
    BOOST_CHECK(!ShouldCollapseToTitanSingleNode(small, params));

    // Undeclared size (0) is treated as "unknown", never triggers.
    ModelManifest undeclared = dense;
    undeclared.totalSizeBytes = 0;
    BOOST_CHECK(!ShouldCollapseToTitanSingleNode(undeclared, params));

    // Feature disabled network-wide (threshold == 0) -> never triggers.
    Consensus::Params disabledParams;
    disabledParams.nOPoITitanOffloadThresholdGB = 0;
    BOOST_CHECK(!ShouldCollapseToTitanSingleNode(dense, disabledParams));
}

BOOST_AUTO_TEST_SUITE_END()
