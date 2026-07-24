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
                        CAmount payment, CAmount feePerToken = 0, int8_t taskType = OPOI_TASK_OPEN)
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
    req.taskType     = taskType;
    req.blockHeight  = 100;
    req.sigTime      = 1234;
    req.txHash       = HashOf(requestId + ":tx");
    req.status       = OPOI_STATUS_FULFILLED;
    return req;
}

// Builds a real REVEALed OPoIResponse the way GetVerifiablePaymentsForBlock
// actually reads one (via g_opoiCache.ListResponses(); only requestId,
// minerAddress and tokenCount are touched by that function).
OPoIResponse MakeResponse(const std::string& requestId, const std::string& minerAddress,
                          uint32_t tokenCount = 0)
{
    OPoIResponse resp;
    resp.SetNull();
    resp.requestId     = requestId;
    resp.minerAddress  = minerAddress;
    resp.responseHash  = HashOf(requestId + ":response");
    resp.tokenCount    = tokenCount;
    resp.responsePhase = 1; // REVEAL
    resp.blockHeight   = 100;
    resp.sigTime       = 1234;
    resp.txHash        = HashOf(requestId + ":resptx");
    return resp;
}

// A single Auditor verdict, for direct insertion into g_opoiCache (the
// "already in cache from an earlier block" side of GetVerifiablePaymentsForBlock's
// combined view) or for feeding straight into ComputeAuditorMajority (the pure
// function, which never touches requestId at all).
AuditorVerification MakeVerification(const std::string& requestId, const std::string& auditorAddress,
                                     uint8_t result)
{
    AuditorVerification v;
    v.SetNull();
    v.requestId      = requestId;
    v.auditorAddress = auditorAddress;
    v.result         = result;
    return v;
}

// Builds a real AUDITOR_VERIFY CTransaction the way GetVerifiablePaymentsForBlock
// actually expects to read one (opoiRequestId, opoiAuditorAddress,
// opoiAuditorVerifyResult) — the "this block's own not-yet-applied vote" side
// of its combined view.
CTransaction MakeAuditorVerifyTx(const std::string& requestId, const std::string& auditorAddress,
                                 uint8_t result)
{
    CMutableTransaction mtx;
    mtx.nVersion                = OPOI_TX_VERSION;
    mtx.nType                   = OPOI_AUDITOR_VERIFY_TX_TYPE;
    mtx.opoiRequestId           = requestId;
    mtx.opoiAuditorAddress      = auditorAddress;
    mtx.opoiAuditorVerifyResult = result;
    return CTransaction(mtx);
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

// A dummy, distinct-per-label collateral UTXO reference — real AuditorVerification
// records always carry one (see ProcessOPoITransaction's AUDITOR_VERIFY apply
// branch: fv.auditorCollateral = tx.opoiAuditorCollateralIn), and
// ProcessAuditorVerifications' entire job is deciding what happens to exactly
// this UTXO, so the collateral-locking tests below need it non-null.
COutPoint MakeCollateral(const std::string& label)
{
    return COutPoint(HashOf(label), 0);
}

// Same as MakeVerification (above), but with a real collateral UTXO attached —
// needed for g_opoiCache.AddAuditorVerification(fv) to actually lock something
// (AddAuditorVerification's own "if (!fv.auditorCollateral.IsNull())" guard),
// which is the exact real entry point ProcessOPoITransaction itself uses to
// apply an AUDITOR_VERIFY tx (see opoi.cpp: "g_opoiCache.AddAuditorVerification(fv);
// // also locks the collateral").
AuditorVerification MakeVerificationWithCollateral(const std::string& requestId,
                                                   const std::string& auditorAddress,
                                                   uint8_t result, const COutPoint& collateral)
{
    AuditorVerification v = MakeVerification(requestId, auditorAddress, result);
    v.auditorCollateral = collateral;
    return v;
}

// A real AUDITOR_VERIFY CTransaction that also carries its collateral UTXO —
// MakeAuditorVerifyTx (above) deliberately omits opoiAuditorCollateralIn since
// GetVerifiablePaymentsForBlock never reads it; ProcessOPoITransaction's undo
// branch for this tx type does (g_opoiCache.UnlockUTXO(tx.opoiAuditorCollateralIn)),
// so the undo-path test below needs this fuller variant.
CTransaction MakeAuditorVerifyTxWithCollateral(const std::string& requestId, const std::string& auditorAddress,
                                               uint8_t result, const COutPoint& collateral)
{
    CMutableTransaction mtx;
    mtx.nVersion                = OPOI_TX_VERSION;
    mtx.nType                   = OPOI_AUDITOR_VERIFY_TX_TYPE;
    mtx.opoiRequestId           = requestId;
    mtx.opoiAuditorAddress      = auditorAddress;
    mtx.opoiAuditorVerifyResult = result;
    mtx.opoiAuditorCollateralIn = collateral;
    return CTransaction(mtx);
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

// ── ComputeAuditorMajority (F14-C) ────────────────────────────────────────
// Auditor verdicts are PASS/FAIL/TIMEOUT votes (not hash-agreement like
// ComputeShardMajority), so the majority rule here is a plain STRICT
// majority (revealed > 2x) of one of the three fixed result values, gated
// by a quorum floor (minVerifiers) on the count of REVEALED votes — there
// is no "bucket key" or tie-break-by-count concept the way shard majority
// has.

BOOST_AUTO_TEST_CASE(auditor_majority_clear_majority_pass)
{
    std::vector<AuditorVerification> verifs;
    verifs.push_back(MakeVerification("req", "auditor1", AUDITOR_VERIFY_PASS));
    verifs.push_back(MakeVerification("req", "auditor2", AUDITOR_VERIFY_PASS));
    verifs.push_back(MakeVerification("req", "auditor3", AUDITOR_VERIFY_FAIL));

    int result = ComputeAuditorMajority(verifs, 3);
    BOOST_CHECK_EQUAL(result, (int)AUDITOR_VERIFY_PASS);
}

BOOST_AUTO_TEST_CASE(auditor_majority_clear_majority_fail)
{
    std::vector<AuditorVerification> verifs;
    verifs.push_back(MakeVerification("req", "auditor1", AUDITOR_VERIFY_FAIL));
    verifs.push_back(MakeVerification("req", "auditor2", AUDITOR_VERIFY_FAIL));
    verifs.push_back(MakeVerification("req", "auditor3", AUDITOR_VERIFY_PASS));

    int result = ComputeAuditorMajority(verifs, 3);
    BOOST_CHECK_EQUAL(result, (int)AUDITOR_VERIFY_FAIL);
}

BOOST_AUTO_TEST_CASE(auditor_majority_exact_tie_no_winner)
{
    std::vector<AuditorVerification> verifs;
    verifs.push_back(MakeVerification("req", "auditor1", AUDITOR_VERIFY_PASS));
    verifs.push_back(MakeVerification("req", "auditor2", AUDITOR_VERIFY_FAIL));

    // Quorum (2) is met, but 1-vs-1 is not a STRICT majority (1 > 2/2=1 is false
    // for both sides) -> unresolved.
    int result = ComputeAuditorMajority(verifs, 2);
    BOOST_CHECK_EQUAL(result, -1);
}

BOOST_AUTO_TEST_CASE(auditor_majority_three_way_split_no_winner)
{
    // All three result values appear exactly once -- exercises the TIMEOUT
    // branch too, and confirms a plain 1/1/1 split never resolves.
    std::vector<AuditorVerification> verifs;
    verifs.push_back(MakeVerification("req", "auditor1", AUDITOR_VERIFY_PASS));
    verifs.push_back(MakeVerification("req", "auditor2", AUDITOR_VERIFY_FAIL));
    verifs.push_back(MakeVerification("req", "auditor3", AUDITOR_VERIFY_TIMEOUT));

    int result = ComputeAuditorMajority(verifs, 3);
    BOOST_CHECK_EQUAL(result, -1);
}

BOOST_AUTO_TEST_CASE(auditor_majority_below_min_auditors_never_resolves)
{
    // Two Auditors genuinely agree, but the configured floor (mirrors
    // Consensus::Params::nOPoIMinAuditors) requires 3 REVEALED votes.
    std::vector<AuditorVerification> verifs;
    verifs.push_back(MakeVerification("req", "auditor1", AUDITOR_VERIFY_PASS));
    verifs.push_back(MakeVerification("req", "auditor2", AUDITOR_VERIFY_PASS));

    int result = ComputeAuditorMajority(verifs, 3);
    BOOST_CHECK_EQUAL(result, -1);
}

BOOST_AUTO_TEST_CASE(auditor_majority_single_vote_is_its_own_majority)
{
    std::vector<AuditorVerification> verifs;
    verifs.push_back(MakeVerification("req", "auditor1", AUDITOR_VERIFY_PASS));

    int result = ComputeAuditorMajority(verifs, 1);
    BOOST_CHECK_EQUAL(result, (int)AUDITOR_VERIFY_PASS); // 1 > 1/2=0
}

BOOST_AUTO_TEST_CASE(auditor_majority_empty_input)
{
    std::vector<AuditorVerification> verifs;
    BOOST_CHECK_EQUAL(ComputeAuditorMajority(verifs, 1), -1);
    BOOST_CHECK_EQUAL(ComputeAuditorMajority(verifs, 0), -1);
}

// ── GetVerifiablePaymentsForBlock (F14-C) ─────────────────────────────────
// The VERIFIABLE-task/N-of-M-Auditor sibling of GetShardPaymentsForBlock:
// pays a RESPONSE's miner in full once its request's Auditor verdicts
// (cache + this block's own not-yet-applied AUDITOR_VERIFY txs, deduped by
// auditorAddress) resolve to a strict AUDITOR_VERIFY_PASS majority, and only
// once per requestId (OPoICache::setPaidResponses via IsResponsePaid).

BOOST_AUTO_TEST_CASE(verifiable_payments_majority_pass_full_payment)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-verifiable-pass";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_FAIL));

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_REQUIRE_EQUAL(payments.size(), 1u);
    BOOST_CHECK_EQUAL(payments[0].requestId, reqId);
    BOOST_CHECK_EQUAL(payments[0].minerAddress, "miner1");
    BOOST_CHECK_EQUAL(payments[0].amount, 5 * COIN);
}

BOOST_AUTO_TEST_CASE(verifiable_payments_fee_per_token_added)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-verifiable-feetoken";
    CAmount feePerToken = COIN / 10; // 0.1 CS/token
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 2 * COIN, feePerToken, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1", /*tokenCount=*/20));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_PASS));

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_REQUIRE_EQUAL(payments.size(), 1u);
    // 2 CS base + 20 tokens * 0.1 CS = 4 CS.
    BOOST_CHECK_EQUAL(payments[0].amount, 4 * COIN);
}

BOOST_AUTO_TEST_CASE(verifiable_payments_majority_fail_pays_nothing)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-verifiable-fail";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_FAIL));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_FAIL));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_PASS));

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty()); // majority resolved, but to FAIL, not PASS
}

BOOST_AUTO_TEST_CASE(verifiable_payments_no_quorum_pays_nothing)
{
    Consensus::Params params; // default nOPoIMinAuditors == 3

    const std::string reqId = "req-verifiable-noquorum";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    // Only 2 of the required 3 Auditors have voted.

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(verifiable_payments_already_paid_not_paid_again)
{
    // OPoICache::setPaidResponses bookkeeping (IsResponsePaid/MarkResponsePaid):
    // a requestId already marked paid must never be returned again, even if
    // its majority still resolves cleanly against fresh votes in this block.
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-verifiable-alreadypaid";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));
    g_opoiCache.MarkResponsePaid(reqId);

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_PASS));

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(verifiable_payments_combines_cache_and_block_votes_with_dedup)
{
    // Mirrors GetShardPaymentsForBlock's combine-cache-with-this-block's-own-
    // txs pattern: 1 FAIL + 1 PASS already resolved-into-cache from an earlier
    // block, this block brings a NEW PASS vote plus a REDUNDANT re-delivery of
    // the already-cached FAIL vote from auditor1. If the redundant vote were
    // not deduped by auditorAddress (the "seen" set), revealed would be 4
    // (FAIL,PASS,FAIL,PASS) and 2 > 4/2=2 would be false for every verdict,
    // so this majority would wrongly fail to resolve.
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-verifiable-dedup";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));
    g_opoiCache.AddAuditorVerification(MakeVerification(reqId, "auditor1", AUDITOR_VERIFY_FAIL));
    g_opoiCache.AddAuditorVerification(MakeVerification(reqId, "auditor2", AUDITOR_VERIFY_PASS));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_PASS)); // new
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_FAIL)); // redundant, must be deduped

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_REQUIRE_EQUAL(payments.size(), 1u); // 1 FAIL, 2 PASS out of 3 -> strict PASS majority
    BOOST_CHECK_EQUAL(payments[0].amount, 5 * COIN);
}

BOOST_AUTO_TEST_CASE(verifiable_payments_open_task_request_ignored)
{
    // OPEN-task requests are paid same-block via the SHARD_RESULT/dense
    // pipeline (GetShardPaymentsForBlock), never here — even if a stray
    // Auditor majority happened to resolve PASS for one.
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-verifiable-opentask";
    g_opoiCache.AddRequest(MakeRequest(reqId, "TEXT_MODEL", 5 * COIN)); // default taskType == OPOI_TASK_OPEN
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_PASS));

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(verifiable_payments_zero_payment_request_pays_nothing)
{
    // req.payment <= 0 -> explicitly skipped, same guard shape as
    // GetShardPaymentsForBlock's req.payment <= 0 check.
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-verifiable-zeropay";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 0, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_PASS));

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(verifiable_payments_orphan_response_unknown_request_ignored)
{
    // A RESPONSE recorded for a requestId that was never registered as a
    // REQUEST (g_opoiCache.GetRequest fails) must not crash or pay anything —
    // the mirror image of shard_payments_unknown_request_id_ignored.
    Consensus::Params params;
    params.nOPoIMinAuditors = 1;

    g_opoiCache.AddResponse(MakeResponse("no-such-request", "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx("no-such-request", "auditor1", AUDITOR_VERIFY_PASS));

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

BOOST_AUTO_TEST_CASE(verifiable_payments_zero_responses_no_op)
{
    // A block/cache with a VERIFIABLE request but no RESPONSE at all touches
    // nothing (ListResponses() is empty, the loop body never runs).
    Consensus::Params params;
    const std::string reqId = "req-verifiable-noresponses";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());

    auto payments = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(payments.empty());
}

// ── ProcessAuditorVerifications (F14-C) ───────────────────────────────────
// Unlike GetShardPaymentsForBlock/GetVerifiablePaymentsForBlock (pure
// computations returning a vector), this is a mutation: it walks every
// requestId in g_opoiCache.mapAuditorVerifications, and the moment one first
// reaches quorum, flips each vote's `status` and calls
// g_opoiCache.UnlockUTXO/leaves it locked depending on majority agreement,
// then g_opoiCache.MarkAuditorResolved so it's never reprocessed. Tests below
// call the real function and then query g_opoiCache directly (IsLockedUTXO,
// GetAuditorVerifications, IsAuditorResolved) — never reimplementing the
// unlock/slash decision.

BOOST_AUTO_TEST_CASE(auditor_verifications_no_quorum_stays_pending)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-av-noquorum";
    COutPoint c1 = MakeCollateral("c1");
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor1", AUDITOR_VERIFY_PASS, c1));

    BOOST_CHECK(g_opoiCache.IsLockedUTXO(c1)); // AddAuditorVerification locks it immediately

    ProcessAuditorVerifications(100, params);

    BOOST_CHECK(!g_opoiCache.IsAuditorResolved(reqId)); // only 1 of 3 required votes in
    BOOST_CHECK(g_opoiCache.IsLockedUTXO(c1)); // untouched — still pending, not unlocked or slashed

    auto verifs = g_opoiCache.GetAuditorVerifications(reqId);
    BOOST_REQUIRE_EQUAL(verifs.size(), 1u);
    BOOST_CHECK_EQUAL(verifs[0].status, OPOI_AUDITOR_STATUS_PENDING);
}

BOOST_AUTO_TEST_CASE(auditor_verifications_quorum_majority_unlocks_winners_slashes_loser)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-av-majority";
    COutPoint c1 = MakeCollateral("maj-c1"), c2 = MakeCollateral("maj-c2"), c3 = MakeCollateral("maj-c3");
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor1", AUDITOR_VERIFY_PASS, c1));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor2", AUDITOR_VERIFY_PASS, c2));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor3", AUDITOR_VERIFY_FAIL, c3));

    ProcessAuditorVerifications(100, params);

    BOOST_CHECK(g_opoiCache.IsAuditorResolved(reqId));
    // Majority (PASS) voters get their collateral back...
    BOOST_CHECK(!g_opoiCache.IsLockedUTXO(c1));
    BOOST_CHECK(!g_opoiCache.IsLockedUTXO(c2));
    // ...the lone divergent voter's collateral is burned (stays locked forever).
    BOOST_CHECK(g_opoiCache.IsLockedUTXO(c3));

    auto verifs = g_opoiCache.GetAuditorVerifications(reqId);
    BOOST_REQUIRE_EQUAL(verifs.size(), 3u);
    for (const auto& v : verifs) {
        if (v.auditorAddress == "auditor3")
            BOOST_CHECK_EQUAL(v.status, OPOI_AUDITOR_STATUS_SLASHED);
        else
            BOOST_CHECK_EQUAL(v.status, OPOI_AUDITOR_STATUS_COMPLETE);
    }

    // A later block re-running this (RebuildOPoICache replay, or simply the
    // next ConnectBlock) must be a no-op: IsAuditorResolved's guard skips the
    // requestId entirely, so nothing gets re-unlocked or re-slashed.
    ProcessAuditorVerifications(101, params);
    BOOST_CHECK(!g_opoiCache.IsLockedUTXO(c1));
    BOOST_CHECK(!g_opoiCache.IsLockedUTXO(c2));
    BOOST_CHECK(g_opoiCache.IsLockedUTXO(c3));
}

BOOST_AUTO_TEST_CASE(auditor_verifications_tie_resolves_nobody_stays_locked)
{
    // A straight 1-vs-1 tie with quorum=2: ComputeAuditorMajority returns -1
    // (no STRICT majority), so ProcessAuditorVerifications' `if (majority < 0)
    // continue;` guard means this requestId is left completely untouched —
    // neither "everyone refunded" nor "everyone slashed", just never resolved
    // (matches the function's own "Known v1 limitation" comment: quorum
    // reached but never a majority means the vote just stays pending forever).
    Consensus::Params params;
    params.nOPoIMinAuditors = 2;

    const std::string reqId = "req-av-tie";
    COutPoint c1 = MakeCollateral("tie-c1"), c2 = MakeCollateral("tie-c2");
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor1", AUDITOR_VERIFY_PASS, c1));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor2", AUDITOR_VERIFY_FAIL, c2));

    ProcessAuditorVerifications(100, params);

    BOOST_CHECK(!g_opoiCache.IsAuditorResolved(reqId));
    BOOST_CHECK(g_opoiCache.IsLockedUTXO(c1)); // still locked, not refunded
    BOOST_CHECK(g_opoiCache.IsLockedUTXO(c2)); // still locked, not slashed either

    auto verifs = g_opoiCache.GetAuditorVerifications(reqId);
    for (const auto& v : verifs)
        BOOST_CHECK_EQUAL(v.status, OPOI_AUDITOR_STATUS_PENDING);
}

BOOST_AUTO_TEST_CASE(auditor_verifications_canary_fail_strikes_miner_and_clears_obligation)
{
    // F9-F integration: a canary REQUEST resolving FAIL strikes the
    // responding miner's stake (not a full slash) and clears any outstanding
    // canaryObligationDeadline, so ProcessCanaryAudits doesn't double-strike
    // the same cycle later.
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-av-canary-fail";
    OPoIRequest req = MakeRequest(reqId, "CANARY_MODEL", 1 * COIN, 0, OPOI_TASK_VERIFIABLE);
    req.isCanary = 1;
    g_opoiCache.AddRequest(req);
    g_opoiCache.AddResponse(MakeResponse(reqId, "canary-miner"));

    OPoIStake stake;
    stake.SetNull();
    stake.minerAddress = "canary-miner";
    stake.amount = 1;
    stake.stakeStatus = OPOI_STAKE_ACTIVE;
    stake.canaryStrikes = 0;
    stake.canaryObligationDeadline = 500; // outstanding obligation
    g_opoiCache.AddStake(stake);

    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor1", AUDITOR_VERIFY_FAIL, MakeCollateral("cf-c1")));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor2", AUDITOR_VERIFY_FAIL, MakeCollateral("cf-c2")));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor3", AUDITOR_VERIFY_PASS, MakeCollateral("cf-c3")));

    ProcessAuditorVerifications(100, params);

    BOOST_CHECK(g_opoiCache.IsAuditorResolved(reqId));
    OPoIStake outStake;
    BOOST_REQUIRE(g_opoiCache.GetStake("canary-miner", outStake));
    BOOST_CHECK_EQUAL(outStake.canaryStrikes, 1u);
    BOOST_CHECK_EQUAL(outStake.canaryObligationDeadline, 0u); // cleared, whether PASS or FAIL
    BOOST_CHECK(outStake.IsActive()); // 1 strike < OPOI_MAX_CANARY_STRIKES(3), not suspended yet
}

BOOST_AUTO_TEST_CASE(auditor_verifications_canary_third_strike_suspends_stake)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-av-canary-suspend";
    OPoIRequest req = MakeRequest(reqId, "CANARY_MODEL", 1 * COIN, 0, OPOI_TASK_VERIFIABLE);
    req.isCanary = 1;
    g_opoiCache.AddRequest(req);
    g_opoiCache.AddResponse(MakeResponse(reqId, "canary-miner2"));

    OPoIStake stake;
    stake.SetNull();
    stake.minerAddress = "canary-miner2";
    stake.amount = 1;
    stake.stakeStatus = OPOI_STAKE_ACTIVE;
    stake.canaryStrikes = 2; // already 2 strikes from earlier cycles
    g_opoiCache.AddStake(stake);

    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor1", AUDITOR_VERIFY_FAIL, MakeCollateral("s3-c1")));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor2", AUDITOR_VERIFY_FAIL, MakeCollateral("s3-c2")));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor3", AUDITOR_VERIFY_PASS, MakeCollateral("s3-c3")));

    ProcessAuditorVerifications(100, params);

    OPoIStake outStake;
    BOOST_REQUIRE(g_opoiCache.GetStake("canary-miner2", outStake));
    BOOST_CHECK_EQUAL(outStake.canaryStrikes, 3u);
    BOOST_CHECK(outStake.IsSuspended());
}

BOOST_AUTO_TEST_CASE(auditor_verifications_undo_via_process_opoi_transaction)
{
    // ProcessAuditorVerifications itself takes no fUndo parameter and has no
    // undo branch — a reorg doesn't call it in reverse. Instead, collateral
    // undo is handled per-vote by ProcessOPoITransaction's own fUndo branch
    // for OPOI_AUDITOR_VERIFY_TX_TYPE (opoi.cpp), which now looks up that
    // Auditor's vote status BEFORE erasing it, only UnlockUTXO()s their
    // collateral when the vote was NOT SLASHED, and UnmarkAuditorResolved()s
    // the requestId. This test exercises that real undo path directly and
    // confirms the fixed behavior: undoing the SLASHED minority's own vote
    // must leave its collateral permanently burned (locked), matching the
    // analogous CHALLENGE-undo handling (ch.challengeStatus ==
    // OPOI_CHALLENGE_SLASHED) just above it in ProcessOPoITransaction.
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-av-undo";
    COutPoint c1 = MakeCollateral("undo-c1"), c2 = MakeCollateral("undo-c2"), c3 = MakeCollateral("undo-c3");
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor1", AUDITOR_VERIFY_PASS, c1));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor2", AUDITOR_VERIFY_PASS, c2));
    g_opoiCache.AddAuditorVerification(MakeVerificationWithCollateral(reqId, "auditor3", AUDITOR_VERIFY_FAIL, c3));

    ProcessAuditorVerifications(100, params);
    BOOST_REQUIRE(g_opoiCache.IsAuditorResolved(reqId));
    BOOST_REQUIRE(g_opoiCache.IsLockedUTXO(c3)); // slashed, burned

    CTransaction undoTx = MakeAuditorVerifyTxWithCollateral(reqId, "auditor3", AUDITOR_VERIFY_FAIL, c3);
    bool ok = ProcessOPoITransaction(undoTx, 100, /*fUndo=*/true, &params);
    BOOST_CHECK(ok);

    // The vote itself is gone...
    auto verifs = g_opoiCache.GetAuditorVerifications(reqId);
    for (const auto& v : verifs)
        BOOST_CHECK(v.auditorAddress != "auditor3");
    // ...the resolution is reopened...
    BOOST_CHECK(!g_opoiCache.IsAuditorResolved(reqId));
    // ...and the burned collateral correctly STAYS locked — it was never
    // unlocked as a SLASHED minority vote, and undoing the vote must not
    // release it.
    BOOST_CHECK(g_opoiCache.IsLockedUTXO(c3));
}

// ── ProcessShardPayments (F16 mutation wrapper) ───────────────────────────
// GetShardPaymentsForBlock (tested above) is the pure calculation;
// ProcessShardPayments is the real stateful wrapper that actually calls
// g_opoiCache.MarkShardPaid for every payment it computes — this is what
// setPaidShards/IsShardPaid actually get set BY, in production. Tests below
// call ProcessShardPayments itself (not MarkShardPaid directly) and then
// query IsShardPaid / re-invoke GetShardPaymentsForBlock to confirm the real
// mutation took hold and a second pass never double-pays.

BOOST_AUTO_TEST_CASE(process_shard_payments_marks_resolved_shard_paid)
{
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 1;

    const std::string reqId = "req-psp-resolved";
    g_opoiCache.AddRequest(MakeRequest(reqId, "SINGLE_SHARD_MODEL", 5 * COIN));
    g_opoiCache.AddModelManifest(MakeDenseManifest("SINGLE_SHARD_MODEL", 10, 1));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner1", HashOf("out0"), 0));

    BOOST_CHECK(!g_opoiCache.IsShardPaid(reqId, 0));
    ProcessShardPayments(vtx, params);
    BOOST_CHECK(g_opoiCache.IsShardPaid(reqId, 0));
}

BOOST_AUTO_TEST_CASE(process_shard_payments_second_call_never_double_pays)
{
    // Simulates the same SHARD_RESULT txs still being visible on a *later*
    // block's re-derivation (e.g. RebuildOPoICache replay) — the real
    // mutation (setPaidShards, via MarkShardPaid) must make the second call a
    // total no-op, not just a lucky zero from the pure calculation alone.
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 1;

    const std::string reqId = "req-psp-nodouble";
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 5 * COIN));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner1", HashOf("out"), 0));

    ProcessShardPayments(vtx, params);
    BOOST_REQUIRE(g_opoiCache.IsShardPaid(reqId, 0));

    // Second call (as if processing a later block containing the very same
    // txs, or a duplicate RebuildOPoICache pass): must find nothing left to pay.
    auto secondPass = GetShardPaymentsForBlock(vtx, params);
    BOOST_CHECK(secondPass.empty());
    ProcessShardPayments(vtx, params); // must not crash or change anything
    BOOST_CHECK(g_opoiCache.IsShardPaid(reqId, 0));
}

BOOST_AUTO_TEST_CASE(process_shard_payments_unresolved_shard_not_marked_paid)
{
    // Below min submissions -> ComputeShardMajority never resolves -> nothing
    // computed -> ProcessShardPayments' for-loop over an empty vector never
    // calls MarkShardPaid.
    Consensus::Params params;
    params.nOPoIShardMinSubmissions = 3;

    const std::string reqId = "req-psp-unresolved";
    g_opoiCache.AddRequest(MakeRequest(reqId, "NO_MANIFEST_MODEL", 5 * COIN));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner1", HashOf("out"), 0));
    vtx.push_back(MakeShardResultTx(reqId, 0, "miner2", HashOf("out"), 0));
    // Only 2 of the required 3 submissions are in.

    ProcessShardPayments(vtx, params);
    BOOST_CHECK(!g_opoiCache.IsShardPaid(reqId, 0));
}

// ── ProcessVerifiableResponsePayments (F14-C mutation wrapper) ────────────
// The IsResponsePaid/MarkResponsePaid mirror of ProcessShardPayments' tests
// above, for the Auditor/VERIFIABLE payment path.

BOOST_AUTO_TEST_CASE(process_verifiable_payments_marks_resolved_response_paid)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-pvp-resolved";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_FAIL));

    BOOST_CHECK(!g_opoiCache.IsResponsePaid(reqId));
    ProcessVerifiableResponsePayments(vtx, params);
    BOOST_CHECK(g_opoiCache.IsResponsePaid(reqId));
}

BOOST_AUTO_TEST_CASE(process_verifiable_payments_second_call_never_double_pays)
{
    Consensus::Params params;
    params.nOPoIMinAuditors = 3;

    const std::string reqId = "req-pvp-nodouble";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor3", AUDITOR_VERIFY_PASS));

    ProcessVerifiableResponsePayments(vtx, params);
    BOOST_REQUIRE(g_opoiCache.IsResponsePaid(reqId));

    auto secondPass = GetVerifiablePaymentsForBlock(vtx, params);
    BOOST_CHECK(secondPass.empty());
    ProcessVerifiableResponsePayments(vtx, params); // must not crash or re-mark anything
    BOOST_CHECK(g_opoiCache.IsResponsePaid(reqId));
}

BOOST_AUTO_TEST_CASE(process_verifiable_payments_unresolved_response_not_marked_paid)
{
    Consensus::Params params; // default nOPoIMinAuditors == 3

    const std::string reqId = "req-pvp-unresolved";
    g_opoiCache.AddRequest(MakeRequest(reqId, "CODE_MODEL", 5 * COIN, 0, OPOI_TASK_VERIFIABLE));
    g_opoiCache.AddResponse(MakeResponse(reqId, "miner1"));

    std::vector<CTransaction> vtx;
    vtx.push_back(MakeDummyCoinbase());
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor1", AUDITOR_VERIFY_PASS));
    vtx.push_back(MakeAuditorVerifyTx(reqId, "auditor2", AUDITOR_VERIFY_PASS));
    // Only 2 of the required 3 Auditors have voted -> no quorum.

    ProcessVerifiableResponsePayments(vtx, params);
    BOOST_CHECK(!g_opoiCache.IsResponsePaid(reqId));
}

BOOST_AUTO_TEST_SUITE_END()
