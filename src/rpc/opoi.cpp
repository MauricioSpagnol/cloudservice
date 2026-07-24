// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// RPC commands for the OPoI (Optimistic Proof of Inference) subsystem:
//   listopoirequests   — list AI inference requests (optional status filter)
//   listopoiresponses  — list committed AI response proofs
//   getopoirequest     — get a single request by UUID
//   submitopoirequest  — broadcast a new REQUEST tx (client side)
//   submitopoiresponsecommit — commit-reveal RESPONSE, COMMIT phase (F10-B, miner side)
//   submitopoiresponse — commit-reveal RESPONSE, REVEAL phase        (miner side)
//   rebuilopoidb       — rescan chain and rebuild OPoI cache

#include "opoi/opoi.h"
#include "opoi/opoi_vrf.h"
#include "crypto/sha256.h"
#include "rpc/server.h"
#include "key.h"
#include "primitives/transaction.h"
#include "main.h"
#include "net.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "univalue/include/univalue.h"
#include "wallet/wallet.h"
#include "key_io.h"
#include "csnode/obfuscation.h"
#include "init.h"
#include "random.h"

#ifdef ENABLE_WALLET
extern CWallet* pwalletMain;
void EnsureWalletIsUnlocked();
#endif

// ── Helpers ──────────────────────────────────────────────────────────────────

static UniValue OPoIRequestToUniValue(const OPoIRequest& r)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("request_id",    r.requestId);
    obj.pushKV("requester",     r.requester);
    obj.pushKV("model",         r.model);
    obj.pushKV("prompt_hash",   r.promptHash.GetHex());
    obj.pushKV("max_tokens",    (int)r.maxTokens);
    obj.pushKV("payment",       ValueFromAmount(r.payment));
    obj.pushKV("fee_per_token", ValueFromAmount(r.feePerToken));
    obj.pushKV("task_type",     r.taskType == OPOI_TASK_VERIFIABLE ? "VERIFIABLE" : "OPEN");
    obj.pushKV("task_class",    r.taskClass == OPOI_TASKCLASS_BATCH ? "BATCH" : "INTERACTIVE");
    if (r.taskType == OPOI_TASK_VERIFIABLE)
        obj.pushKV("test_suite", r.testSuite.GetHex());
    obj.pushKV("prompt_token_count", (int)r.promptTokenCount); // F11-A
    obj.pushKV("is_canary",          (bool)r.isCanary);        // F9-F
    obj.pushKV("block_height",  (int)r.blockHeight);
    obj.pushKV("sig_time",      (int)r.sigTime);
    obj.pushKV("tx_hash",       r.txHash.GetHex());

    std::string s;
    switch (r.status) {
        case OPOI_STATUS_PENDING:   s = "PENDING";   break;
        case OPOI_STATUS_FULFILLED: s = "FULFILLED"; break;
        case OPOI_STATUS_EXPIRED:   s = "EXPIRED";   break;
        default:                    s = "UNKNOWN";   break;
    }
    obj.pushKV("status", s);
    // F10-B: commit-reveal visibility for testing/monitoring
    obj.pushKV("commit_window_closed", r.commitWindowClosed);
    obj.pushKV("response_commits", (int)r.responseCommits.size());
    obj.pushKV("response_reveals", (int)r.responseReveals.size());
    return obj;
}

static UniValue OPoIResponseToUniValue(const OPoIResponse& r)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("request_id",    r.requestId);
    obj.pushKV("miner_address", r.minerAddress);
    obj.pushKV("response_hash", r.responseHash.GetHex());
    obj.pushKV("commitment",    r.commitment.GetHex());
    obj.pushKV("token_count",   (int)r.tokenCount);
    obj.pushKV("block_height",  (int)r.blockHeight);
    obj.pushKV("sig_time",      (int)r.sigTime);
    obj.pushKV("tx_hash",       r.txHash.GetHex());
    return obj;
}

static std::string ArchTypeToString(uint8_t archType)
{
    switch (archType) {
        case OPOI_ARCH_DENSE:  return "DENSE";
        case OPOI_ARCH_MOE:    return "MOE";
        case OPOI_ARCH_HYBRID: return "HYBRID";
        default:               return "UNKNOWN";
    }
}

static uint8_t ArchTypeFromString(const std::string& s)
{
    if (s == "DENSE")  return OPOI_ARCH_DENSE;
    if (s == "MOE")    return OPOI_ARCH_MOE;
    if (s == "HYBRID") return OPOI_ARCH_HYBRID;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "arch_type must be DENSE, MOE or HYBRID");
}

static std::string ModelStatusToString(int8_t status)
{
    switch (status) {
        case OPOI_MODEL_STATUS_VOTING:   return "VOTING";
        case OPOI_MODEL_STATUS_APPROVED: return "APPROVED";
        case OPOI_MODEL_STATUS_ACTIVE:   return "ACTIVE";
        case OPOI_MODEL_STATUS_REJECTED: return "REJECTED";
        default:                         return "UNKNOWN";
    }
}

// F15-A: includes a live vote tally so the admin panel can show voting progress
// without a separate RPC round-trip.
static UniValue ModelManifestToUniValue(const ModelManifest& m)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("model_id",                m.modelId);
    obj.pushKV("arch_type",               ArchTypeToString(m.archType));
    obj.pushKV("total_params",            (uint64_t)m.totalParams);
    obj.pushKV("active_params_per_token", (uint64_t)m.activeParamsPerToken);
    obj.pushKV("num_layers",              (int)m.numLayers);
    obj.pushKV("num_dense_shards",        (int)m.numDenseShards);
    obj.pushKV("shard_topology_hash",     m.shardTopologyHash.GetHex());
    obj.pushKV("num_experts",             (int)m.numExperts);
    obj.pushKV("top_k_experts",           (int)m.topKExperts);
    obj.pushKV("backbone_pom_root",       m.backbonePomRoot.GetHex());
    UniValue experts(UniValue::VARR);
    for (const auto& root : m.expertPomRoots) experts.push_back(root.GetHex());
    obj.pushKV("expert_pom_roots",        experts);
    obj.pushKV("min_reward_per_token",    ValueFromAmount(m.minRewardPerToken));
    obj.pushKV("total_size_bytes",        (uint64_t)m.totalSizeBytes); // F9-G/F15-M
    obj.pushKV("proposer",                m.proposer);
    obj.pushKV("proposed_height",         (int)m.proposedHeight);
    obj.pushKV("vote_window_end_height",  (int)m.voteWindowEndHeight);
    obj.pushKV("activation_height",       (int)m.activationHeight);
    obj.pushKV("tx_hash",                 m.txHash.GetHex());
    obj.pushKV("status",                  ModelStatusToString(m.status));

    CAmount yesWeight = 0, noWeight = 0;
    g_opoiCache.TallyModelVotes(m.modelId, yesWeight, noWeight);
    CAmount totalActiveStake = g_opoiCache.TotalActiveStake();
    UniValue voting(UniValue::VOBJ);
    voting.pushKV("yes_weight_cs",   ValueFromAmount(yesWeight));
    voting.pushKV("no_weight_cs",    ValueFromAmount(noWeight));
    voting.pushKV("total_active_stake_cs", ValueFromAmount(totalActiveStake));
    voting.pushKV("approval_pct_needed", (int)Params().GetConsensus().nOPoIModelApprovalPct);
    voting.pushKV("approval_pct_current",
        totalActiveStake > 0 ? (double)yesWeight * 100.0 / (double)totalActiveStake : 0.0);
    obj.pushKV("voting", voting);
    return obj;
}

static bool SignWithAddress(const std::string& address, const std::string& message,
                            std::vector<unsigned char>& vchSig, std::string& errMsg)
{
#ifndef ENABLE_WALLET
    errMsg = "Wallet support not compiled in";
    return false;
#else
    if (!pwalletMain) { errMsg = "Wallet not available"; return false; }
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) { errMsg = "Invalid address: " + address; return false; }
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) { errMsg = "Address is not P2PKH"; return false; }
    CKey key;
    if (!pwalletMain->GetKey(*keyID, key)) {
        errMsg = "Private key not in wallet for " + address;
        return false;
    }
    CObfuScationSigner signer;
    return signer.SignMessage(message, errMsg, vchSig, key);
#endif
}

// ── RPC commands ─────────────────────────────────────────────────────────────

UniValue listopoirequests(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "listopoirequests ( \"status\" )\n"
            "\nList AI inference requests on the CS Coin chain.\n"
            "\nArguments:\n"
            "1. status  (string, optional) Filter: PENDING | FULFILLED | EXPIRED\n"
            "\nResult:\n"
            "[{ request_id, requester, model, prompt_hash, payment, status, ... }, ...]\n"
            "\nExamples:\n"
            + HelpExampleCli("listopoirequests", "")
            + HelpExampleCli("listopoirequests", "\"PENDING\"")
            + HelpExampleRpc("listopoirequests", "\"PENDING\"")
        );

    int8_t statusFilter = -1;
    if (params.size() == 1) {
        std::string s = params[0].get_str();
        if      (s == "PENDING")   statusFilter = OPOI_STATUS_PENDING;
        else if (s == "FULFILLED") statusFilter = OPOI_STATUS_FULFILLED;
        else if (s == "EXPIRED")   statusFilter = OPOI_STATUS_EXPIRED;
        else throw std::runtime_error("Invalid status. Use PENDING, FULFILLED or EXPIRED.");
    }

    UniValue arr(UniValue::VARR);
    for (const auto& r : g_opoiCache.ListRequests(statusFilter))
        arr.push_back(OPoIRequestToUniValue(r));
    return arr;
}

UniValue listopoiresponses(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "listopoiresponses\n"
            "\nList committed AI inference response proofs.\n"
            "\nExamples:\n"
            + HelpExampleCli("listopoiresponses", "")
            + HelpExampleRpc("listopoiresponses", "")
        );

    UniValue arr(UniValue::VARR);
    for (const auto& r : g_opoiCache.ListResponses())
        arr.push_back(OPoIResponseToUniValue(r));
    return arr;
}

UniValue getopoirequest(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getopoirequest \"request_id\"\n"
            "\nGet a single OPoI request by UUID.\n"
            "\nArguments:\n"
            "1. request_id  (string, required) UUID of the inference request\n"
            "\nExamples:\n"
            + HelpExampleCli("getopoirequest", "\"550e8400-e29b-41d4-a716-446655440000\"")
            + HelpExampleRpc("getopoirequest", "\"550e8400-e29b-41d4-a716-446655440000\"")
        );

    OPoIRequest req;
    if (!g_opoiCache.GetRequest(params[0].get_str(), req))
        throw std::runtime_error("OPoI request not found: " + params[0].get_str());
    return OPoIRequestToUniValue(req);
}

// submitopoirequest "request_id" "model" "prompt_hash_hex" max_tokens payment "requester_address" ( fee_per_token task_type )
UniValue submitopoirequest(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 6 || params.size() > 12)
        throw std::runtime_error(
            "submitopoirequest \"request_id\" \"model\" \"prompt_hash_hex\""
            " max_tokens payment \"requester_address\""
            " ( fee_per_token task_type task_class test_suite_hex prompt_token_count is_canary )\n"
            "\nBroadcast an AI inference request transaction.\n"
            "\nThe actual prompt text is NOT stored on-chain — only its SHA-256 hash.\n"
            "Send the prompt directly to the miner's HTTP API after broadcasting.\n"
            "\nArguments:\n"
            "1. request_id        (string, required)  UUID for this request\n"
            "2. model             (string, required)  Model name — or a registered\n"
            "                     Model Manifest modelId (F15-A) to enable shard\n"
            "                     execution (getmodelgraph) for this request\n"
            "3. prompt_hash_hex   (string, required)  SHA-256 of the prompt as hex\n"
            "4. max_tokens        (numeric, required) Maximum tokens in the response\n"
            "5. payment           (numeric, required) Base CSCOIN reward for the miner —\n"
            "                     also the REQUEST's own budget floor (F11-A): must be >=\n"
            "                     nOPoIFeeBase + prompt_token_count * nOPoIFeePerToken\n"
            "6. requester_address (string, required)  Your CS wallet address\n"
            "7. fee_per_token     (numeric, optional) Extra fee per token generated (default: 0)\n"
            "8. task_type         (string, optional)  OPEN or VERIFIABLE (default: OPEN)\n"
            "9. task_class        (string, optional)  INTERACTIVE or BATCH (default: INTERACTIVE)\n"
            "                     F15-G: if model's dense pipeline is deeper than\n"
            "                     nOPoIMaxPipelineDepth, INTERACTIVE is rejected —\n"
            "                     use BATCH for models with a deep shard pipeline.\n"
            "10. test_suite_hex   (string, required if task_type=VERIFIABLE, or if\n"
            "                     is_canary=true) SHA-256 of the test suite an Auditor\n"
            "                     will check the response against (F14-C). A canary\n"
            "                     REQUEST must use getcanarytestsuite's hash exactly.\n"
            "11. prompt_token_count (numeric, optional) F11-A: your own estimate of the\n"
            "                     prompt's token count, self-declared (never verified —\n"
            "                     the prompt itself is never on-chain) — used only to\n"
            "                     compute this REQUEST's own minimum payment (see #5)\n"
            "12. is_canary        (bool, optional) F9-F: mark this as a canary audit —\n"
            "                     requires task_type=VERIFIABLE and test_suite_hex ==\n"
            "                     getcanarytestsuite's hash. A FAILed canary strikes the\n"
            "                     responding miner (see getopoistake's canary_strikes);\n"
            "                     3 strikes suspends the stake until renewopoistake.\n"
            "\nTotal miner payment = payment + actual_token_count * fee_per_token\n"
            "\nResult:\n"
            "\"txid\"  (string) Transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("submitopoirequest",
                "\"uuid\" \"gemma3:4b\" \"abc123...\" 512 1.0 \"t1Xyz...\"")
            + HelpExampleCli("submitopoirequest",
                "\"uuid\" \"qwen3:32b\" \"abc123...\" 2048 2.0 \"t1Xyz...\" 0.001 \"VERIFIABLE\"")
            + HelpExampleRpc("submitopoirequest",
                "\"uuid\", \"gemma3:4b\", \"abc123...\", 512, 1.0, \"t1Xyz...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId   = params[0].get_str();
    std::string model       = params[1].get_str();
    std::string phHex       = params[2].get_str();
    uint32_t    maxTok      = (uint32_t)params[3].get_int();
    CAmount     payment     = AmountFromValue(params[4]);
    std::string requester   = params[5].get_str();
    CAmount     feePerToken = (params.size() > 6) ? AmountFromValue(params[6]) : 0;
    int8_t      taskType    = OPOI_TASK_OPEN;
    if (params.size() > 7) {
        std::string tt = params[7].get_str();
        if (tt == "VERIFIABLE") taskType = OPOI_TASK_VERIFIABLE;
        else if (tt != "OPEN")  throw std::runtime_error("task_type must be OPEN or VERIFIABLE");
    }
    uint8_t     taskClass   = OPOI_TASKCLASS_INTERACTIVE;
    if (params.size() > 8) {
        std::string tc = params[8].get_str();
        if (tc == "BATCH") taskClass = OPOI_TASKCLASS_BATCH;
        else if (tc != "INTERACTIVE") throw std::runtime_error("task_class must be INTERACTIVE or BATCH");
    }
    uint256 testSuite;
    if (params.size() > 9) {
        testSuite.SetHex(params[9].get_str());
        if (testSuite.IsNull())
            throw std::runtime_error("test_suite_hex is invalid or all-zero");
    }
    uint32_t promptTokenCount = (params.size() > 10) ? (uint32_t)params[10].get_int() : 0;
    bool     isCanary         = (params.size() > 11) ? params[11].get_bool() : false;

    // Friendly pre-check mirroring CheckOPoITransaction's consensus rule (F14-B).
    if (taskType == OPOI_TASK_VERIFIABLE && testSuite.IsNull())
        throw std::runtime_error("task_type=VERIFIABLE requires a non-empty test_suite_hex");

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (model.empty())     throw std::runtime_error("model must not be empty");
    if (payment <= 0)      throw std::runtime_error("payment must be positive");

    uint256 promptHash;
    promptHash.SetHex(phHex);
    if (promptHash.IsNull())
        throw std::runtime_error("prompt_hash_hex is invalid or all-zero");

    // F15-G: friendly pre-check mirroring CheckOPoITransaction's consensus rule,
    // so the caller gets a clear error instead of a confusing mempool rejection.
    {
        ModelManifest manifest;
        if (g_opoiCache.GetModelManifest(model, manifest) && manifest.IsActive()
            && taskClass == OPOI_TASKCLASS_INTERACTIVE
            && (int)manifest.numDenseShards > Params().GetConsensus().nOPoIMaxPipelineDepth)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                "model %s has a %u-deep dense pipeline, too deep for INTERACTIVE "
                "(max %d) — resubmit with task_class=BATCH", manifest.modelId,
                manifest.numDenseShards, Params().GetConsensus().nOPoIMaxPipelineDepth));
    }

    // F11-A: friendly pre-check mirroring CheckOPoITransaction's consensus rule.
    {
        const Consensus::Params& p = Params().GetConsensus();
        CAmount minPayment = p.nOPoIFeeBase + (CAmount)promptTokenCount * p.nOPoIFeePerToken;
        if ((p.nOPoIFeeBase > 0 || p.nOPoIFeePerToken > 0) && payment < minPayment)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                "payment %s below required minimum %s (base %s + %u prompt tokens * %s)",
                FormatMoney(payment), FormatMoney(minPayment), FormatMoney(p.nOPoIFeeBase),
                promptTokenCount, FormatMoney(p.nOPoIFeePerToken)));
    }
    // F9-F: friendly pre-check mirroring CheckOPoITransaction's consensus rule.
    if (isCanary) {
        if (taskType != OPOI_TASK_VERIFIABLE)
            throw std::runtime_error("is_canary=true requires task_type=VERIFIABLE");
        if (testSuite != GetOPoICanaryTestSuiteHash())
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "is_canary=true requires test_suite_hex == " + GetOPoICanaryTestSuiteHash().GetHex());
    }

    CMutableTransaction mutTx;
    mutTx.nVersion       = OPOI_TX_VERSION;
    mutTx.nType          = OPOI_REQUEST_TX_TYPE;
    mutTx.opoiRequestId  = requestId;
    mutTx.opoiRequester  = requester;
    mutTx.opoiModel      = model;
    mutTx.opoiPromptHash = promptHash;
    mutTx.opoiMaxTokens  = maxTok;
    mutTx.opoiPayment    = payment;
    mutTx.opoiFeePerToken= feePerToken;
    mutTx.opoiTaskType   = taskType;
    mutTx.opoiTaskClass  = taskClass;
    mutTx.opoiTestSuite  = testSuite;
    mutTx.opoiPromptTokenCount = promptTokenCount;
    mutTx.opoiIsCanary         = isCanary ? 1 : 0;
    mutTx.opoiSigTime    = (uint32_t)GetTime();

    // Sign: requestId + requester + model + promptHashHex + maxTokens + payment + feePerToken + taskType + taskClass + testSuiteHex + promptTokenCount + isCanary
    std::string sigMsg = requestId + requester + model + phHex +
                         strprintf("%u%d%d%d%d", maxTok, payment, feePerToken, (int)taskType, (int)taskClass) +
                         testSuite.GetHex() +
                         strprintf("%u%d", promptTokenCount, (int)mutTx.opoiIsCanary);
    std::string errMsg;
    if (!SignWithAddress(requester, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for submitopoirequest");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",         tx.GetHash().GetHex());
    ret.pushKV("request_id",   requestId);
    ret.pushKV("task_type",    taskType == OPOI_TASK_VERIFIABLE ? "VERIFIABLE" : "OPEN");
    ret.pushKV("task_class",   taskClass == OPOI_TASKCLASS_BATCH ? "BATCH" : "INTERACTIVE");
    if (taskType == OPOI_TASK_VERIFIABLE)
        ret.pushKV("test_suite", testSuite.GetHex());
    ret.pushKV("fee_per_token",ValueFromAmount(feePerToken));
    return ret;
}

// F10-B: shared by submitopoiresponsecommit and submitopoiresponse so both
// sides of the RPC boundary agree on the preimage — must stay byte-identical
// to the hash CheckOPoITransaction recomputes in opoi.cpp's REVEAL branch.
static void ComputeResponseCommitHash(const uint256& responseHash, const uint256& commitment,
                                       uint32_t tokenCount, const std::vector<unsigned char>& nonce,
                                       unsigned char out[32])
{
    CSHA256 hasher;
    hasher.Write(responseHash.begin(), 32);
    hasher.Write(commitment.begin(), 32);
    std::string tokenStr = strprintf("%u", tokenCount);
    hasher.Write((const unsigned char*)tokenStr.data(), tokenStr.size());
    hasher.Write(nonce.data(), nonce.size());
    hasher.Finalize(out);
}

// submitopoiresponsecommit "request_id" "response_hash_hex" "miner_address" ( "commitment_hex" token_count "nonce_hex" )
UniValue submitopoiresponsecommit(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6)
        throw std::runtime_error(
            "submitopoiresponsecommit \"request_id\" \"response_hash_hex\" \"miner_address\""
            " ( \"commitment_hex\" token_count \"nonce_hex\" )\n"
            "\nOpen a commit-reveal RESPONSE (F10-B anti-copy protocol, COMMIT phase).\n"
            "\nresponse_hash/commitment/token_count are hidden behind a hash until the commit\n"
            "window closes (nOPoIResponseCommitWindowBlocks after the REQUEST confirmed) —\n"
            "disclose them later with submitopoiresponse, passing the SAME nonce_hex returned\n"
            "here. This is what stops a copy-cat: no answer is public while commits are\n"
            "still being accepted, so there's nothing yet for a rival to steal.\n"
            "\nArguments:\n"
            "1. request_id        (string, required)  UUID of the inference request\n"
            "2. response_hash_hex (string, required)  SHA-256 of the response text as hex\n"
            "3. miner_address     (string, required)  Miner's CS wallet address\n"
            "4. commitment_hex    (string, optional)  model_fixed_forward(reqHash||respHash) — anti-equivocation\n"
            "5. token_count       (numeric, optional) Actual tokens generated (for fee-per-token)\n"
            "6. nonce_hex         (string, optional)  Secret nonce — generated for you if omitted\n"
            "\nResult:\n"
            "{ txid, request_id, nonce_hex, commit_window_closes_at_height }\n"
            "\nExamples:\n"
            + HelpExampleCli("submitopoiresponsecommit",
                "\"uuid\" \"def456...\" \"t1MinerAddr...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId  = params[0].get_str();
    std::string rhHex      = params[1].get_str();
    std::string minerAddr  = params[2].get_str();
    std::string commitHex  = (params.size() > 3) ? params[3].get_str() : "";
    uint32_t    tokenCount = (params.size() > 4) ? (uint32_t)params[4].get_int() : 0;
    std::string nonceHex   = (params.size() > 5) ? params[5].get_str() : "";

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");

    uint256 responseHash;
    responseHash.SetHex(rhHex);
    if (responseHash.IsNull())
        throw std::runtime_error("response_hash_hex is invalid or all-zero");

    uint256 commitment;
    if (!commitHex.empty()) commitment.SetHex(commitHex);

    std::vector<unsigned char> nonce;
    if (!nonceHex.empty()) {
        nonce = ParseHex(nonceHex);
        if (nonce.empty()) throw std::runtime_error("nonce_hex is invalid");
    } else {
        nonce.resize(16);
        GetRandBytes(nonce.data(), nonce.size());
        nonceHex = HexStr(nonce);
    }

    OPoIRequest req;
    if (!g_opoiCache.GetRequest(requestId, req))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown request_id: " + requestId);
    if (req.commitWindowClosed)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "commit window already closed for request " + requestId);

    OPoIStake stake;
    if (!g_opoiCache.GetStake(minerAddr, stake) || !stake.IsActive())
        throw JSONRPCError(RPC_INVALID_PARAMETER, minerAddr + " is not an active OPoI staker");

    unsigned char commitHashBytes[32];
    ComputeResponseCommitHash(responseHash, commitment, tokenCount, nonce, commitHashBytes);

    CMutableTransaction mutTx;
    mutTx.nVersion            = OPOI_TX_VERSION;
    mutTx.nType               = OPOI_RESPONSE_TX_TYPE;
    mutTx.opoiRequestId       = requestId;
    mutTx.opoiMinerAddress    = minerAddr;
    mutTx.opoiResponsePhase   = 0; // COMMIT
    mutTx.opoiResponseCommitHash.assign(commitHashBytes, commitHashBytes + 32);
    mutTx.opoiSigTime         = (uint32_t)GetTime();

    std::string sigMsg = requestId + minerAddr + HexStr(commitHashBytes, commitHashBytes + 32);
    std::string errMsg;
    if (!SignWithAddress(minerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for submitopoiresponsecommit");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",       tx.GetHash().GetHex());
    ret.pushKV("request_id", requestId);
    ret.pushKV("nonce_hex",  nonceHex);
    ret.pushKV("commit_window_closes_at_height",
               (int)(req.blockHeight + Params().GetConsensus().nOPoIResponseCommitWindowBlocks));
    return ret;
}

// submitopoiresponse "request_id" "response_hash_hex" "miner_address" "commitment_hex" token_count "nonce_hex"
UniValue submitopoiresponse(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 6 || params.size() > 6)
        throw std::runtime_error(
            "submitopoiresponse \"request_id\" \"response_hash_hex\" \"miner_address\""
            " \"commitment_hex\" token_count \"nonce_hex\"\n"
            "\nDisclose a committed AI inference response (REVEAL phase, miner only).\n"
            "\nMust be preceded by submitopoiresponsecommit for the same request_id/miner_address,\n"
            "with the SAME response_hash_hex/commitment_hex/token_count/nonce_hex — and can only\n"
            "be broadcast once the commit window has closed (F10-B anti-copy: see\n"
            "submitopoiresponsecommit's commit_window_closes_at_height).\n"
            "\nArguments:\n"
            "1. request_id        (string, required)  UUID of the inference request\n"
            "2. response_hash_hex (string, required)  SHA-256 of the response text as hex\n"
            "3. miner_address     (string, required)  Miner's CS wallet address\n"
            "4. commitment_hex    (string, required)  model_fixed_forward(reqHash||respHash) — anti-equivocation.\n"
            "                     Pass \"\" if submitopoiresponsecommit was also called without it.\n"
            "5. token_count       (numeric, required) Actual tokens generated (for fee-per-token)\n"
            "6. nonce_hex         (string, required)  The nonce_hex returned by submitopoiresponsecommit\n"
            "\nResult:\n"
            "\"txid\"  (string) Transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("submitopoiresponse",
                "\"uuid\" \"def456...\" \"t1MinerAddr...\" \"\" 256 \"abcd1234...\"")
            + HelpExampleRpc("submitopoiresponse",
                "\"uuid\", \"def456...\", \"t1MinerAddr...\", \"\", 256, \"abcd1234...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId   = params[0].get_str();
    std::string rhHex       = params[1].get_str();
    std::string minerAddr   = params[2].get_str();
    std::string commitHex   = params[3].get_str();
    uint32_t    tokenCount  = (uint32_t)params[4].get_int();
    std::string nonceHex    = params[5].get_str();

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");
    if (nonceHex.empty())  throw std::runtime_error("nonce_hex must not be empty");

    uint256 responseHash;
    responseHash.SetHex(rhHex);
    if (responseHash.IsNull())
        throw std::runtime_error("response_hash_hex is invalid or all-zero");

    uint256 commitment;
    if (!commitHex.empty()) {
        commitment.SetHex(commitHex);
    }

    std::vector<unsigned char> nonce = ParseHex(nonceHex);
    if (nonce.empty()) throw std::runtime_error("nonce_hex is invalid");

    // Client-side pre-check (mirrors revealchallenge): catch a mismatched
    // nonce/hash here with a clear message instead of a bare consensus reject.
    {
        std::string committedHash;
        if (!g_opoiCache.GetResponseCommit(requestId, minerAddr, committedHash))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "no COMMIT found for " + minerAddr + " on request " + requestId +
                " — call submitopoiresponsecommit first");
        unsigned char computed[32];
        ComputeResponseCommitHash(responseHash, commitment, tokenCount, nonce, computed);
        if (committedHash != HexStr(computed, computed + 32))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "response_hash/commitment/token_count/nonce does not match the COMMIT stored earlier");
    }

    // F10-D: generate the VRF eligibility proof. Seed is anchored to the block the
    // REQUEST confirmed in (stable forever), NOT the current chain tip — bug fix
    // (2026-07-02): using the tip meant a proof went stale the moment any other
    // block was mined before this tx confirmed, since the tip is a moving target.
    OPoIRequest req;
    if (!g_opoiCache.GetRequest(requestId, req))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown request_id: " + requestId);

    OPoIStake stake;
    if (!g_opoiCache.GetStake(minerAddr, stake) || !stake.IsActive())
        throw JSONRPCError(RPC_INVALID_PARAMETER, minerAddr + " is not an active OPoI staker");
    if (stake.minerPubKey.size() != 33)
        throw std::runtime_error(minerAddr + " has no recorded pubkey (re-stake required after this upgrade)");

    CKey minerKey;
#ifdef ENABLE_WALLET
    CKeyID keyId = stake.minerPubKey.GetID();
    if (!pwalletMain || !pwalletMain->GetKey(keyId, minerKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for " + minerAddr + " not in wallet");
#endif

    CBlockIndex* pSeedBlock = chainActive[req.blockHeight];
    if (!pSeedBlock) throw std::runtime_error("cannot locate the request's confirmation block to derive VRF seed");
    unsigned char seed[32];
    {
        uint256 seedBlockHash = pSeedBlock->GetBlockHash();
        CSHA256 hasher;
        hasher.Write(seedBlockHash.begin(), 32);
        hasher.Write((const unsigned char*)requestId.data(), requestId.size());
        hasher.Finalize(seed);
    }
    std::vector<unsigned char> vrfProof;
    unsigned char pubKeyBytes[33];
    memcpy(pubKeyBytes, stake.minerPubKey.begin(), 33);
    if (!OPoIVRFProve(minerKey.begin(), pubKeyBytes, seed, 32, vrfProof))
        throw std::runtime_error("VRF proof generation failed");

    CMutableTransaction mutTx;
    mutTx.nVersion          = OPOI_TX_VERSION;
    mutTx.nType             = OPOI_RESPONSE_TX_TYPE;
    mutTx.opoiRequestId     = requestId;
    mutTx.opoiMinerAddress  = minerAddr;
    mutTx.opoiResponsePhase = 1; // REVEAL — bug fix (2026-07-02): this was never set before,
                                 // so responseHash/commitment/tokenCount were silently dropped
                                 // by the phase==0 branch of CTransaction's real serialization.
    mutTx.opoiResponseHash  = responseHash;
    mutTx.opoiCommitment    = commitment;
    mutTx.opoiTokenCount    = tokenCount;
    mutTx.opoiResponseNonce = nonce; // F10-B: disclosed now so CheckOPoITransaction can
                                      // recompute and match it against the stored COMMIT hash.
    mutTx.opoiVrfProof      = vrfProof;
    mutTx.opoiSigTime       = (uint32_t)GetTime();

    // Canonical form (both sides derive this from the typed tx fields, not raw
    // user-supplied hex strings, so signing and verification always agree
    // regardless of hex case/formatting the caller used). Deliberately excludes
    // the nonce — that's already bound by the commit-hash match check above, and
    // the signature formula must stay identical to what CheckOPoITransaction
    // verifies (see opoi.cpp), which predates F10-B and was never extended here.
    std::string sigMsg = requestId + minerAddr + responseHash.GetHex() + commitment.GetHex()
                        + strprintf("%u", tokenCount);
    std::string errMsg;
    if (!SignWithAddress(minerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for submitopoiresponse");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",        tx.GetHash().GetHex());
    ret.pushKV("request_id",  requestId);
    ret.pushKV("token_count", (int)tokenCount);
    return ret;
}

UniValue rebuilopoidb(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "rebuilopoidb\n"
            "\nRescan the entire blockchain and rebuild the OPoI in-memory cache.\n"
            "\nExamples:\n"
            + HelpExampleCli("rebuilopoidb", "")
            + HelpExampleRpc("rebuilopoidb", "")
        );

    RebuildOPoICache();
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("rebuilt",    true);
    ret.pushKV("requests",   (int)g_opoiCache.RequestCount());
    ret.pushKV("responses",  (int)g_opoiCache.ResponseCount());
    ret.pushKV("stakes",     (int)g_opoiCache.StakeCount());
    ret.pushKV("challenges", (int)g_opoiCache.ChallengeCount());
    return ret;
}

// ── opoivrfselftest (F10-D / F15-C) ──────────────────────────────────────────
// Runtime self-test for the hand-rolled ECVRF (opoi/opoi_vrf.cpp): generates a
// fresh keypair, proves + verifies a message, and confirms tampering / wrong
// message / wrong key are all correctly rejected. Exists so this can be
// exercised against the *actual running daemon* (not just a compile-time
// unit test) — see CS COIN OPoI MELHOR IMPLEMENTAÇÃO.txt's testing convention.

UniValue opoivrfselftest(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "opoivrfselftest\n"
            "\nRuns an internal ECVRF prove/verify self-test against a freshly\n"
            "generated ephemeral keypair (not derived from the wallet).\n"
            "\nResult:\n"
            "{ prove_ok, verify_ok, tamper_rejected, wrong_message_rejected,\n"
            "  wrong_key_rejected, deterministic, all_pass, proof_hex, output_hex }\n"
            "\nExamples:\n"
            + HelpExampleCli("opoivrfselftest", "")
        );

    CKey testKey;
    testKey.MakeNewKey(true);
    CPubKey testPubKey = testKey.GetPubKey();
    if (testPubKey.size() != 33)
        throw std::runtime_error("internal error: expected compressed 33-byte pubkey");

    CKey otherKey;
    otherKey.MakeNewKey(true);
    CPubKey otherPubKey = otherKey.GetPubKey();

    std::string alpha = "opoi-vrf-selftest-message";
    const unsigned char* alphaBytes = (const unsigned char*)alpha.data();

    std::vector<unsigned char> proof;
    bool proveOk = OPoIVRFProve(testKey.begin(), testPubKey.begin(), alphaBytes, alpha.size(), proof);

    unsigned char output[32] = {0};
    bool verifyOk = proveOk && OPoIVRFVerify(testPubKey.begin(), alphaBytes, alpha.size(), proof, output);

    bool tamperRejected = false;
    if (proveOk) {
        std::vector<unsigned char> tampered = proof;
        tampered[0] ^= 0x01;
        unsigned char dummy[32];
        tamperRejected = !OPoIVRFVerify(testPubKey.begin(), alphaBytes, alpha.size(), tampered, dummy);
    }

    bool wrongMessageRejected = false;
    if (proveOk) {
        std::string wrongAlpha = "a-different-message";
        unsigned char dummy[32];
        wrongMessageRejected = !OPoIVRFVerify(testPubKey.begin(),
            (const unsigned char*)wrongAlpha.data(), wrongAlpha.size(), proof, dummy);
    }

    bool wrongKeyRejected = false;
    if (proveOk) {
        unsigned char dummy[32];
        wrongKeyRejected = !OPoIVRFVerify(otherPubKey.begin(), alphaBytes, alpha.size(), proof, dummy);
    }

    std::vector<unsigned char> proof2;
    bool prove2Ok = OPoIVRFProve(testKey.begin(), testPubKey.begin(), alphaBytes, alpha.size(), proof2);
    bool deterministic = prove2Ok && proof == proof2;

    bool allPass = proveOk && verifyOk && tamperRejected && wrongMessageRejected
                 && wrongKeyRejected && deterministic;

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("prove_ok",               proveOk);
    ret.pushKV("verify_ok",              verifyOk);
    ret.pushKV("tamper_rejected",        tamperRejected);
    ret.pushKV("wrong_message_rejected", wrongMessageRejected);
    ret.pushKV("wrong_key_rejected",     wrongKeyRejected);
    ret.pushKV("deterministic",          deterministic);
    ret.pushKV("all_pass",               allPass);
    ret.pushKV("proof_hex",              HexStr(proof));
    ret.pushKV("output_hex",             HexStr(std::vector<unsigned char>(output, output + 32)));
    return ret;
}

// ── opoivrfverifyraw (F15-H cross-language test) ─────────────────────────────
// Verifies an externally-supplied VRF proof against an externally-supplied
// pubkey/message — unlike opoivrfselftest (which only exercises a keypair it
// generates itself), this lets a proof computed OUTSIDE this process (e.g. by
// cs-miner's Rust implementation) be checked against this daemon's C++
// verifier. This is the actual correctness property F15-H depends on: cs-miner
// generates proofs the daemon must accept, in a different language entirely.

UniValue opoivrfverifyraw(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "opoivrfverifyraw \"pubkey_hex\" \"alpha_hex\" \"proof_hex\"\n"
            "\nVerifies an externally-generated VRF proof (81 bytes) against an\n"
            "externally-supplied compressed pubkey (33 bytes) and message. Exists to\n"
            "test cross-language compatibility (e.g. cs-miner's Rust VRF implementation\n"
            "against this daemon's C++ one) without needing a live stake/request.\n"
            "\nArguments:\n"
            "1. pubkey_hex  (string, required) 33-byte compressed pubkey, hex\n"
            "2. alpha_hex   (string, required) message bytes, hex\n"
            "3. proof_hex   (string, required) 81-byte VRF proof, hex\n"
            "\nResult:\n"
            "{ valid, output_hex }\n"
            "\nExamples:\n"
            + HelpExampleCli("opoivrfverifyraw", "\"02abcd...\" \"646561646265656600\" \"03aabb...\"")
        );

    std::vector<unsigned char> pkBytes  = ParseHex(params[0].get_str());
    std::vector<unsigned char> alpha    = ParseHex(params[1].get_str());
    std::vector<unsigned char> proof    = ParseHex(params[2].get_str());

    UniValue ret(UniValue::VOBJ);
    if (pkBytes.size() != OPOI_VRF_PK_SIZE) {
        ret.pushKV("valid", false);
        ret.pushKV("output_hex", "");
        ret.pushKV("error", "pubkey_hex must decode to exactly 33 bytes");
        return ret;
    }

    unsigned char output[32] = {0};
    bool valid = OPoIVRFVerify(pkBytes.data(), alpha.data(), alpha.size(), proof, output);

    ret.pushKV("valid", valid);
    ret.pushKV("output_hex", valid ? HexStr(std::vector<unsigned char>(output, output + 32)) : "");
    return ret;
}

// ── opoiselecttopkexperts (F15-H cross-language test) ────────────────────────
// Exposes SelectTopKExperts (opoi_shard.h) directly so cs-miner's Rust mirror
// (expert_router.rs) can be checked for byte-for-byte agreement without
// needing a live Model Manifest/request — the two MUST always agree, since
// CheckOPoITransaction uses this to gate which EXPERT shard submissions are
// valid, and cs-miner uses its own copy to decide what to attempt.

UniValue opoiselecttopkexperts(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw std::runtime_error(
            "opoiselecttopkexperts \"request_id\" \"prompt_hash_hex\" num_experts top_k\n"
            "\nReturns the deterministic top-k expert selection for arbitrary inputs —\n"
            "exists purely to cross-check cs-miner's Rust mirror of this algorithm.\n"
            "\nResult:\n"
            "{ selected: [ints] }\n"
        );

    std::string requestId = params[0].get_str();
    uint256 promptHash;
    promptHash.SetHex(params[1].get_str());
    uint32_t numExperts = (uint32_t)params[2].get_int64();
    uint32_t topK       = (uint32_t)params[3].get_int64();

    auto selected = SelectTopKExperts(requestId, promptHash, numExperts, topK);

    UniValue arr(UniValue::VARR);
    for (uint32_t e : selected) arr.push_back((int)e);
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("selected", arr);
    return ret;
}

// ── Phase 3 helpers ───────────────────────────────────────────────────────────

static std::string StakeStatusStr(int8_t s) {
    switch (s) {
        case OPOI_STAKE_ACTIVE:    return "ACTIVE";
        case OPOI_STAKE_UNSTAKING: return "UNSTAKING";
        case OPOI_STAKE_RELEASED:  return "RELEASED";
        case OPOI_STAKE_SLASHED:   return "SLASHED";
        case OPOI_STAKE_SUSPENDED: return "SUSPENDED"; // F9-E/F9-F: renewal overdue or 3 canary strikes
        default:                   return "UNKNOWN";
    }
}

static std::string ChallengeStatusStr(int8_t s) {
    switch (s) {
        case OPOI_CHALLENGE_OPEN:              return "OPEN";
        case OPOI_CHALLENGE_SLASHED:           return "SLASHED";
        case OPOI_CHALLENGE_EXPIRED:           return "EXPIRED";
        case OPOI_CHALLENGE_REVEALED_PENDING:  return "REVEALED_PENDING";
        case OPOI_CHALLENGE_RESOLVED_NO_ORACLE:return "RESOLVED_NO_ORACLE";
        default:                                return "UNKNOWN";
    }
}

static UniValue OPoIStakeToUniValue(const OPoIStake& s)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("miner_address",  s.minerAddress);
    obj.pushKV("collateral_txid",s.collateralIn.hash.GetHex());
    obj.pushKV("collateral_vout",(int)s.collateralIn.n);
    obj.pushKV("amount",         ValueFromAmount(s.amount));
    obj.pushKV("model_id",       s.modelId);
    obj.pushKV("tier",           (int)s.tier);
    obj.pushKV("pom_root",       s.pomRoot.GetHex());
    obj.pushKV("block_height",   (int)s.blockHeight);
    obj.pushKV("status",         StakeStatusStr(s.stakeStatus));
    obj.pushKV("unstake_height", (int)s.unstakeHeight);
    obj.pushKV("tx_hash",        s.txHash.GetHex());
    UniValue experts(UniValue::VARR);
    for (uint32_t e : s.hostedExpertIds) experts.push_back((int)e);
    obj.pushKV("hosted_expert_ids", experts);
    obj.pushKV("endpoint", s.endpoint);
    // F10-C: on-chain reputation
    obj.pushKV("reputation_score",      s.ReputationScore());
    obj.pushKV("responses_total",       (int)s.responsesTotal);
    obj.pushKV("responses_challenged",  (int)s.responsesChallenged);
    obj.pushKV("responses_slashed",     (int)s.responsesSlashed);
    // F9-E/F9-F: renewal + canary-strike visibility
    obj.pushKV("last_renewal_height",   (int)s.lastRenewalHeight);
    obj.pushKV("canary_strikes",        (int)s.canaryStrikes);
    return obj;
}

static UniValue OPoIChallengeToUniValue(const OPoIChallenge& c)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("request_id",           c.requestId);
    obj.pushKV("challenger_address",   c.challengerAddress);
    obj.pushKV("collateral_txid",      c.challengerCollateral.hash.GetHex());
    obj.pushKV("collateral_vout",      (int)c.challengerCollateral.n);
    obj.pushKV("phase",                c.phase == 0 ? "COMMIT" : "REVEAL");
    obj.pushKV("commit_hash",          c.commitHash);
    obj.pushKV("commit_height",        (int)c.commitHeight);
    if (c.IsRevealPhase())
        obj.pushKV("fraud_proof",      HexStr(c.fraudProof));
    obj.pushKV("block_height",         (int)c.blockHeight);
    obj.pushKV("status",               ChallengeStatusStr(c.challengeStatus));
    obj.pushKV("tx_hash",              c.txHash.GetHex());
    return obj;
}

// ── stakeopoi ─────────────────────────────────────────────────────────────────

UniValue stakeopoi(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 8)
        throw std::runtime_error(
            "stakeopoi \"miner_address\" \"collateral_txid\" collateral_vout"
            " ( hosted_expert_ids endpoint \"model_id\" tier \"pom_root\" )\n"
            "\nRegister an OPoI stake for a miner.\n"
            "\nThe referenced UTXO must be >= the network minimum stake (100 CS on mainnet).\n"
            "\nArguments:\n"
            "1. miner_address       (string, required) Miner's CS wallet address\n"
            "2. collateral_txid     (string, required) TXID of the collateral UTXO\n"
            "3. collateral_vout     (numeric, required) Output index of the collateral UTXO\n"
            "4. hosted_expert_ids   (array, optional) F15-E: MoE expert IDs this miner hosts\n"
            "5. endpoint            (string, optional) F15-H: \"host:port\" this miner's\n"
            "                       cs-miner HTTP API is reachable at, for coordinator\n"
            "                       shard relay. Omit if not reachable (e.g. behind NAT).\n"
            "6. model_id            (string, optional) F9-B: model this miner declares hosting,\n"
            "                       e.g. \"GEMMA_3_4B\" — F15-H peer discovery (model_fetch)\n"
            "                       filters candidates by this field, so it must be set for a\n"
            "                       miner to be found as a P2P source for that model_id.\n"
            "7. tier                (numeric, optional) F9-B/F9-G: 0=light/1=default/2=high/\n"
            "                       3=veryhigh/4=titan. Purely self-declared (no hardware\n"
            "                       verification exists for ANY tier, 0-3 included).\n"
            "8. pom_root            (string, optional) F9-B: Merkle root of the GGUF this miner\n"
            "                       proved hosting via Proof-of-Model. Not consensus-enforced\n"
            "                       against anything yet (recorded only).\n"
            "\nResult:\n"
            "{ txid, miner_address }\n"
            "\nExamples:\n"
            + HelpExampleCli("stakeopoi", "\"t1MinerAddr...\" \"abc123...\" 0")
            + HelpExampleCli("stakeopoi", "\"t1MinerAddr...\" \"abc123...\" 0 \"[0,1]\" \"1.2.3.4:3500\"")
            + HelpExampleCli("stakeopoi", "\"t1MinerAddr...\" \"abc123...\" 0 \"[]\" \"1.2.3.4:3500\" \"GEMMA_3_4B\" 1")
            + HelpExampleRpc("stakeopoi", "\"t1MinerAddr...\", \"abc123...\", 0")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string minerAddr = params[0].get_str();
    uint256     colTxid;
    colTxid.SetHex(params[1].get_str());
    uint32_t    colVout   = (uint32_t)params[2].get_int();

    std::vector<uint32_t> hostedExpertIds;
    if (params.size() > 3) {
        UniValue arr = params[3].get_array();
        for (unsigned int i = 0; i < arr.size(); i++)
            hostedExpertIds.push_back((uint32_t)arr[i].get_int64());
    }
    std::string endpoint = (params.size() > 4) ? params[4].get_str() : "";
    std::string modelId  = (params.size() > 5) ? params[5].get_str() : "";
    uint8_t     tier      = (params.size() > 6) ? (uint8_t)params[6].get_int64() : 0;
    uint256     pomRoot;
    if (params.size() > 7) pomRoot.SetHex(params[7].get_str());

    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");
    if (colTxid.IsNull())  throw std::runtime_error("collateral_txid is invalid");

    // Look up the UTXO to get its value
    COutPoint colOut(colTxid, colVout);
    CCoins coins;
    CAmount stakeAmount = 0;
    {
        LOCK(cs_main);
        CCoinsViewCache view(pcoinsTip);
        if (!view.GetCoins(colTxid, coins) || colVout >= coins.vout.size() || coins.vout[colVout].IsNull())
            throw std::runtime_error("collateral UTXO not found in the UTXO set");
        stakeAmount = coins.vout[colVout].nValue;
    }

    const CChainParams& chainparams = Params();
    CAmount minStake = chainparams.GetConsensus().nOPoIMinStake;
    if (stakeAmount < minStake)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Collateral value %.4f CS is below minimum stake %.4f CS",
                      (double)stakeAmount / COIN, (double)minStake / COIN));

    CMutableTransaction mutTx;
    mutTx.nVersion        = OPOI_TX_VERSION;
    mutTx.nType           = OPOI_STAKE_TX_TYPE;
    mutTx.opoiMinerAddress= minerAddr;
    mutTx.opoiCollateralIn= colOut;
    mutTx.opoiPayment     = stakeAmount;
    mutTx.opoiHostedExpertIds = hostedExpertIds;
    mutTx.opoiEndpoint    = endpoint;
    mutTx.opoiModelId     = modelId;
    mutTx.opoiTier        = tier;
    mutTx.opoiPomRoot     = pomRoot;
    mutTx.opoiSigTime     = (uint32_t)GetTime();

    std::string sigMsg = minerAddr + colTxid.GetHex() + strprintf("%u", colVout);
    std::string errMsg;
    if (!SignWithAddress(minerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for stakeopoi");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",          tx.GetHash().GetHex());
    ret.pushKV("miner_address", minerAddr);
    ret.pushKV("amount",        ValueFromAmount(stakeAmount));
    return ret;
}

// ── unstakeopoi ───────────────────────────────────────────────────────────────

UniValue unstakeopoi(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "unstakeopoi \"miner_address\"\n"
            "\nBegin the unstake cooldown for a miner.\n"
            "\nThe collateral is released after nOPoIUnstakeCooldownBlocks blocks.\n"
            "\nArguments:\n"
            "1. miner_address  (string, required) Miner's CS wallet address\n"
            "\nResult:\n"
            "{ txid, miner_address, cooldown_blocks }\n"
            "\nExamples:\n"
            + HelpExampleCli("unstakeopoi", "\"t1MinerAddr...\"")
            + HelpExampleRpc("unstakeopoi", "\"t1MinerAddr...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string minerAddr = params[0].get_str();
    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");

    if (!g_opoiCache.IsActiveStaker(minerAddr))
        throw JSONRPCError(RPC_INVALID_PARAMETER, minerAddr + " is not an active OPoI staker");

    CMutableTransaction mutTx;
    mutTx.nVersion         = OPOI_TX_VERSION;
    mutTx.nType            = OPOI_UNSTAKE_TX_TYPE;
    mutTx.opoiMinerAddress = minerAddr;
    mutTx.opoiSigTime      = (uint32_t)GetTime();

    std::string sigMsg = std::string("UNSTAKE") + minerAddr;
    std::string errMsg;
    if (!SignWithAddress(minerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for unstakeopoi");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",           tx.GetHash().GetHex());
    ret.pushKV("miner_address",  minerAddr);
    ret.pushKV("cooldown_blocks",(int)Params().GetConsensus().nOPoIUnstakeCooldownBlocks);
    return ret;
}

// ── renewopoistake (F9-E/F9-F) ─────────────────────────────────────────────────

UniValue renewopoistake(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "renewopoistake \"miner_address\"\n"
            "\nProve continued liveness for an OPoI stake (F9-E) — resets the\n"
            "nOPoIStakeRenewalBlocks clock and (F9-F) clears any canary strikes,\n"
            "lifting a SUSPENDED status back to ACTIVE. No collateral involved:\n"
            "unlike a fresh stakeopoi call, this never touches the miner's locked\n"
            "collateral. Works for either an ACTIVE stake approaching its renewal\n"
            "deadline, or one already SUSPENDED (renewal overdue, or 3 canary\n"
            "strikes) — never for UNSTAKING/RELEASED/SLASHED.\n"
            "\nArguments:\n"
            "1. miner_address  (string, required) Miner's CS wallet address\n"
            "\nResult:\n"
            "{ txid, miner_address }\n"
            "\nExamples:\n"
            + HelpExampleCli("renewopoistake", "\"t1MinerAddr...\"")
            + HelpExampleRpc("renewopoistake", "\"t1MinerAddr...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string minerAddr = params[0].get_str();
    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");

    OPoIStake stake;
    if (!g_opoiCache.GetStake(minerAddr, stake)
        || (stake.stakeStatus != OPOI_STAKE_ACTIVE && stake.stakeStatus != OPOI_STAKE_SUSPENDED))
        throw JSONRPCError(RPC_INVALID_PARAMETER, minerAddr + " has no ACTIVE or SUSPENDED OPoI stake to renew");

    CMutableTransaction mutTx;
    mutTx.nVersion         = OPOI_TX_VERSION;
    mutTx.nType            = OPOI_RENEW_TX_TYPE;
    mutTx.opoiMinerAddress = minerAddr;
    mutTx.opoiSigTime      = (uint32_t)GetTime();

    std::string sigMsg = std::string("RENEW") + minerAddr;
    std::string errMsg;
    if (!SignWithAddress(minerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for renewopoistake");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",          tx.GetHash().GetHex());
    ret.pushKV("miner_address", minerAddr);
    return ret;
}

// ── getcanarytestsuite (F9-F) ───────────────────────────────────────────────────

UniValue getcanarytestsuite(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getcanarytestsuite\n"
            "\nReturns the single test_suite hash every canary REQUEST (F9-F,\n"
            "is_canary=true in submitopoirequest) must use — pinned, identical on\n"
            "every network, since an Auditor grades it off-chain either way.\n"
            "\nResult:\n"
            "\"hash_hex\"  (string)\n"
            "\nExamples:\n"
            + HelpExampleCli("getcanarytestsuite", "")
            + HelpExampleRpc("getcanarytestsuite", "")
        );
    return GetOPoICanaryTestSuiteHash().GetHex();
}

// ── challengeopoi (F8-C/F10-A: COMMIT phase) ───────────────────────────────────

UniValue challengeopoi(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
        throw std::runtime_error(
            "challengeopoi \"request_id\" \"challenger_address\" \"commit_hash\""
            " \"collateral_txid\" collateral_vout\n"
            "\nOpen a commit-reveal challenge against a committed RESPONSE (COMMIT phase).\n"
            "\ncommit_hash = SHA-256(fraud_proof || secret_nonce) computed by the caller —\n"
            "the fraud_proof and nonce themselves are disclosed later via revealchallenge,\n"
            "so a copy-cat can't front-run a challenge it can see in the mempool.\n"
            "\nRequires collateral >= (challenged miner's stake * nOPoIChallengerStakePct / 100).\n"
            "If REVEAL doesn't arrive within nOPoIChallengeCommitRevealBlocks, the challenge is\n"
            "dismissed and this collateral is permanently locked (burned) — see revealchallenge.\n"
            "\nArguments:\n"
            "1. request_id        (string, required) UUID of the disputed request\n"
            "2. challenger_address(string, required) Your CS wallet address\n"
            "3. commit_hash        (string, required) hex SHA-256(fraud_proof||nonce)\n"
            "4. collateral_txid    (string, required) TXID of the challenger's collateral UTXO\n"
            "5. collateral_vout    (numeric, required) Output index of the collateral UTXO\n"
            "\nResult:\n"
            "{ txid, request_id, challenged_miner }\n"
            "\nExamples:\n"
            + HelpExampleCli("challengeopoi",
                "\"uuid\" \"t1ChalAddr...\" \"abc123...\" \"def456...\" 0")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId    = params[0].get_str();
    std::string challenger   = params[1].get_str();
    std::string commitHashHex= params[2].get_str();
    uint256     colTxid;
    colTxid.SetHex(params[3].get_str());
    uint32_t    colVout      = (uint32_t)params[4].get_int();

    if (requestId.empty())    throw std::runtime_error("request_id must not be empty");
    if (challenger.empty())   throw std::runtime_error("challenger_address must not be empty");
    if (colTxid.IsNull())     throw std::runtime_error("collateral_txid is invalid");

    std::vector<unsigned char> commitHash = ParseHex(commitHashHex);
    if (commitHash.size() != 32)
        throw std::runtime_error("commit_hash must be exactly 32 bytes (64 hex chars)");

    OPoIResponse resp;
    if (!g_opoiCache.GetResponse(requestId, resp))
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "No committed response found for request " + requestId);

    OPoIStake minerStake;
    if (!g_opoiCache.GetStake(resp.minerAddress, minerStake))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "challenged miner has no stake on record");

    COutPoint colOut(colTxid, colVout);
    CCoins coins;
    CAmount collateralAmount = 0;
    {
        LOCK(cs_main);
        CCoinsViewCache view(pcoinsTip);
        if (!view.GetCoins(colTxid, coins) || colVout >= coins.vout.size() || coins.vout[colVout].IsNull())
            throw std::runtime_error("collateral UTXO not found in the UTXO set");
        collateralAmount = coins.vout[colVout].nValue;
    }
    CAmount minCollateral = (minerStake.amount * Params().GetConsensus().nOPoIChallengerStakePct) / 100;
    if (collateralAmount < minCollateral)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Collateral value %.4f CS is below minimum %.4f CS (%d%% of miner's %.4f CS stake)",
                      (double)collateralAmount / COIN, (double)minCollateral / COIN,
                      Params().GetConsensus().nOPoIChallengerStakePct, (double)minerStake.amount / COIN));

    CMutableTransaction mutTx;
    mutTx.nVersion                  = OPOI_TX_VERSION;
    mutTx.nType                     = OPOI_CHALLENGE_TX_TYPE;
    mutTx.opoiRequestId             = requestId;
    mutTx.opoiRequester             = challenger;
    mutTx.opoiChallengePhase        = 0;
    mutTx.opoiCommitHash            = commitHash;
    mutTx.opoiChallengerCollateralIn= colOut;
    mutTx.opoiSigTime               = (uint32_t)GetTime();

    std::string sigMsg = requestId + challenger + commitHashHex
                       + colTxid.GetHex() + strprintf("%u", colVout);
    std::string errMsg;
    if (!SignWithAddress(challenger, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for challengeopoi");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",             tx.GetHash().GetHex());
    ret.pushKV("request_id",       requestId);
    ret.pushKV("challenged_miner", resp.minerAddress);
    ret.pushKV("reveal_deadline_blocks", (int)Params().GetConsensus().nOPoIChallengeCommitRevealBlocks);
    return ret;
}

// ── revealchallenge (F8-C: REVEAL phase) ───────────────────────────────────────

UniValue revealchallenge(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw std::runtime_error(
            "revealchallenge \"request_id\" \"challenger_address\" \"fraud_proof\" \"nonce\"\n"
            "\nDisclose the fraud_proof + nonce for an open challenge (REVEAL phase).\n"
            "\nMust match the commit_hash from challengeopoi's COMMIT, and must arrive within\n"
            "nOPoIChallengeCommitRevealBlocks of it, or the challenge is dismissed and this\n"
            "collateral is burned instead. For a VERIFIABLE request, resolution follows the\n"
            "Auditor majority (F14-C) — a matching reveal alone never proves inference fraud\n"
            "by itself, it only proves the challenger's claim hasn't changed since COMMIT.\n"
            "\nArguments:\n"
            "1. request_id         (string, required) UUID of the disputed request\n"
            "2. challenger_address (string, required) Same address used in challengeopoi\n"
            "3. fraud_proof        (string, required) hex — the evidence committed to earlier\n"
            "4. nonce               (string, required) hex — the secret nonce committed to earlier\n"
            "\nResult:\n"
            "{ txid, request_id }\n"
            "\nExamples:\n"
            + HelpExampleCli("revealchallenge",
                "\"uuid\" \"t1ChalAddr...\" \"abc123...\" \"deadbeef...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId  = params[0].get_str();
    std::string challenger = params[1].get_str();
    std::vector<unsigned char> proofData = ParseHex(params[2].get_str());
    std::vector<unsigned char> nonce     = ParseHex(params[3].get_str());

    if (requestId.empty())  throw std::runtime_error("request_id must not be empty");
    if (challenger.empty()) throw std::runtime_error("challenger_address must not be empty");
    if (proofData.empty())  throw std::runtime_error("fraud_proof must not be empty");
    if (nonce.empty())      throw std::runtime_error("nonce must not be empty");

    OPoIChallenge ch;
    if (!g_opoiCache.GetChallenge(requestId, ch) || !ch.IsOpen())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "no open COMMIT found for request " + requestId);
    if (ch.challengerAddress != challenger)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "challenger_address does not match the open COMMIT");

    unsigned char computed[32];
    {
        CSHA256 hasher;
        hasher.Write(proofData.data(), proofData.size());
        hasher.Write(nonce.data(), nonce.size());
        hasher.Finalize(computed);
    }
    if (ch.commitHash != HexStr(computed, computed + 32))
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "fraud_proof/nonce does not match the commit_hash stored at COMMIT time");

    CMutableTransaction mutTx;
    mutTx.nVersion                  = OPOI_TX_VERSION;
    mutTx.nType                     = OPOI_CHALLENGE_TX_TYPE;
    mutTx.opoiRequestId             = requestId;
    mutTx.opoiRequester             = challenger;
    mutTx.opoiChallengePhase        = 1;
    mutTx.opoiProofData             = proofData;
    mutTx.opoiChallengeNonce        = nonce;
    mutTx.opoiChallengerCollateralIn= ch.challengerCollateral;
    mutTx.opoiSigTime               = (uint32_t)GetTime();

    std::string sigMsg = requestId + challenger + HexStr(proofData) + HexStr(nonce);
    std::string errMsg;
    if (!SignWithAddress(challenger, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for revealchallenge");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",       tx.GetHash().GetHex());
    ret.pushKV("request_id", requestId);
    return ret;
}

// ── listopoistakes ────────────────────────────────────────────────────────────

UniValue listopoistakes(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "listopoistakes ( \"status\" )\n"
            "\nList OPoI miner stakes.\n"
            "\nArguments:\n"
            "1. status  (string, optional) ACTIVE | UNSTAKING | RELEASED | SLASHED\n"
            "\nExamples:\n"
            + HelpExampleCli("listopoistakes", "")
            + HelpExampleCli("listopoistakes", "\"ACTIVE\"")
            + HelpExampleRpc("listopoistakes", "\"ACTIVE\"")
        );

    int8_t statusFilter = -1;
    if (params.size() == 1) {
        std::string s = params[0].get_str();
        if      (s == "ACTIVE")    statusFilter = OPOI_STAKE_ACTIVE;
        else if (s == "UNSTAKING") statusFilter = OPOI_STAKE_UNSTAKING;
        else if (s == "RELEASED")  statusFilter = OPOI_STAKE_RELEASED;
        else if (s == "SLASHED")   statusFilter = OPOI_STAKE_SLASHED;
        else throw std::runtime_error("Invalid status. Use ACTIVE, UNSTAKING, RELEASED or SLASHED.");
    }

    UniValue arr(UniValue::VARR);
    for (const auto& s : g_opoiCache.ListStakes())
        if (statusFilter < 0 || s.stakeStatus == statusFilter)
            arr.push_back(OPoIStakeToUniValue(s));
    return arr;
}

// ── getopoistake ──────────────────────────────────────────────────────────────

UniValue getopoistake(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getopoistake \"miner_address\"\n"
            "\nGet stake info for a specific miner.\n"
            "\nArguments:\n"
            "1. miner_address  (string, required)\n"
            "\nExamples:\n"
            + HelpExampleCli("getopoistake", "\"t1MinerAddr...\"")
            + HelpExampleRpc("getopoistake", "\"t1MinerAddr...\"")
        );

    OPoIStake stake;
    if (!g_opoiCache.GetStake(params[0].get_str(), stake))
        throw std::runtime_error("OPoI stake not found for: " + params[0].get_str());
    return OPoIStakeToUniValue(stake);
}

// ── listopoichallenges ────────────────────────────────────────────────────────

UniValue listopoichallenges(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "listopoichallenges ( \"status\" )\n"
            "\nList OPoI challenges.\n"
            "\nArguments:\n"
            "1. status  (string, optional) OPEN | SLASHED | EXPIRED | REVEALED_PENDING | RESOLVED_NO_ORACLE\n"
            "\nExamples:\n"
            + HelpExampleCli("listopoichallenges", "")
            + HelpExampleCli("listopoichallenges", "\"OPEN\"")
            + HelpExampleRpc("listopoichallenges", "\"OPEN\"")
        );

    int8_t statusFilter = -1;
    if (params.size() == 1) {
        std::string s = params[0].get_str();
        if      (s == "OPEN")               statusFilter = OPOI_CHALLENGE_OPEN;
        else if (s == "SLASHED")            statusFilter = OPOI_CHALLENGE_SLASHED;
        else if (s == "EXPIRED")            statusFilter = OPOI_CHALLENGE_EXPIRED;
        else if (s == "REVEALED_PENDING")   statusFilter = OPOI_CHALLENGE_REVEALED_PENDING;
        else if (s == "RESOLVED_NO_ORACLE") statusFilter = OPOI_CHALLENGE_RESOLVED_NO_ORACLE;
        else throw std::runtime_error("Invalid status. Use OPEN, SLASHED, EXPIRED, REVEALED_PENDING or RESOLVED_NO_ORACLE.");
    }

    UniValue arr(UniValue::VARR);
    for (const auto& c : g_opoiCache.ListChallenges(statusFilter))
        arr.push_back(OPoIChallengeToUniValue(c));
    return arr;
}

// ── getopoistats ──────────────────────────────────────────────────────────────

UniValue getopoistats(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getopoistats\n"
            "\nReturn aggregated OPoI network statistics.\n"
            "\nResult:\n"
            "{ requests:{total,pending,fulfilled,expired}, responses:{total},\n"
            "  stakes:{total,active,slashed,unstaking}, challenges:{total,open,slashed},\n"
            "  payments:{total_cs} }\n"
            "\nExamples:\n"
            + HelpExampleCli("getopoistats", "")
            + HelpExampleRpc("getopoistats", "")
        );

    auto reqs       = g_opoiCache.ListRequests();
    auto resps      = g_opoiCache.ListResponses();
    auto stakes     = g_opoiCache.ListStakes();
    auto challenges = g_opoiCache.ListChallenges();

    int pending=0, fulfilled=0, expired=0;
    CAmount totalPayments = 0;
    for (const auto& r : reqs) {
        switch (r.status) {
            case OPOI_STATUS_PENDING:   ++pending;   break;
            case OPOI_STATUS_FULFILLED: ++fulfilled; break;
            case OPOI_STATUS_EXPIRED:   ++expired;   break;
        }
        totalPayments += r.payment;
    }

    int activeStakes=0, slashedStakes=0, unstakingStakes=0;
    for (const auto& s : stakes) {
        switch (s.stakeStatus) {
            case OPOI_STAKE_ACTIVE:    ++activeStakes;    break;
            case OPOI_STAKE_SLASHED:   ++slashedStakes;   break;
            case OPOI_STAKE_UNSTAKING: ++unstakingStakes; break;
        }
    }

    int openChallenges=0, slashedChallenges=0;
    for (const auto& c : challenges) {
        if (c.challengeStatus == OPOI_CHALLENGE_OPEN)    ++openChallenges;
        if (c.challengeStatus == OPOI_CHALLENGE_SLASHED) ++slashedChallenges;
    }

    UniValue reqObj(UniValue::VOBJ);
    reqObj.pushKV("total",     (int)reqs.size());
    reqObj.pushKV("pending",   pending);
    reqObj.pushKV("fulfilled", fulfilled);
    reqObj.pushKV("expired",   expired);

    UniValue respObj(UniValue::VOBJ);
    respObj.pushKV("total", (int)resps.size());

    UniValue stakeObj(UniValue::VOBJ);
    stakeObj.pushKV("total",    (int)stakes.size());
    stakeObj.pushKV("active",   activeStakes);
    stakeObj.pushKV("slashed",  slashedStakes);
    stakeObj.pushKV("unstaking",unstakingStakes);

    UniValue chalObj(UniValue::VOBJ);
    chalObj.pushKV("total",   (int)challenges.size());
    chalObj.pushKV("open",    openChallenges);
    chalObj.pushKV("slashed", slashedChallenges);

    UniValue payObj(UniValue::VOBJ);
    payObj.pushKV("total_cs", ValueFromAmount(totalPayments));

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("requests",   reqObj);
    ret.pushKV("responses",  respObj);
    ret.pushKV("stakes",     stakeObj);
    ret.pushKV("challenges", chalObj);
    ret.pushKV("payments",   payObj);
    return ret;
}

// ── registermodelopoi (F15-A) ────────────────────────────────────────────────

UniValue registermodelopoi(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "registermodelopoi manifest_json \"proposer_address\"\n"
            "\nPropose a new Model Manifest (dense, MoE or hybrid) for OPoI mining.\n"
            "\nThe proposer must be an ACTIVE OPoI staker. The model enters a voting\n"
            "window (nOPoIModelVoteWindowBlocks) during which stakers cast votemodelopoi.\n"
            "\nArguments:\n"
            "1. manifest_json  (object, required)\n"
            "   {\n"
            "     \"model_id\": \"MIXTRAL_8X22B\",       (string, required)\n"
            "     \"arch_type\": \"MOE\",                (string, required) DENSE|MOE|HYBRID\n"
            "     \"total_params\": 141000000000,      (numeric, required)\n"
            "     \"active_params_per_token\": 39000000000, (numeric, required)\n"
            "     \"num_layers\": 56,                   (numeric, required)\n"
            "     \"num_dense_shards\": 4,              (numeric, optional, default 1 — F15-B pipeline split)\n"
            "     \"num_experts\": 8,                   (numeric, optional, default 0 — DENSE)\n"
            "     \"top_k_experts\": 2,                 (numeric, optional, default 0 — DENSE)\n"
            "     \"backbone_pom_root\": \"<hex64>\",     (string, required)\n"
            "     \"expert_pom_roots\": [\"<hex64>\",...], (array, required if MOE/HYBRID)\n"
            "     \"min_reward_per_token\": 0.001       (numeric, optional, default 0)\n"
            "     \"total_size_bytes\": 3300000000     (numeric, optional, default 0 — F9-G/F15-M:\n"
            "                       total on-disk size of the model's weights; only input to the\n"
            "                       titan MoE-offload single-node routing preference, see F15-M)\n"
            "   }\n"
            "2. proposer_address  (string, required) Must be an ACTIVE OPoI staker\n"
            "\nResult:\n"
            "{ txid, model_id, vote_window_end_height }\n"
            "\nExamples:\n"
            + HelpExampleCli("registermodelopoi", "'{\"model_id\":\"GEMMA_5_4B\",\"arch_type\":\"DENSE\",...}' \"t1Proposer...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    UniValue manifest = params[0].get_obj();
    std::string proposerAddr = params[1].get_str();
    if (proposerAddr.empty()) throw std::runtime_error("proposer_address must not be empty");

    if (!g_opoiCache.IsActiveStaker(proposerAddr))
        throw JSONRPCError(RPC_INVALID_PARAMETER, proposerAddr + " is not an active OPoI staker");

    std::string modelId = find_value(manifest, "model_id").get_str();
    if (modelId.empty()) throw std::runtime_error("model_id must not be empty");
    {
        ModelManifest existing;
        if (g_opoiCache.GetModelManifest(modelId, existing))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "model " + modelId + " is already registered");
    }

    uint8_t archType = ArchTypeFromString(find_value(manifest, "arch_type").get_str());

    uint64_t totalParams = (uint64_t)find_value(manifest, "total_params").get_int64();
    uint64_t activeParamsPerToken = (uint64_t)find_value(manifest, "active_params_per_token").get_int64();
    uint32_t numLayers = (uint32_t)find_value(manifest, "num_layers").get_int64();

    UniValue uvNumDenseShards = find_value(manifest, "num_dense_shards");
    uint32_t numDenseShards = uvNumDenseShards.isNull() ? 1 : (uint32_t)uvNumDenseShards.get_int64();

    UniValue uvNumExperts  = find_value(manifest, "num_experts");
    UniValue uvTopK        = find_value(manifest, "top_k_experts");
    uint32_t numExperts = uvNumExperts.isNull() ? 0 : (uint32_t)uvNumExperts.get_int64();
    uint32_t topKExperts = uvTopK.isNull() ? 0 : (uint32_t)uvTopK.get_int64();

    uint256 backboneRoot;
    backboneRoot.SetHex(find_value(manifest, "backbone_pom_root").get_str());
    if (backboneRoot.IsNull())
        throw std::runtime_error("backbone_pom_root must be a valid 64-char hex hash");

    std::vector<uint256> expertRoots;
    UniValue uvExpertRoots = find_value(manifest, "expert_pom_roots");
    if (uvExpertRoots.isArray()) {
        for (unsigned int i = 0; i < uvExpertRoots.size(); i++) {
            uint256 root; root.SetHex(uvExpertRoots[i].get_str());
            expertRoots.push_back(root);
        }
    }

    if (archType == OPOI_ARCH_DENSE) {
        if (numExperts != 0 || topKExperts != 0 || !expertRoots.empty())
            throw std::runtime_error("DENSE model must not declare experts");
    } else {
        if (numExperts == 0 || topKExperts == 0 || topKExperts > numExperts)
            throw std::runtime_error("MOE/HYBRID model needs num_experts >= top_k_experts > 0");
        if (expertRoots.size() != numExperts)
            throw std::runtime_error(strprintf(
                "expert_pom_roots must have exactly num_experts (%u) entries, got %d",
                numExperts, (int)expertRoots.size()));
    }

    if (numLayers == 0)
        throw std::runtime_error("num_layers must be > 0");
    if (numDenseShards == 0 || numDenseShards > numLayers)
        throw std::runtime_error(strprintf(
            "num_dense_shards must be between 1 and num_layers (%u), got %u", numLayers, numDenseShards));

    UniValue uvMinReward = find_value(manifest, "min_reward_per_token");
    CAmount minRewardPerToken = uvMinReward.isNull() ? 0 : AmountFromValue(uvMinReward);

    UniValue uvTotalSizeBytes = find_value(manifest, "total_size_bytes");
    uint64_t totalSizeBytes = uvTotalSizeBytes.isNull() ? 0 : (uint64_t)uvTotalSizeBytes.get_int64();

    CMutableTransaction mutTx;
    mutTx.nVersion                       = OPOI_TX_VERSION;
    mutTx.nType                          = OPOI_MODEL_REGISTER_TX_TYPE;
    mutTx.opoiModelId                    = modelId;
    mutTx.opoiRequester                  = proposerAddr;
    mutTx.opoiModelArchType              = archType;
    mutTx.opoiModelTotalParams           = totalParams;
    mutTx.opoiModelActiveParamsPerToken  = activeParamsPerToken;
    mutTx.opoiModelNumLayers             = numLayers;
    mutTx.opoiModelNumDenseShards        = numDenseShards;
    mutTx.opoiModelNumExperts            = numExperts;
    mutTx.opoiModelTopKExperts           = topKExperts;
    mutTx.opoiPomRoot                    = backboneRoot;
    mutTx.opoiModelExpertPomRoots        = expertRoots;
    mutTx.opoiModelMinRewardPerToken     = minRewardPerToken;
    mutTx.opoiModelTotalSizeBytes        = totalSizeBytes;
    mutTx.opoiSigTime                    = (uint32_t)GetTime();

    std::string sigMsg = modelId + proposerAddr + strprintf("%d", (int)archType) + backboneRoot.GetHex();
    std::string errMsg;
    if (!SignWithAddress(proposerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for registermodelopoi");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",     tx.GetHash().GetHex());
    ret.pushKV("model_id", modelId);
    ret.pushKV("vote_window_blocks", (int)Params().GetConsensus().nOPoIModelVoteWindowBlocks);
    return ret;
}

// ── votemodelopoi (F15-A2) ───────────────────────────────────────────────────

UniValue votemodelopoi(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "votemodelopoi \"model_id\" \"voter_address\" approve\n"
            "\nCast a stake-weighted vote on a proposed Model Manifest.\n"
            "\nWeight = voter's ACTIVE OPoI stake amount at the time of voting.\n"
            "Re-voting overwrites the voter's previous vote.\n"
            "\nArguments:\n"
            "1. model_id       (string, required)\n"
            "2. voter_address  (string, required) Must be an ACTIVE OPoI staker\n"
            "3. approve        (boolean, required) true = yes, false = no\n"
            "\nResult:\n"
            "{ txid, model_id, voter_address, approve, weight }\n"
            "\nExamples:\n"
            + HelpExampleCli("votemodelopoi", "\"MIXTRAL_8X22B\" \"t1Voter...\" true")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string modelId    = params[0].get_str();
    std::string voterAddr  = params[1].get_str();
    bool approve           = params[2].get_bool();

    ModelManifest m;
    if (!g_opoiCache.GetModelManifest(modelId, m))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown model_id: " + modelId);
    if (!m.IsVoting())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "voting window for " + modelId + " is closed");
    if (!g_opoiCache.IsActiveStaker(voterAddr))
        throw JSONRPCError(RPC_INVALID_PARAMETER, voterAddr + " is not an active OPoI staker");

    CMutableTransaction mutTx;
    mutTx.nVersion             = OPOI_TX_VERSION;
    mutTx.nType                = OPOI_MODEL_VOTE_TX_TYPE;
    mutTx.opoiModelId          = modelId;
    mutTx.opoiRequester        = voterAddr;
    mutTx.opoiModelVoteApprove = approve ? 1 : 0;
    mutTx.opoiSigTime          = (uint32_t)GetTime();

    std::string sigMsg = modelId + voterAddr + strprintf("%d", (int)mutTx.opoiModelVoteApprove);
    std::string errMsg;
    if (!SignWithAddress(voterAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for votemodelopoi");
#endif

    OPoIStake voterStake;
    g_opoiCache.GetStake(voterAddr, voterStake);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",          tx.GetHash().GetHex());
    ret.pushKV("model_id",      modelId);
    ret.pushKV("voter_address", voterAddr);
    ret.pushKV("approve",       approve);
    ret.pushKV("weight",        ValueFromAmount(voterStake.amount));
    return ret;
}

// ── getmodelmanifest / listmodelmanifests (F15-A) ────────────────────────────

UniValue getmodelmanifest(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getmodelmanifest \"model_id\"\n"
            "\nGet a Model Manifest and its current vote tally.\n"
            "\nArguments:\n"
            "1. model_id  (string, required)\n"
            "\nExamples:\n"
            + HelpExampleCli("getmodelmanifest", "\"MIXTRAL_8X22B\"")
        );

    ModelManifest m;
    if (!g_opoiCache.GetModelManifest(params[0].get_str(), m))
        throw std::runtime_error("Model manifest not found for: " + params[0].get_str());
    return ModelManifestToUniValue(m);
}

UniValue listmodelmanifests(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "listmodelmanifests ( \"status\" )\n"
            "\nList Model Manifests.\n"
            "\nArguments:\n"
            "1. status  (string, optional) VOTING | APPROVED | ACTIVE | REJECTED\n"
            "\nExamples:\n"
            + HelpExampleCli("listmodelmanifests", "")
            + HelpExampleCli("listmodelmanifests", "\"ACTIVE\"")
        );

    int8_t statusFilter = -1;
    if (params.size() == 1) {
        std::string s = params[0].get_str();
        if      (s == "VOTING")   statusFilter = OPOI_MODEL_STATUS_VOTING;
        else if (s == "APPROVED") statusFilter = OPOI_MODEL_STATUS_APPROVED;
        else if (s == "ACTIVE")   statusFilter = OPOI_MODEL_STATUS_ACTIVE;
        else if (s == "REJECTED") statusFilter = OPOI_MODEL_STATUS_REJECTED;
        else throw std::runtime_error("Invalid status. Use VOTING, APPROVED, ACTIVE or REJECTED.");
    }

    UniValue arr(UniValue::VARR);
    for (const auto& m : g_opoiCache.ListModelManifests(statusFilter))
        arr.push_back(ModelManifestToUniValue(m));
    return arr;
}

// ── getmodelgraph (F15-B) ────────────────────────────────────────────────────

UniValue getmodelgraph(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getmodelgraph \"model_id\"\n"
            "\nReturn the Model Execution Graph (MEG) for a registered model: the\n"
            "ordered list of DenseShards (pipeline stages) and, for MoE/HYBRID models,\n"
            "the ExpertShards. Fully deterministic from the manifest — any node computes\n"
            "the identical graph, which is why only shardTopologyHash (a commitment to\n"
            "this graph) needs to live on-chain.\n"
            "\nArguments:\n"
            "1. model_id  (string, required)\n"
            "\nExamples:\n"
            + HelpExampleCli("getmodelgraph", "\"MIXTRAL_8X22B\"")
        );

    ModelManifest m;
    if (!g_opoiCache.GetModelManifest(params[0].get_str(), m))
        throw std::runtime_error("Model manifest not found for: " + params[0].get_str());

    // F9-G/F15-M: titan single-node routing preference — same check used by
    // every consensus call site (opoi.cpp), so this RPC's view of the MEG
    // always matches what actually gets validated/paid.
    bool collapseTitan = ShouldCollapseToTitanSingleNode(m, Params().GetConsensus());

    UniValue shards(UniValue::VARR);
    for (const auto& d : BuildModelExecutionGraph(m, collapseTitan)) {
        UniValue s(UniValue::VOBJ);
        s.pushKV("shard_index", (int)d.shardIndex);
        s.pushKV("shard_type",  d.shardType == OPOI_SHARD_DENSE ? "DENSE" : "EXPERT");
        if (d.shardType == OPOI_SHARD_DENSE) {
            s.pushKV("layer_start", (int)d.layerStart);
            s.pushKV("layer_end",   (int)d.layerEnd);
        } else {
            s.pushKV("expert_id", (int)d.expertId);
        }
        shards.push_back(s);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("model_id",           m.modelId);
    ret.pushKV("shard_topology_hash",m.shardTopologyHash.GetHex());
    ret.pushKV("titan_single_node",  collapseTitan); // F9-G/F15-M
    ret.pushKV("shards",             shards);
    return ret;
}

// ── claimcoordinator / listcoordinatorclaims (F15-C) ─────────────────────────
// NOTE: this only implements coordinator SELECTION (VRF self-claim, verifiable
// by any node). The relay/consensus duties of the role (distributing shard
// activations, publishing SHARD_COMMIT/REVEAL, misconduct proofs) depend on the
// shard execution protocol (F15-D/F15-H), which does not exist yet.

UniValue claimcoordinator(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "claimcoordinator \"request_id\" \"miner_address\"\n"
            "\nSelf-claim eligibility to coordinate a request's shard pipeline via VRF.\n"
            "\nThe miner must be an ACTIVE OPoI staker. Eligibility is probabilistic\n"
            "(governed by nOPoICoordinatorThreshold) — multiple miners may be eligible\n"
            "for the same request by design (redundancy).\n"
            "\nArguments:\n"
            "1. request_id     (string, required)\n"
            "2. miner_address  (string, required) Must be an ACTIVE OPoI staker\n"
            "\nResult:\n"
            "{ txid, request_id, miner_address }\n"
            "\nExamples:\n"
            + HelpExampleCli("claimcoordinator", "\"uuid\" \"t1Miner...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId = params[0].get_str();
    std::string minerAddr = params[1].get_str();
    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");

    OPoIRequest req;
    if (!g_opoiCache.GetRequest(requestId, req))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown request_id: " + requestId);

    OPoIStake stake;
    if (!g_opoiCache.GetStake(minerAddr, stake) || !stake.IsActive())
        throw JSONRPCError(RPC_INVALID_PARAMETER, minerAddr + " is not an active OPoI staker");
    if (stake.minerPubKey.size() != 33)
        throw std::runtime_error(minerAddr + " has no recorded pubkey (re-stake required after this upgrade)");

    CKey minerKey;
#ifdef ENABLE_WALLET
    CKeyID keyId = stake.minerPubKey.GetID();
    if (!pwalletMain || !pwalletMain->GetKey(keyId, minerKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for " + minerAddr + " not in wallet");
#endif

    // Bug fix (2026-07-02): seed anchored to the request's confirmation block,
    // not the moving chain tip — see submitopoiresponse for full explanation.
    CBlockIndex* pSeedBlock = chainActive[req.blockHeight];
    if (!pSeedBlock) throw std::runtime_error("cannot locate the request's confirmation block to derive VRF seed");
    unsigned char seed[32];
    {
        uint256 seedBlockHash = pSeedBlock->GetBlockHash();
        CSHA256 hasher;
        hasher.Write(seedBlockHash.begin(), 32);
        hasher.Write((const unsigned char*)requestId.data(), requestId.size());
        const std::string coordSuffix = "COORD";
        hasher.Write((const unsigned char*)coordSuffix.data(), coordSuffix.size());
        hasher.Finalize(seed);
    }
    std::vector<unsigned char> vrfProof;
    unsigned char pubKeyBytes[33];
    memcpy(pubKeyBytes, stake.minerPubKey.begin(), 33);
    if (!OPoIVRFProve(minerKey.begin(), pubKeyBytes, seed, 32, vrfProof))
        throw std::runtime_error("VRF proof generation failed — this miner is likely not eligible "
                                  "for this request (try a different request or wait for the next block)");

    CMutableTransaction mutTx;
    mutTx.nVersion         = OPOI_TX_VERSION;
    mutTx.nType            = OPOI_COORDINATOR_CLAIM_TX_TYPE;
    mutTx.opoiRequestId    = requestId;
    mutTx.opoiMinerAddress = minerAddr;
    mutTx.opoiVrfProof     = vrfProof;
    mutTx.opoiSigTime      = (uint32_t)GetTime();

    std::string sigMsg = std::string("COORD") + requestId + minerAddr;
    std::string errMsg;
    if (!SignWithAddress(minerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for claimcoordinator");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",          tx.GetHash().GetHex());
    ret.pushKV("request_id",    requestId);
    ret.pushKV("miner_address", minerAddr);
    return ret;
}

UniValue listcoordinatorclaims(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "listcoordinatorclaims \"request_id\"\n"
            "\nList miners who have self-claimed (and been verified) as eligible\n"
            "shard coordinators for a request.\n"
            "\nArguments:\n"
            "1. request_id  (string, required)\n"
            "\nExamples:\n"
            + HelpExampleCli("listcoordinatorclaims", "\"uuid\"")
        );

    UniValue arr(UniValue::VARR);
    for (const auto& c : g_opoiCache.ListCoordinatorClaims(params[0].get_str())) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("request_id",    c.requestId);
        obj.pushKV("miner_address", c.minerAddress);
        obj.pushKV("block_height",  (int)c.blockHeight);
        obj.pushKV("tx_hash",       c.txHash.GetHex());
        arr.push_back(obj);
    }
    return arr;
}

// ── submitshardresult / getshardresult (F15-D) ───────────────────────────────
// NOTE: this only covers the on-chain bookkeeping of a shard's boundary output
// (VRF-gated submission + majority consensus). It does NOT run real model
// inference — boundary_output_hash is whatever the caller supplies, exactly
// like opoiCommitment elsewhere in OPoI (see F8-A note: an economic placeholder
// until ZKML/TEE can prove the underlying computation actually happened).

UniValue submitshardresult(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 6)
        throw std::runtime_error(
            "submitshardresult \"request_id\" shard_index \"miner_address\" \"boundary_output_hash_hex\""
            " ( \"router_logits_hash_hex\" token_count )\n"
            "\nSelf-claim eligibility (via VRF) and publish this miner's output hash\n"
            "for one shard of a request's Model Execution Graph (see getmodelgraph).\n"
            "\nArguments:\n"
            "1. request_id               (string, required)\n"
            "2. shard_index              (numeric, required) Index into the MEG (getmodelgraph)\n"
            "3. miner_address            (string, required) Must be an ACTIVE OPoI staker\n"
            "4. boundary_output_hash_hex (string, required) Hash of this shard's output activations\n"
            "5. router_logits_hash_hex   (string, optional) Only for MoE router boundaries\n"
            "6. token_count              (numeric, optional, default 0) F16: tokens generated by\n"
            "                            this shard's compute — drives the per-token fee component\n"
            "                            of shard payments (request.feePerToken). Self-declared, like\n"
            "                            RESPONSE's token count; only miners who agree on BOTH the\n"
            "                            output hash and this count are counted toward the shard's\n"
            "                            resolved majority (see ComputeShardMajority).\n"
            "\nResult:\n"
            "{ txid, request_id, shard_index, miner_address }\n"
            "\nExamples:\n"
            + HelpExampleCli("submitshardresult", "\"uuid\" 0 \"t1Miner...\" \"abc123...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId  = params[0].get_str();
    uint32_t    shardIndex = (uint32_t)params[1].get_int64();
    std::string minerAddr  = params[2].get_str();
    std::string outputHex  = params[3].get_str();
    std::string routerHex  = (params.size() > 4) ? params[4].get_str() : "";
    uint32_t    tokenCount = (params.size() > 5) ? (uint32_t)params[5].get_int64() : 0;

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");

    uint256 boundaryOutputHash;
    boundaryOutputHash.SetHex(outputHex);
    if (boundaryOutputHash.IsNull())
        throw std::runtime_error("boundary_output_hash_hex is invalid or all-zero");
    uint256 routerLogitsHash;
    if (!routerHex.empty()) routerLogitsHash.SetHex(routerHex);

    OPoIRequest req;
    if (!g_opoiCache.GetRequest(requestId, req))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown request_id: " + requestId);

    OPoIStake stake;
    if (!g_opoiCache.GetStake(minerAddr, stake) || !stake.IsActive())
        throw JSONRPCError(RPC_INVALID_PARAMETER, minerAddr + " is not an active OPoI staker");
    if (stake.minerPubKey.size() != 33)
        throw std::runtime_error(minerAddr + " has no recorded pubkey (re-stake required after this upgrade)");

    CKey minerKey;
#ifdef ENABLE_WALLET
    CKeyID keyId = stake.minerPubKey.GetID();
    if (!pwalletMain || !pwalletMain->GetKey(keyId, minerKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for " + minerAddr + " not in wallet");
#endif

    // Bug fix (2026-07-02): seed anchored to the request's confirmation block,
    // not the moving chain tip — see submitopoiresponse for full explanation.
    CBlockIndex* pSeedBlock = chainActive[req.blockHeight];
    if (!pSeedBlock) throw std::runtime_error("cannot locate the request's confirmation block to derive VRF seed");
    unsigned char seed[32];
    {
        uint256 seedBlockHash = pSeedBlock->GetBlockHash();
        CSHA256 hasher;
        hasher.Write(seedBlockHash.begin(), 32);
        hasher.Write((const unsigned char*)requestId.data(), requestId.size());
        std::string suffix = "SHARD" + strprintf("%u", shardIndex);
        hasher.Write((const unsigned char*)suffix.data(), suffix.size());
        hasher.Finalize(seed);
    }
    std::vector<unsigned char> vrfProof;
    unsigned char pubKeyBytes[33];
    memcpy(pubKeyBytes, stake.minerPubKey.begin(), 33);
    if (!OPoIVRFProve(minerKey.begin(), pubKeyBytes, seed, 32, vrfProof))
        throw std::runtime_error("VRF proof generation failed — this miner is likely not eligible "
                                  "for this shard (try a different shard or wait for the next block)");

    CMutableTransaction mutTx;
    mutTx.nVersion         = OPOI_TX_VERSION;
    mutTx.nType            = OPOI_SHARD_RESULT_TX_TYPE;
    mutTx.opoiRequestId    = requestId;
    mutTx.opoiShardIndex   = shardIndex;
    mutTx.opoiMinerAddress = minerAddr;
    mutTx.opoiResponseHash = boundaryOutputHash;
    mutTx.opoiCommitment   = routerLogitsHash;
    mutTx.opoiTokenCount   = tokenCount;
    mutTx.opoiVrfProof     = vrfProof;
    mutTx.opoiSigTime      = (uint32_t)GetTime();

    std::string sigMsg = std::string("SHARD") + requestId + strprintf("%u", shardIndex)
                        + minerAddr + boundaryOutputHash.GetHex() + routerLogitsHash.GetHex()
                        + strprintf("%u", tokenCount);
    std::string errMsg;
    if (!SignWithAddress(minerAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for submitshardresult");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",          tx.GetHash().GetHex());
    ret.pushKV("request_id",    requestId);
    ret.pushKV("shard_index",   (int)shardIndex);
    ret.pushKV("miner_address", minerAddr);
    return ret;
}

UniValue getshardresult(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "getshardresult \"request_id\" shard_index\n"
            "\nList all submissions for a shard and the resolved majority.\n"
            "\nNormally waits for nOPoIShardMinSubmissions (R) independent submissions.\n"
            "F15-F: if fewer than R miners could EVER submit for this shard (e.g. an\n"
            "expert hosted by only 1-2 active stakers), the effective threshold is\n"
            "lowered to however many are actually available, and reduced_redundancy\n"
            "is set — the request isn't stuck waiting for miners that don't exist.\n"
            "\nArguments:\n"
            "1. request_id   (string, required)\n"
            "2. shard_index  (numeric, required)\n"
            "\nExamples:\n"
            + HelpExampleCli("getshardresult", "\"uuid\" 0")
        );

    std::string requestId  = params[0].get_str();
    uint32_t    shardIndex = (uint32_t)params[1].get_int64();

    UniValue subs(UniValue::VARR);
    for (const auto& s : g_opoiCache.ListShardResults(requestId, shardIndex)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("miner_address",         s.minerAddress);
        obj.pushKV("boundary_output_hash",  s.boundaryOutputHash.GetHex());
        obj.pushKV("router_logits_hash",    s.routerLogitsHash.GetHex());
        obj.pushKV("token_count",           (int)s.tokenCount);
        obj.pushKV("block_height",          (int)s.blockHeight);
        obj.pushKV("tx_hash",               s.txHash.GetHex());
        subs.push_back(obj);
    }

    int configuredMin = Params().GetConsensus().nOPoIShardMinSubmissions;
    int effectiveMin  = configuredMin;
    bool reducedRedundancy = false;

    // F15-F: figure out how many miners could ever possibly submit for this
    // shard (shared with F16 payment logic via GetEffectiveShardMinSubmissions,
    // so "resolved" always means the same thing whether queried or paid).
    OPoIRequest req;
    if (g_opoiCache.GetRequest(requestId, req)) {
        effectiveMin = GetEffectiveShardMinSubmissions(req, shardIndex, Params().GetConsensus());
        reducedRedundancy = effectiveMin < configuredMin;
    }

    uint256 majorityHash;
    uint32_t majorityTokenCount = 0;
    std::vector<std::string> agreeing, divergent;
    bool resolved = g_opoiCache.GetShardMajority(requestId, shardIndex, effectiveMin, majorityHash,
                                                  majorityTokenCount, agreeing, divergent);

    UniValue divergentArr(UniValue::VARR);
    for (const auto& addr : divergent) divergentArr.push_back(addr);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("request_id",         requestId);
    ret.pushKV("shard_index",        (int)shardIndex);
    ret.pushKV("submissions",        subs);
    ret.pushKV("resolved",           resolved);
    ret.pushKV("majority_hash",      resolved ? majorityHash.GetHex() : "");
    // F16: token count agreed on by the resolved majority (0 if unresolved or
    // no submitter reported one) — drives the per-token fee, see submitshardresult.
    ret.pushKV("majority_token_count", resolved ? (int)majorityTokenCount : 0);
    ret.pushKV("divergent",          divergentArr);
    ret.pushKV("reduced_redundancy", reducedRedundancy);
    ret.pushKV("effective_min_submissions", effectiveMin);
    return ret;
}

// ── submitauditorverification (F14-C) ──────────────────────────────────────────

UniValue submitauditorverification(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
        throw std::runtime_error(
            "submitauditorverification \"auditor_address\" \"request_id\" \"result\""
            " \"collateral_txid\" collateral_vout\n"
            "\nSubmit an Auditor's verdict on a VERIFIABLE request's RESPONSE (F14-B),\n"
            "checked against the REQUEST's test suite. Permissionless — any address\n"
            "that locks the required collateral may audit, no OPoI stake required.\n"
            "\nSandbox execution (F14-E) is not yet implemented — the caller decides\n"
            "PASS/FAIL/TIMEOUT themselves for now.\n"
            "\nOnce nOPoIMinAuditors verdicts are in for a request, the majority result\n"
            "is resolved (ProcessAuditorVerifications): Auditors matching the majority\n"
            "get their collateral unlocked, the minority stay locked forever (slashed).\n"
            "The underlying RESPONSE is only paid if the majority is PASS.\n"
            "\nArguments:\n"
            "1. auditor_address  (string, required) Address casting this verdict\n"
            "2. request_id       (string, required) The VERIFIABLE request being audited\n"
            "3. result           (string, required) PASS, FAIL, or TIMEOUT\n"
            "4. collateral_txid  (string, required) TXID of the Auditor's collateral UTXO\n"
            "5. collateral_vout  (numeric, required) Output index of the collateral UTXO\n"
            "\nResult:\n"
            "{ txid, request_id, auditor_address, result }\n"
            "\nExamples:\n"
            + HelpExampleCli("submitauditorverification", "\"t1Auditor...\" \"uuid\" \"PASS\" \"abc123...\" 0")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string auditorAddr = params[0].get_str();
    std::string requestId   = params[1].get_str();
    std::string resultStr   = params[2].get_str();
    uint256     colTxid;
    colTxid.SetHex(params[3].get_str());
    uint32_t    colVout     = (uint32_t)params[4].get_int();

    if (auditorAddr.empty()) throw std::runtime_error("auditor_address must not be empty");
    if (requestId.empty())   throw std::runtime_error("request_id must not be empty");
    if (colTxid.IsNull())    throw std::runtime_error("collateral_txid is invalid");

    uint8_t result;
    if (resultStr == "PASS") result = AUDITOR_VERIFY_PASS;
    else if (resultStr == "FAIL") result = AUDITOR_VERIFY_FAIL;
    else if (resultStr == "TIMEOUT") result = AUDITOR_VERIFY_TIMEOUT;
    else throw std::runtime_error("result must be PASS, FAIL, or TIMEOUT");

    OPoIRequest req;
    if (!g_opoiCache.GetRequest(requestId, req))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown request_id: " + requestId);
    if (!req.IsVerifiable())
        throw JSONRPCError(RPC_INVALID_PARAMETER, requestId + " is not a VERIFIABLE task — nothing for an Auditor to check");

    // Look up the UTXO to get its value (same pattern as stakeopoi).
    COutPoint colOut(colTxid, colVout);
    CCoins coins;
    CAmount collateralAmount = 0;
    {
        LOCK(cs_main);
        CCoinsViewCache view(pcoinsTip);
        if (!view.GetCoins(colTxid, coins) || colVout >= coins.vout.size() || coins.vout[colVout].IsNull())
            throw std::runtime_error("collateral UTXO not found in the UTXO set");
        collateralAmount = coins.vout[colVout].nValue;
    }
    CAmount minCollateral = Params().GetConsensus().nOPoIAuditorMinCollateral;
    if (collateralAmount < minCollateral)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Collateral value %.4f CS is below minimum %.4f CS",
                      (double)collateralAmount / COIN, (double)minCollateral / COIN));

    CMutableTransaction mutTx;
    mutTx.nVersion              = OPOI_TX_VERSION;
    mutTx.nType                 = OPOI_AUDITOR_VERIFY_TX_TYPE;
    mutTx.opoiRequestId          = requestId;
    mutTx.opoiAuditorAddress     = auditorAddr;
    mutTx.opoiAuditorVerifyResult= result;
    mutTx.opoiAuditorCollateralIn= colOut;
    mutTx.opoiSigTime            = (uint32_t)GetTime();

    std::string sigMsg = auditorAddr + requestId + colTxid.GetHex() + strprintf("%u", colVout);
    std::string errMsg;
    if (!SignWithAddress(auditorAddr, sigMsg, mutTx.opoiSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for submitauditorverification");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid",             tx.GetHash().GetHex());
    ret.pushKV("request_id",       requestId);
    ret.pushKV("auditor_address",  auditorAddr);
    ret.pushKV("result",           resultStr);
    return ret;
}

UniValue getauditorverifications(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getauditorverifications \"request_id\"\n"
            "\nList all Auditor verdicts for a request and the resolved majority.\n"
            "\nArguments:\n"
            "1. request_id  (string, required)\n"
            "\nExamples:\n"
            + HelpExampleCli("getauditorverifications", "\"uuid\"")
        );

    std::string requestId = params[0].get_str();
    int minAuditors = Params().GetConsensus().nOPoIMinAuditors;

    UniValue verifs(UniValue::VARR);
    for (const auto& fv : g_opoiCache.GetAuditorVerifications(requestId)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("auditor_address", fv.auditorAddress);
        std::string resultStr = fv.result == AUDITOR_VERIFY_PASS ? "PASS"
                               : fv.result == AUDITOR_VERIFY_FAIL ? "FAIL" : "TIMEOUT";
        obj.pushKV("result",          resultStr);
        obj.pushKV("block_height",    (int)fv.blockHeight);
        obj.pushKV("tx_hash",         fv.txHash.GetHex());
        std::string statusStr = fv.status == OPOI_AUDITOR_STATUS_PENDING  ? "PENDING"
                               : fv.status == OPOI_AUDITOR_STATUS_COMPLETE ? "COMPLETE" : "SLASHED";
        obj.pushKV("status",          statusStr);
        verifs.push_back(obj);
    }

    int majority = g_opoiCache.GetAuditorMajorityResult(requestId, minAuditors);
    std::string majorityStr = majority < 0 ? ""
                            : majority == AUDITOR_VERIFY_PASS ? "PASS"
                            : majority == AUDITOR_VERIFY_FAIL ? "FAIL" : "TIMEOUT";

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("request_id",     requestId);
    ret.pushKV("verifications",  verifs);
    ret.pushKV("resolved",       majority >= 0);
    ret.pushKV("majority_result",majorityStr);
    ret.pushKV("min_auditors",   minAuditors);
    return ret;
}

// ── OPoI relay (2026-07-05): P2P delivery for NAT'd/CGNAT'd miners ────────────
// See PendingDelivery/COPoIDataMsg doc comments in opoi.h for the full design.

static bool ParseOPoIDeliveryKind(const std::string& s, uint8_t& out)
{
    if (s.empty() || s == "PROMPT")       { out = OPOI_DELIVERY_PROMPT;              return true; }
    if (s == "SHARD_ASSIGN")              { out = OPOI_DELIVERY_SHARD_ASSIGN;        return true; }
    if (s == "SHARD_RESULT")              { out = OPOI_DELIVERY_SHARD_RESULT;        return true; }
    if (s == "MODEL_CHUNK_REQUEST")       { out = OPOI_DELIVERY_MODEL_CHUNK_REQUEST; return true; }
    if (s == "MODEL_CHUNK")               { out = OPOI_DELIVERY_MODEL_CHUNK;         return true; }
    return false;
}

UniValue submitopoipendingdelivery(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw std::runtime_error(
            "submitopoipendingdelivery \"request_id\" \"dest_stake_address\" \"payload_hex\""
            " ( \"kind\" \"sender_address\" )\n"
            "\nOPoI relay: deliver off-chain data to a miner with no reachable HTTP\n"
            "endpoint, via P2P flood-relay instead of POSTing directly to the miner's\n"
            "declared endpoint. Floods to every connected peer; the destination miner's\n"
            "own node ends up with a copy regardless of which node originated it (no\n"
            "addressed routing needed) and polls it via getopoipendingdeliveries on ITS\n"
            "OWN node.\n"
            "\nFor kind=PROMPT (default), signs as the REQUEST's own requester — see\n"
            "/api/opoi/prompt for the direct-HTTP equivalent. For kind=SHARD_ASSIGN (a\n"
            "coordinator relaying a shard assignment — F15-H) or kind=SHARD_RESULT (the\n"
            "assigned miner's reply carrying the computed tensor back), sender_address is\n"
            "required and must be this node's own address: a coordinator (must have an\n"
            "accepted claim for this request) or an ACTIVE staker, respectively — there\n"
            "is no single address derivable from request_id alone for these two kinds,\n"
            "since a request can have several accepted coordinators (VRF redundancy) and\n"
            "any ACTIVE staker could be the assigned miner.\n"
            "\nkind=MODEL_CHUNK_REQUEST/MODEL_CHUNK (model distribution fast-follow) work\n"
            "the same way: sender_address required, must be an ACTIVE staker. A GGUF/\n"
            "tokenizer is split client-side into many <=64KB chunks (cs-miner's\n"
            "model_fetch.rs), so a full transfer is one REQUEST plus many CHUNK calls.\n"
            "\nArguments:\n"
            "1. request_id          (string, required) UUID of the inference request\n"
            "2. dest_stake_address  (string, required) Recipient's stake/mining address\n"
            "3. payload_hex         (string, required) Raw payload as hex — max 64KB encoded\n"
            "4. kind                (string, optional) PROMPT (default) | SHARD_ASSIGN | SHARD_RESULT\n"
            "                       | MODEL_CHUNK_REQUEST | MODEL_CHUNK\n"
            "5. sender_address      (string, optional) Required for anything but PROMPT;\n"
            "                       this node's wallet must hold its key\n"
            "\nResult:\n"
            "{ delivered: true }\n"
            "\nExamples:\n"
            + HelpExampleCli("submitopoipendingdelivery", "\"uuid\" \"tmMinerAddr...\" \"68656c6c6f\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId  = params[0].get_str();
    std::string destAddr   = params[1].get_str();
    std::string payloadHex = params[2].get_str();
    std::string kindStr    = (params.size() > 3) ? params[3].get_str() : "";
    std::string senderAddr = (params.size() > 4) ? params[4].get_str() : "";

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (destAddr.empty())  throw std::runtime_error("dest_stake_address must not be empty");
    if (payloadHex.size() > OPOI_DELIVERY_MAX_PAYLOAD_HEX)
        throw std::runtime_error("payload_hex exceeds max size");

    uint8_t kind;
    if (!ParseOPoIDeliveryKind(kindStr, kind))
        throw std::runtime_error("kind must be PROMPT, SHARD_ASSIGN, or SHARD_RESULT");
    if (kind != OPOI_DELIVERY_PROMPT && senderAddr.empty())
        throw std::runtime_error("sender_address is required for SHARD_ASSIGN/SHARD_RESULT");

    OPoIRequest req;
    if (!g_opoiCache.GetRequest(requestId, req))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown request_id: " + requestId);
    if (!req.IsPending())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "request " + requestId + " is no longer PENDING");

    std::string signerAddr = (kind == OPOI_DELIVERY_PROMPT) ? req.requester : senderAddr;

    COPoIDataMsg msg;
    msg.destStakeAddress = destAddr;
    msg.requestId        = requestId;
    msg.kind             = kind;
    msg.senderAddress    = senderAddr;
    msg.payloadHex       = payloadHex;
    msg.sigTime          = (uint32_t)GetTime();

    std::string sigMsg = std::string("OPOIDATA") + requestId + destAddr
                        + strprintf("%u", (unsigned)msg.kind) + senderAddr + payloadHex;
    std::string errMsg;
    if (!SignWithAddress(signerAddr, sigMsg, msg.sig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign: " + errMsg);

    std::string reason;
    if (!ProcessOPoIDataMessage(msg, reason))
        throw JSONRPCError(RPC_MISC_ERROR, "rejected: " + reason);

    // Flood to every currently-connected peer — same code shape as the P2P
    // receive handler in main.cpp's ProcessMessage "opoidata" branch.
    uint256 msgHash = msg.GetHash();
    g_opoiCache.MarkOPoIDataHashKnown(msgHash);
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes) {
            if (pnode->setKnown.insert(msgHash).second)
                pnode->PushMessage("opoidata", msg);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("delivered", true);
    return ret;
}

UniValue getopoipendingdeliveries(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getopoipendingdeliveries \"stake_address\"\n"
            "\nOPoI relay: read and DRAIN (removes them) every pending delivery queued\n"
            "for this stake address on THIS node — see submitopoipendingdelivery. A\n"
            "miner with no reachable HTTP endpoint polls this on its OWN trusted node\n"
            "instead of exposing its own HTTP server; since deliveries are flooded to\n"
            "every peer, this node has a copy regardless of who originated it.\n"
            "\nArguments:\n"
            "1. stake_address  (string, required) The miner's stake/mining address\n"
            "\nResult:\n"
            "[{ request_id, kind, kind_str, sender_address, payload_hex, sig_time }, ...]\n"
            "\nExamples:\n"
            + HelpExampleCli("getopoipendingdeliveries", "\"tmMinerAddr...\"")
        );

    std::string destAddr = params[0].get_str();
    if (destAddr.empty()) throw std::runtime_error("stake_address must not be empty");

    UniValue arr(UniValue::VARR);
    for (const auto& d : g_opoiCache.GetAndDrainPendingDeliveries(destAddr)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("request_id",     d.requestId);
        obj.pushKV("kind",           (int)d.kind);
        std::string kindStr = d.kind == OPOI_DELIVERY_SHARD_ASSIGN        ? "SHARD_ASSIGN"
                            : d.kind == OPOI_DELIVERY_SHARD_RESULT        ? "SHARD_RESULT"
                            : d.kind == OPOI_DELIVERY_MODEL_CHUNK_REQUEST ? "MODEL_CHUNK_REQUEST"
                            : d.kind == OPOI_DELIVERY_MODEL_CHUNK         ? "MODEL_CHUNK" : "PROMPT";
        obj.pushKV("kind_str",       kindStr);
        obj.pushKV("sender_address", d.senderAddress);
        obj.pushKV("payload_hex",    d.payloadHex);
        obj.pushKV("sig_time",       (int)d.sigTime);
        arr.push_back(obj);
    }
    return arr;
}

// ── OPoI content cache (F14-E) ───────────────────────────────────────────────

UniValue submitopoicontent(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "submitopoicontent \"request_id\" \"kind\" \"content_hex\"\n"
            "\nPublish the plaintext test suite or response text for a VERIFIABLE\n"
            "request, so a permissionless Auditor can fetch and grade it (F14-E) —\n"
            "only the SHA-256 hash of either is ever on-chain otherwise. Rejected\n"
            "unless content_hex's own SHA-256 matches the hash already committed\n"
            "on-chain (the REQUEST's testSuite, or the RESPONSE's responseHash) —\n"
            "there is no signature check here, the hash match IS the trust model:\n"
            "nobody can poison this with the wrong content. Floods to every peer\n"
            "the same way submitopoipendingdelivery does; every node ends up with a\n"
            "copy regardless of who originated it.\n"
            "\nArguments:\n"
            "1. request_id   (string, required) UUID of the VERIFIABLE request\n"
            "2. kind         (string, required) TEST_SUITE or RESPONSE\n"
            "3. content_hex  (string, required) The plaintext, as hex — max 64KB\n"
            "\nResult:\n"
            "{ published: true }\n"
            "\nExamples:\n"
            + HelpExampleCli("submitopoicontent", "\"uuid\" \"TEST_SUITE\" \"646566207465737428293a...\"")
        );

    std::string requestId  = params[0].get_str();
    std::string kindStr    = params[1].get_str();
    std::string contentHex = params[2].get_str();

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    uint8_t kind;
    if (kindStr == "TEST_SUITE")   kind = OPOI_CONTENT_TEST_SUITE;
    else if (kindStr == "RESPONSE") kind = OPOI_CONTENT_RESPONSE;
    else throw std::runtime_error("kind must be TEST_SUITE or RESPONSE");
    if (contentHex.size() > OPOI_DELIVERY_MAX_PAYLOAD_HEX)
        throw std::runtime_error("content_hex exceeds max size");

    COPoIContentMsg msg;
    msg.requestId  = requestId;
    msg.kind       = kind;
    msg.payloadHex = contentHex;

    std::string reason;
    if (!ProcessOPoIContentMessage(msg, reason))
        throw JSONRPCError(RPC_MISC_ERROR, "rejected: " + reason);

    uint256 msgHash = msg.GetHash();
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes) {
            if (pnode->setKnown.insert(msgHash).second)
                pnode->PushMessage("opoicontent", msg);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("published", true);
    return ret;
}

UniValue getopoicontent(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "getopoicontent \"request_id\" \"kind\"\n"
            "\nRead the plaintext test suite or response text for a VERIFIABLE\n"
            "request from THIS node's local content cache (F14-E) — see\n"
            "submitopoicontent. Unlike getopoipendingdeliveries, this does NOT\n"
            "drain: many Auditors read the same content, so it stays available.\n"
            "Empty string if not (yet) published/received on this node — the\n"
            "caller should retry later, not treat this as a permanent absence.\n"
            "\nArguments:\n"
            "1. request_id  (string, required) UUID of the VERIFIABLE request\n"
            "2. kind        (string, required) TEST_SUITE or RESPONSE\n"
            "\nResult:\n"
            "\"content_hex\"  (string) empty if not available yet\n"
            "\nExamples:\n"
            + HelpExampleCli("getopoicontent", "\"uuid\" \"TEST_SUITE\"")
        );

    std::string requestId = params[0].get_str();
    std::string kindStr   = params[1].get_str();
    uint8_t kind;
    if (kindStr == "TEST_SUITE")    kind = OPOI_CONTENT_TEST_SUITE;
    else if (kindStr == "RESPONSE") kind = OPOI_CONTENT_RESPONSE;
    else throw std::runtime_error("kind must be TEST_SUITE or RESPONSE");

    std::string payloadHex;
    g_opoiCache.GetContent(requestId, kind, payloadHex);
    return payloadHex;
}

// ── Registration ──────────────────────────────────────────────────────────────

static const CRPCCommand commands[] =
{   //  category   name                    actor                    okSafeMode
    { "opoi",   "listopoirequests",   &listopoirequests,    false },
    { "opoi",   "listopoiresponses",  &listopoiresponses,   false },
    { "opoi",   "getopoirequest",     &getopoirequest,      false },
    { "opoi",   "getopoistats",       &getopoistats,        false },
    { "opoi",   "submitopoirequest",  &submitopoirequest,   false },
    { "opoi",   "submitopoiresponsecommit", &submitopoiresponsecommit, false },
    { "opoi",   "submitopoiresponse", &submitopoiresponse,  false },
    // Phase 3 — escrow
    { "opoi",   "stakeopoi",          &stakeopoi,           false },
    { "opoi",   "unstakeopoi",        &unstakeopoi,         false },
    { "opoi",   "renewopoistake",     &renewopoistake,      false },
    { "opoi",   "getcanarytestsuite", &getcanarytestsuite,  false },
    { "opoi",   "challengeopoi",      &challengeopoi,       false },
    { "opoi",   "revealchallenge",    &revealchallenge,     false },
    { "opoi",   "listopoistakes",     &listopoistakes,      false },
    { "opoi",   "getopoistake",       &getopoistake,        false },
    { "opoi",   "listopoichallenges", &listopoichallenges,  false },
    // F15-A/A2 — Model Manifest governance
    { "opoi",   "registermodelopoi",  &registermodelopoi,   false },
    { "opoi",   "votemodelopoi",      &votemodelopoi,       false },
    { "opoi",   "getmodelmanifest",   &getmodelmanifest,    false },
    { "opoi",   "listmodelmanifests", &listmodelmanifests,  false },
    { "opoi",   "getmodelgraph",      &getmodelgraph,       false },
    // F15-C — shard coordinator VRF self-claim
    { "opoi",   "claimcoordinator",       &claimcoordinator,       false },
    { "opoi",   "listcoordinatorclaims",  &listcoordinatorclaims,  false },
    // F15-D — shard boundary result
    { "opoi",   "submitshardresult",      &submitshardresult,      false },
    { "opoi",   "getshardresult",         &getshardresult,         false },
    // F14-C — Auditor verification (VERIFIABLE-task payment gate)
    { "opoi",   "submitauditorverification", &submitauditorverification, false },
    { "opoi",   "getauditorverifications",   &getauditorverifications,   false },
    // OPoI relay — P2P delivery for NAT'd/CGNAT'd miners
    { "opoi",   "submitopoipendingdelivery", &submitopoipendingdelivery, false },
    { "opoi",   "getopoipendingdeliveries",  &getopoipendingdeliveries,  false },
    // F14-E — content cache (test suite / response text for permissionless Auditors)
    { "opoi",   "submitopoicontent",  &submitopoicontent,  false },
    { "opoi",   "getopoicontent",     &getopoicontent,     false },
    { "hidden", "rebuilopoidb",       &rebuilopoidb,        false },
    { "hidden", "opoivrfselftest",    &opoivrfselftest,     false },
    { "hidden", "opoivrfverifyraw",   &opoivrfverifyraw,    false },
    { "hidden", "opoiselecttopkexperts", &opoiselecttopkexperts, false },
};

void RegisterOPoIRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
