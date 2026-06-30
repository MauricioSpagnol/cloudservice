// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// RPC commands for the OPoI (Optimistic Proof of Inference) subsystem:
//   listopoirequests   — list AI inference requests (optional status filter)
//   listopoiresponses  — list committed AI response proofs
//   getopoirequest     — get a single request by UUID
//   submitopoirequest  — broadcast a new REQUEST tx (client side)
//   submitopoiresponse — broadcast a RESPONSE tx   (miner side)
//   rebuilopoidb       — rescan chain and rebuild OPoI cache

#include "opoi/opoi.h"
#include "rpc/server.h"
#include "primitives/transaction.h"
#include "main.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "univalue/include/univalue.h"
#include "wallet/wallet.h"
#include "key_io.h"
#include "csnode/obfuscation.h"
#include "init.h"

#ifdef ENABLE_WALLET
extern CWallet* pwalletMain;
void EnsureWalletIsUnlocked();
#endif

// ── Helpers ──────────────────────────────────────────────────────────────────

static UniValue OPoIRequestToUniValue(const OPoIRequest& r)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("request_id",   r.requestId);
    obj.pushKV("requester",    r.requester);
    obj.pushKV("model",        r.model);
    obj.pushKV("prompt_hash",  r.promptHash.GetHex());
    obj.pushKV("max_tokens",   (int)r.maxTokens);
    obj.pushKV("payment",      ValueFromAmount(r.payment));
    obj.pushKV("block_height", (int)r.blockHeight);
    obj.pushKV("sig_time",     (int)r.sigTime);
    obj.pushKV("tx_hash",      r.txHash.GetHex());

    std::string s;
    switch (r.status) {
        case OPOI_STATUS_PENDING:   s = "PENDING";   break;
        case OPOI_STATUS_FULFILLED: s = "FULFILLED"; break;
        case OPOI_STATUS_EXPIRED:   s = "EXPIRED";   break;
        default:                    s = "UNKNOWN";   break;
    }
    obj.pushKV("status", s);
    return obj;
}

static UniValue OPoIResponseToUniValue(const OPoIResponse& r)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("request_id",    r.requestId);
    obj.pushKV("miner_address", r.minerAddress);
    obj.pushKV("response_hash", r.responseHash.GetHex());
    obj.pushKV("block_height",  (int)r.blockHeight);
    obj.pushKV("sig_time",      (int)r.sigTime);
    obj.pushKV("tx_hash",       r.txHash.GetHex());
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

// submitopoirequest "request_id" "model" "prompt_hash_hex" max_tokens payment "requester_address"
UniValue submitopoirequest(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 6)
        throw std::runtime_error(
            "submitopoirequest \"request_id\" \"model\" \"prompt_hash_hex\""
            " max_tokens payment \"requester_address\"\n"
            "\nBroadcast an AI inference request transaction.\n"
            "\nThe actual prompt text is NOT stored on-chain — only its SHA-256 hash.\n"
            "Send the prompt directly to the miner's HTTP API after broadcasting.\n"
            "\nArguments:\n"
            "1. request_id        (string, required) UUID for this request\n"
            "2. model             (string, required) Model name (e.g. \"gemma3:4b\")\n"
            "3. prompt_hash_hex   (string, required) SHA-256 of the prompt as hex\n"
            "4. max_tokens        (numeric, required) Maximum tokens in the response\n"
            "5. payment           (numeric, required) CSCOIN reward for the miner\n"
            "6. requester_address (string, required) Your CS wallet address\n"
            "\nResult:\n"
            "\"txid\"  (string) Transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("submitopoirequest",
                "\"uuid\" \"gemma3:4b\" \"abc123...\" 512 1.0 \"t1Xyz...\"")
            + HelpExampleRpc("submitopoirequest",
                "\"uuid\", \"gemma3:4b\", \"abc123...\", 512, 1.0, \"t1Xyz...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId = params[0].get_str();
    std::string model     = params[1].get_str();
    std::string phHex     = params[2].get_str();
    uint32_t    maxTok    = (uint32_t)params[3].get_int();
    CAmount     payment   = AmountFromValue(params[4]);
    std::string requester = params[5].get_str();

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (model.empty())     throw std::runtime_error("model must not be empty");
    if (payment <= 0)      throw std::runtime_error("payment must be positive");

    uint256 promptHash;
    promptHash.SetHex(phHex);
    if (promptHash.IsNull())
        throw std::runtime_error("prompt_hash_hex is invalid or all-zero");

    CMutableTransaction mutTx;
    mutTx.nVersion       = OPOI_TX_VERSION;
    mutTx.nType          = OPOI_REQUEST_TX_TYPE;
    mutTx.opoiRequestId  = requestId;
    mutTx.opoiRequester  = requester;
    mutTx.opoiModel      = model;
    mutTx.opoiPromptHash = promptHash;
    mutTx.opoiMaxTokens  = maxTok;
    mutTx.opoiPayment    = payment;
    mutTx.opoiSigTime    = (uint32_t)GetTime();

    // Sign: requestId + requester + model + promptHashHex + maxTokens + payment
    std::string sigMsg = requestId + requester + model + phHex +
                         strprintf("%u%d", maxTok, payment);
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
    ret.pushKV("txid",       tx.GetHash().GetHex());
    ret.pushKV("request_id", requestId);
    return ret;
}

// submitopoiresponse "request_id" "response_hash_hex" "miner_address"
UniValue submitopoiresponse(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "submitopoiresponse \"request_id\" \"response_hash_hex\" \"miner_address\"\n"
            "\nBroadcast an AI inference response proof transaction (miner only).\n"
            "\nArguments:\n"
            "1. request_id        (string, required) UUID of the inference request\n"
            "2. response_hash_hex (string, required) SHA-256 of the response text as hex\n"
            "3. miner_address     (string, required) Miner's CS wallet address\n"
            "\nResult:\n"
            "\"txid\"  (string) Transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("submitopoiresponse",
                "\"uuid\" \"def456...\" \"t1MinerAddr...\"")
            + HelpExampleRpc("submitopoiresponse",
                "\"uuid\", \"def456...\", \"t1MinerAddr...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId  = params[0].get_str();
    std::string rhHex      = params[1].get_str();
    std::string minerAddr  = params[2].get_str();

    if (requestId.empty()) throw std::runtime_error("request_id must not be empty");
    if (minerAddr.empty()) throw std::runtime_error("miner_address must not be empty");

    uint256 responseHash;
    responseHash.SetHex(rhHex);
    if (responseHash.IsNull())
        throw std::runtime_error("response_hash_hex is invalid or all-zero");

    CMutableTransaction mutTx;
    mutTx.nVersion          = OPOI_TX_VERSION;
    mutTx.nType             = OPOI_RESPONSE_TX_TYPE;
    mutTx.opoiRequestId     = requestId;
    mutTx.opoiMinerAddress  = minerAddr;
    mutTx.opoiResponseHash  = responseHash;
    mutTx.opoiSigTime       = (uint32_t)GetTime();

    std::string sigMsg = requestId + minerAddr + rhHex;
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
    ret.pushKV("txid",       tx.GetHash().GetHex());
    ret.pushKV("request_id", requestId);
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

// ── Phase 3 helpers ───────────────────────────────────────────────────────────

static std::string StakeStatusStr(int8_t s) {
    switch (s) {
        case OPOI_STAKE_ACTIVE:    return "ACTIVE";
        case OPOI_STAKE_UNSTAKING: return "UNSTAKING";
        case OPOI_STAKE_RELEASED:  return "RELEASED";
        case OPOI_STAKE_SLASHED:   return "SLASHED";
        default:                   return "UNKNOWN";
    }
}

static std::string ChallengeStatusStr(int8_t s) {
    switch (s) {
        case OPOI_CHALLENGE_OPEN:    return "OPEN";
        case OPOI_CHALLENGE_SLASHED: return "SLASHED";
        case OPOI_CHALLENGE_EXPIRED: return "EXPIRED";
        default:                     return "UNKNOWN";
    }
}

static UniValue OPoIStakeToUniValue(const OPoIStake& s)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("miner_address",  s.minerAddress);
    obj.pushKV("collateral_txid",s.collateralIn.hash.GetHex());
    obj.pushKV("collateral_vout",(int)s.collateralIn.n);
    obj.pushKV("amount",         ValueFromAmount(s.amount));
    obj.pushKV("block_height",   (int)s.blockHeight);
    obj.pushKV("status",         StakeStatusStr(s.stakeStatus));
    obj.pushKV("unstake_height", (int)s.unstakeHeight);
    obj.pushKV("tx_hash",        s.txHash.GetHex());
    return obj;
}

static UniValue OPoIChallengeToUniValue(const OPoIChallenge& c)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("request_id",           c.requestId);
    obj.pushKV("challenger_address",   c.challengerAddress);
    obj.pushKV("claimed_response_hash",c.claimedResponseHash.GetHex());
    obj.pushKV("block_height",         (int)c.blockHeight);
    obj.pushKV("status",               ChallengeStatusStr(c.challengeStatus));
    obj.pushKV("tx_hash",              c.txHash.GetHex());
    return obj;
}

// ── stakeopoi ─────────────────────────────────────────────────────────────────

UniValue stakeopoi(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "stakeopoi \"miner_address\" \"collateral_txid\" collateral_vout\n"
            "\nRegister an OPoI stake for a miner.\n"
            "\nThe referenced UTXO must be >= the network minimum stake (100 CS on mainnet).\n"
            "\nArguments:\n"
            "1. miner_address    (string, required) Miner's CS wallet address\n"
            "2. collateral_txid  (string, required) TXID of the collateral UTXO\n"
            "3. collateral_vout  (numeric, required) Output index of the collateral UTXO\n"
            "\nResult:\n"
            "{ txid, miner_address }\n"
            "\nExamples:\n"
            + HelpExampleCli("stakeopoi", "\"t1MinerAddr...\" \"abc123...\" 0")
            + HelpExampleRpc("stakeopoi", "\"t1MinerAddr...\", \"abc123...\", 0")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string minerAddr = params[0].get_str();
    uint256     colTxid;
    colTxid.SetHex(params[1].get_str());
    uint32_t    colVout   = (uint32_t)params[2].get_int();

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

// ── challengeopoi ─────────────────────────────────────────────────────────────

UniValue challengeopoi(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "challengeopoi \"request_id\" \"challenger_address\" \"claimed_response_hash\"\n"
            "\nChallenge a committed RESPONSE on-chain.\n"
            "\nIf the challenge is not countered within the challenge window, the miner\n"
            "who submitted the RESPONSE will have their stake slashed.\n"
            "\nArguments:\n"
            "1. request_id             (string, required) UUID of the disputed request\n"
            "2. challenger_address     (string, required) Your CS wallet address\n"
            "3. claimed_response_hash  (string, required) SHA-256 you claim is the correct response\n"
            "\nResult:\n"
            "{ txid, request_id }\n"
            "\nExamples:\n"
            + HelpExampleCli("challengeopoi",
                "\"uuid\" \"t1ChalAddr...\" \"abc123...\"")
            + HelpExampleRpc("challengeopoi",
                "\"uuid\", \"t1ChalAddr...\", \"abc123...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string requestId   = params[0].get_str();
    std::string challenger  = params[1].get_str();
    std::string claimedHex  = params[2].get_str();

    if (requestId.empty())  throw std::runtime_error("request_id must not be empty");
    if (challenger.empty()) throw std::runtime_error("challenger_address must not be empty");

    uint256 claimedHash;
    claimedHash.SetHex(claimedHex);
    if (claimedHash.IsNull())
        throw std::runtime_error("claimed_response_hash is invalid or all-zero");

    OPoIResponse resp;
    if (!g_opoiCache.GetResponse(requestId, resp))
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "No committed response found for request " + requestId);

    if (claimedHash == resp.responseHash)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "claimed_response_hash matches the committed hash — nothing to challenge");

    CMutableTransaction mutTx;
    mutTx.nVersion        = OPOI_TX_VERSION;
    mutTx.nType           = OPOI_CHALLENGE_TX_TYPE;
    mutTx.opoiRequestId   = requestId;
    mutTx.opoiRequester   = challenger;
    mutTx.opoiResponseHash= claimedHash;
    mutTx.opoiSigTime     = (uint32_t)GetTime();

    std::string sigMsg = requestId + challenger + claimedHex;
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
    ret.pushKV("txid",       tx.GetHash().GetHex());
    ret.pushKV("request_id", requestId);
    ret.pushKV("challenged_miner", resp.minerAddress);
    ret.pushKV("window_blocks", (int)Params().GetConsensus().nOPoIChallengeWindowBlocks);
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
            "1. status  (string, optional) OPEN | SLASHED | EXPIRED\n"
            "\nExamples:\n"
            + HelpExampleCli("listopoichallenges", "")
            + HelpExampleCli("listopoichallenges", "\"OPEN\"")
            + HelpExampleRpc("listopoichallenges", "\"OPEN\"")
        );

    int8_t statusFilter = -1;
    if (params.size() == 1) {
        std::string s = params[0].get_str();
        if      (s == "OPEN")    statusFilter = OPOI_CHALLENGE_OPEN;
        else if (s == "SLASHED") statusFilter = OPOI_CHALLENGE_SLASHED;
        else if (s == "EXPIRED") statusFilter = OPOI_CHALLENGE_EXPIRED;
        else throw std::runtime_error("Invalid status. Use OPEN, SLASHED or EXPIRED.");
    }

    UniValue arr(UniValue::VARR);
    for (const auto& c : g_opoiCache.ListChallenges(statusFilter))
        arr.push_back(OPoIChallengeToUniValue(c));
    return arr;
}

// ── Registration ──────────────────────────────────────────────────────────────

static const CRPCCommand commands[] =
{   //  category   name                    actor                    okSafeMode
    { "opoi",   "listopoirequests",   &listopoirequests,    false },
    { "opoi",   "listopoiresponses",  &listopoiresponses,   false },
    { "opoi",   "getopoirequest",     &getopoirequest,      false },
    { "opoi",   "submitopoirequest",  &submitopoirequest,   false },
    { "opoi",   "submitopoiresponse", &submitopoiresponse,  false },
    // Phase 3 — escrow
    { "opoi",   "stakeopoi",          &stakeopoi,           false },
    { "opoi",   "unstakeopoi",        &unstakeopoi,         false },
    { "opoi",   "challengeopoi",      &challengeopoi,       false },
    { "opoi",   "listopoistakes",     &listopoistakes,      false },
    { "opoi",   "getopoistake",       &getopoistake,        false },
    { "opoi",   "listopoichallenges", &listopoichallenges,  false },
    { "hidden", "rebuilopoidb",       &rebuilopoidb,        false },
};

void RegisterOPoIRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
