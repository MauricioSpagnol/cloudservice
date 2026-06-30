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
    ret.pushKV("rebuilt",   true);
    ret.pushKV("requests",  (int)g_opoiCache.RequestCount());
    ret.pushKV("responses", (int)g_opoiCache.ResponseCount());
    return ret;
}

// ── Registration ──────────────────────────────────────────────────────────────

static const CRPCCommand commands[] =
{   //  category   name                    actor                  okSafeMode
    { "opoi",   "listopoirequests",   &listopoirequests,   false },
    { "opoi",   "listopoiresponses",  &listopoiresponses,  false },
    { "opoi",   "getopoirequest",     &getopoirequest,     false },
    { "opoi",   "submitopoirequest",  &submitopoirequest,  false },
    { "opoi",   "submitopoiresponse", &submitopoiresponse, false },
    { "hidden", "rebuilopoidb",       &rebuilopoidb,       false },
};

void RegisterOPoIRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
