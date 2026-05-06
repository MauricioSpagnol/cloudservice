// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// RPC commands for the CSApp subsystem:
//   listcsapps     — list all registered apps (optional status filter)
//   getcsapp       — get full spec of a single app by deployment_id
//   rebuildcsappdb — rescan chain and rebuild the in-memory app cache
//   registercsapp  — register a new app on the blockchain
//   stopcsapp      — stop a running app on the blockchain
//   updatecsapp    — update the spec of a registered app on the blockchain

#include "csapp/csapp.h"
#include "rpc/server.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "main.h"
#include "util.h"
#include "univalue/include/univalue.h"
#include "primitives/transaction.h"
#include "wallet/wallet.h"
#include "key_io.h"
#include "csnode/obfuscation.h"
#include "init.h"

#ifdef ENABLE_WALLET
extern CWallet* pwalletMain;
void EnsureWalletIsUnlocked();
#endif

static UniValue CSAppDataToUniValue(const CSAppData& d)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("deployment_id",  d.deploymentId);
    obj.pushKV("owner",          d.owner);
    obj.pushKV("spec",           d.specJson);
    obj.pushKV("ip",             d.ip);
    obj.pushKV("registered_at",  (int)d.registeredAt);
    obj.pushKV("updated_at",     (int)d.updatedAt);
    obj.pushKV("locked_cscoin",  ValueFromAmount(d.lockedCscoin));

    std::string statusStr;
    switch (d.status) {
        case CSAPP_STATUS_RUNNING: statusStr = "RUNNING";  break;
        case CSAPP_STATUS_STOPPED: statusStr = "STOPPED";  break;
        case CSAPP_STATUS_EXPIRED: statusStr = "EXPIRED";  break;
        default:                   statusStr = "UNKNOWN";  break;
    }
    obj.pushKV("status",     statusStr);
    obj.pushKV("tx_hash",    d.txHash.GetHex());
    obj.pushKV("last_tx",    d.lastTxHash.GetHex());
    return obj;
}

UniValue listcsapps(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "listcsapps ( \"status\" )\n"
            "\nReturn a list of all registered CSApps.\n"
            "\nArguments:\n"
            "1. status  (string, optional) Filter: RUNNING | STOPPED | EXPIRED\n"
            "\nResult:\n"
            "[{ deployment_id, owner, spec, status, registered_at, ... }, ...]\n"
            "\nExamples:\n"
            + HelpExampleCli("listcsapps", "")
            + HelpExampleCli("listcsapps", "\"RUNNING\"")
            + HelpExampleRpc("listcsapps", "\"RUNNING\"")
        );

    int8_t statusFilter = -1;
    if (params.size() == 1) {
        std::string s = params[0].get_str();
        if      (s == "RUNNING") statusFilter = CSAPP_STATUS_RUNNING;
        else if (s == "STOPPED") statusFilter = CSAPP_STATUS_STOPPED;
        else if (s == "EXPIRED") statusFilter = CSAPP_STATUS_EXPIRED;
        else throw std::runtime_error("Invalid status. Use RUNNING, STOPPED or EXPIRED.");
    }

    UniValue arr(UniValue::VARR);
    for (const auto& d : g_csappCache.ListApps(statusFilter))
        arr.push_back(CSAppDataToUniValue(d));
    return arr;
}

UniValue getcsapp(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getcsapp \"deployment_id\"\n"
            "\nReturn full data of a single CSApp.\n"
            "\nArguments:\n"
            "1. deployment_id  (string, required) UUID of the deployment\n"
            "\nExamples:\n"
            + HelpExampleCli("getcsapp", "\"550e8400-e29b-41d4-a716-446655440000\"")
            + HelpExampleRpc("getcsapp", "\"550e8400-e29b-41d4-a716-446655440000\"")
        );

    std::string depId = params[0].get_str();
    CSAppData data;
    if (!g_csappCache.GetApp(depId, data))
        throw std::runtime_error("App not found: " + depId);
    return CSAppDataToUniValue(data);
}

UniValue rebuildcsappdb(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "rebuildcsappdb\n"
            "\nRescan the entire blockchain and rebuild the CSApp in-memory cache.\n"
            "This may take several minutes on a fully synced node.\n"
            "\nExamples:\n"
            + HelpExampleCli("rebuildcsappdb", "")
            + HelpExampleRpc("rebuildcsappdb", "")
        );

    RebuildCSAppCache();
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("rebuilt", true);
    ret.pushKV("apps",    (int)g_csappCache.Size());
    return ret;
}

// ---------------------------------------------------------------------------
// Helper: sign a message string with a wallet key corresponding to a CSCoin
// address.  Returns the signature in vchSig on success.
// ---------------------------------------------------------------------------
static bool SignWithAddress(const std::string& address,
                            const std::string& message,
                            std::vector<unsigned char>& vchSig,
                            std::string& errMsg)
{
#ifndef ENABLE_WALLET
    errMsg = "Wallet support not compiled in";
    return false;
#else
    if (!pwalletMain) {
        errMsg = "Wallet not available";
        return false;
    }

    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        errMsg = "Invalid CSCoin address: " + address;
        return false;
    }
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        errMsg = "Address is not a P2PKH address";
        return false;
    }
    CKey key;
    if (!pwalletMain->GetKey(*keyID, key)) {
        errMsg = "Private key not in wallet for address " + address;
        return false;
    }
    CObfuScationSigner signer;
    return signer.SignMessage(message, errMsg, vchSig, key);
#endif
}

// ---------------------------------------------------------------------------
// registercsapp "deployment_id" "spec_json" "owner_address" locked_cscoin
//               ( "ip_hint" )
// ---------------------------------------------------------------------------
UniValue registercsapp(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw std::runtime_error(
            "registercsapp \"deployment_id\" \"spec_json\" \"owner_address\""
            " locked_cscoin ( \"ip_hint\" )\n"
            "\nRegister a new CSApp on the blockchain.\n"
            "\nArguments:\n"
            "1. deployment_id   (string, required) Unique UUID for this deployment\n"
            "2. spec_json       (string, required) JSON string containing the AppSpec\n"
            "3. owner_address   (string, required) Wallet address that owns this app\n"
            "4. locked_cscoin   (numeric, required) CSCOIN amount to lock for billing\n"
            "5. ip_hint         (string, optional) IP hint for scheduling (default: \"\")\n"
            "\nResult:\n"
            "\"txid\"  (string) Transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("registercsapp",
                "\"uuid\" '{\"image\":\"nginx\"}' \"t1Xyz...\" 100.0")
            + HelpExampleRpc("registercsapp",
                "\"uuid\", '{\"image\":\"nginx\"}', \"t1Xyz...\", 100.0")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string deployId  = params[0].get_str();
    std::string specJson  = params[1].get_str();
    std::string owner     = params[2].get_str();
    CAmount lockedAmount  = AmountFromValue(params[3]);
    std::string ipHint    = (params.size() >= 5) ? params[4].get_str() : "";

    if (deployId.empty()) throw std::runtime_error("deployment_id must not be empty");
    if (specJson.empty()) throw std::runtime_error("spec_json must not be empty");
    if (lockedAmount <= 0) throw std::runtime_error("locked_cscoin must be positive");

    CMutableTransaction mutTx;
    mutTx.nVersion          = CSAPP_TX_VERSION;
    mutTx.nType             = CSAPP_REGISTER_TX_TYPE;
    mutTx.csappDeploymentId = deployId;
    mutTx.csappOwner        = owner;
    mutTx.csappSpecJson     = specJson;
    mutTx.csappIp           = ipHint;
    mutTx.csappLockedAmount = lockedAmount;

    // Sign: message = deployId + owner + specJson + ipHint + amount_str
    std::string sigMsg = deployId + owner + specJson + ipHint +
                         strprintf("%d", lockedAmount);
    std::string errMsg;
    if (!SignWithAddress(owner, sigMsg, mutTx.csappSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign tx: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for registercsapp");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid", tx.GetHash().GetHex());
    return ret;
}

// ---------------------------------------------------------------------------
// stopcsapp "deployment_id" "owner_address"
// ---------------------------------------------------------------------------
UniValue stopcsapp(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "stopcsapp \"deployment_id\" \"owner_address\"\n"
            "\nStop a running CSApp on the blockchain.\n"
            "\nArguments:\n"
            "1. deployment_id  (string, required) UUID of the deployment to stop\n"
            "2. owner_address  (string, required) Owner wallet address\n"
            "\nResult:\n"
            "\"txid\"  (string) Transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("stopcsapp", "\"uuid\" \"t1Xyz...\"")
            + HelpExampleRpc("stopcsapp",  "\"uuid\", \"t1Xyz...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string deployId = params[0].get_str();
    std::string owner    = params[1].get_str();

    if (deployId.empty()) throw std::runtime_error("deployment_id must not be empty");

    CMutableTransaction mutTx;
    mutTx.nVersion          = CSAPP_TX_VERSION;
    mutTx.nType             = CSAPP_STOP_TX_TYPE;
    mutTx.csappDeploymentId = deployId;
    mutTx.csappOwner        = owner;

    std::string sigMsg = deployId + owner + std::string("stop");
    std::string errMsg;
    if (!SignWithAddress(owner, sigMsg, mutTx.csappSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign tx: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for stopcsapp");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid", tx.GetHash().GetHex());
    return ret;
}

// ---------------------------------------------------------------------------
// updatecsapp "deployment_id" "spec_json" "owner_address"
// ---------------------------------------------------------------------------
UniValue updatecsapp(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "updatecsapp \"deployment_id\" \"spec_json\" \"owner_address\"\n"
            "\nUpdate the spec of a registered CSApp on the blockchain.\n"
            "\nArguments:\n"
            "1. deployment_id  (string, required) UUID of the deployment to update\n"
            "2. spec_json      (string, required) Updated JSON AppSpec\n"
            "3. owner_address  (string, required) Owner wallet address\n"
            "\nResult:\n"
            "\"txid\"  (string) Transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("updatecsapp",
                "\"uuid\" '{\"image\":\"nginx:1.25\"}' \"t1Xyz...\"")
            + HelpExampleRpc("updatecsapp",
                "\"uuid\", '{\"image\":\"nginx:1.25\"}', \"t1Xyz...\"")
        );

#ifdef ENABLE_WALLET
    EnsureWalletIsUnlocked();
#endif

    std::string deployId = params[0].get_str();
    std::string specJson = params[1].get_str();
    std::string owner    = params[2].get_str();

    if (deployId.empty()) throw std::runtime_error("deployment_id must not be empty");
    if (specJson.empty()) throw std::runtime_error("spec_json must not be empty");

    CMutableTransaction mutTx;
    mutTx.nVersion          = CSAPP_TX_VERSION;
    mutTx.nType             = CSAPP_UPDATE_TX_TYPE;
    mutTx.csappDeploymentId = deployId;
    mutTx.csappOwner        = owner;
    mutTx.csappSpecJson     = specJson;

    std::string sigMsg = deployId + owner + specJson + std::string("update");
    std::string errMsg;
    if (!SignWithAddress(owner, sigMsg, mutTx.csappSig, errMsg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign tx: " + errMsg);

    CTransaction tx(mutTx);
#ifdef ENABLE_WALLET
    CReserveKey reservekey(pwalletMain);
    CWalletTx walletTx(pwalletMain, tx);
    if (!pwalletMain->CommitTransaction(walletTx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "CommitTransaction failed for updatecsapp");
#endif

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid", tx.GetHash().GetHex());
    return ret;
}

static const CRPCCommand commands[] =
{   //  category    name                actor                okSafeMode
    { "csapp",  "listcsapps",       &listcsapps,        false },
    { "csapp",  "getcsapp",         &getcsapp,          false },
    { "hidden", "rebuildcsappdb",   &rebuildcsappdb,    false },
    { "csapp",  "registercsapp",    &registercsapp,     false },
    { "csapp",  "stopcsapp",        &stopcsapp,         false },
    { "csapp",  "updatecsapp",      &updatecsapp,       false },
};

void RegisterCSAppRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
