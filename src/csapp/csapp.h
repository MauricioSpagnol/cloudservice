// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef CSCOIN_CSAPP_H
#define CSCOIN_CSAPP_H

#include <string>
#include <map>
#include <mutex>
#include "serialize.h"
#include "uint256.h"
#include "primitives/transaction.h"
#include "sync.h"

// Status stored in cache
static const int8_t CSAPP_STATUS_RUNNING  = 1;
static const int8_t CSAPP_STATUS_STOPPED  = 2;
static const int8_t CSAPP_STATUS_EXPIRED  = 3;

/**
 * In-memory record for a registered CSApp.
 * Populated from CSAPP_TX_VERSION transactions as the chain is scanned.
 */
struct CSAppData {
    std::string deploymentId;    // UUID assigned by the registering wallet
    std::string owner;           // CS address of the app owner
    std::string specJson;        // Full AppSpec serialised as JSON
    std::string ip;              // Reserved — optional hint from registrant
    uint32_t    registeredAt;    // Block height of the register tx
    uint32_t    updatedAt;       // Block height of the last update tx
    int8_t      status;          // RUNNING / STOPPED / EXPIRED
    CAmount     lockedCscoin;    // Amount locked at registration (billing pool)
    uint256     txHash;          // Hash of the register tx
    uint256     lastTxHash;      // Hash of the most recent update/stop tx

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(deploymentId);
        READWRITE(owner);
        READWRITE(specJson);
        READWRITE(ip);
        READWRITE(registeredAt);
        READWRITE(updatedAt);
        READWRITE(status);
        READWRITE(lockedCscoin);
        READWRITE(txHash);
        READWRITE(lastTxHash);
    }

    void SetNull() {
        deploymentId.clear();
        owner.clear();
        specJson.clear();
        ip.clear();
        registeredAt = 0;
        updatedAt    = 0;
        status       = CSAPP_STATUS_RUNNING;
        lockedCscoin = 0;
        txHash.SetNull();
        lastTxHash.SetNull();
    }

    bool IsNull() const { return deploymentId.empty(); }
};

/**
 * Thread-safe in-memory cache of all CSApp records.
 * Persisted to LevelDB via CSAppCacheDB (csappcachedb.h).
 */
class CSAppCache {
public:
    mutable CCriticalSection cs;

    // deploymentId → CSAppData
    std::map<std::string, CSAppData> mapApps;

    CSAppCache() = default;

    void SetNull() {
        LOCK(cs);
        mapApps.clear();
    }

    bool AddApp(const CSAppData& data) {
        LOCK(cs);
        mapApps[data.deploymentId] = data;
        return true;
    }

    bool UpdateApp(const std::string& deploymentId, const std::string& specJson,
                   uint32_t blockHeight, const uint256& txHash) {
        LOCK(cs);
        auto it = mapApps.find(deploymentId);
        if (it == mapApps.end()) return false;
        it->second.specJson   = specJson;
        it->second.updatedAt  = blockHeight;
        it->second.lastTxHash = txHash;
        return true;
    }

    bool StopApp(const std::string& deploymentId, uint32_t blockHeight,
                 const uint256& txHash, bool expired = false) {
        LOCK(cs);
        auto it = mapApps.find(deploymentId);
        if (it == mapApps.end()) return false;
        it->second.status     = expired ? CSAPP_STATUS_EXPIRED : CSAPP_STATUS_STOPPED;
        it->second.updatedAt  = blockHeight;
        it->second.lastTxHash = txHash;
        return true;
    }

    bool GetApp(const std::string& deploymentId, CSAppData& dataOut) const {
        LOCK(cs);
        auto it = mapApps.find(deploymentId);
        if (it == mapApps.end()) return false;
        dataOut = it->second;
        return true;
    }

    std::vector<CSAppData> ListApps(int8_t statusFilter = -1) const {
        LOCK(cs);
        std::vector<CSAppData> result;
        for (const auto& kv : mapApps) {
            if (statusFilter < 0 || kv.second.status == statusFilter)
                result.push_back(kv.second);
        }
        return result;
    }

    size_t Size() const {
        LOCK(cs);
        return mapApps.size();
    }
};

// Global instance (initialised in init.cpp)
extern CSAppCache g_csappCache;

// Called from main.cpp when connecting/disconnecting blocks
bool ProcessCSAppTransaction(const CTransaction& tx, uint32_t blockHeight, bool fUndo = false);

// Called from init.cpp to rebuild the cache from chain history
void RebuildCSAppCache();

#endif // CSCOIN_CSAPP_H
