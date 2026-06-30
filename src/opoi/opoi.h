// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// OPoI (Optimistic Proof of Inference) subsystem.
// Maintains an in-memory index of:
//   - Pending AI inference requests  (OPOI_REQUEST_TX_TYPE)
//   - Committed AI response proofs   (OPOI_RESPONSE_TX_TYPE)

#ifndef CSCOIN_OPOI_H
#define CSCOIN_OPOI_H

#include <string>
#include <map>
#include <vector>
#include "serialize.h"
#include "uint256.h"
#include "amount.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "consensus/validation.h"

static const int8_t OPOI_STATUS_PENDING    = 1; // request confirmed, awaiting miner
static const int8_t OPOI_STATUS_FULFILLED  = 2; // response committed on-chain
static const int8_t OPOI_STATUS_EXPIRED    = 3; // no response within expiry window

/** One inference request record. */
struct OPoIRequest {
    std::string requestId;      // UUID
    std::string requester;      // CS address of the client
    std::string model;          // e.g. "gemma3:4b"
    uint256     promptHash;     // SHA-256 of the prompt text (verification only)
    uint32_t    maxTokens;
    CAmount     payment;        // CSCOIN reward for the miner
    uint32_t    blockHeight;    // block where this tx confirmed
    uint32_t    sigTime;
    uint256     txHash;         // hash of the REQUEST tx
    int8_t      status;         // PENDING / FULFILLED / EXPIRED

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId);
        READWRITE(requester);
        READWRITE(model);
        READWRITE(promptHash);
        READWRITE(maxTokens);
        READWRITE(payment);
        READWRITE(blockHeight);
        READWRITE(sigTime);
        READWRITE(txHash);
        READWRITE(status);
    }

    void SetNull() {
        requestId.clear();
        requester.clear();
        model.clear();
        promptHash.SetNull();
        maxTokens   = 0;
        payment     = 0;
        blockHeight = 0;
        sigTime     = 0;
        txHash.SetNull();
        status = OPOI_STATUS_PENDING;
    }

    bool IsNull() const { return requestId.empty(); }
};

/** One inference response record. */
struct OPoIResponse {
    std::string requestId;      // links back to OPoIRequest
    std::string minerAddress;   // CS address of the GPU miner
    uint256     responseHash;   // SHA-256 of the response text
    uint32_t    blockHeight;
    uint32_t    sigTime;
    uint256     txHash;         // hash of the RESPONSE tx

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId);
        READWRITE(minerAddress);
        READWRITE(responseHash);
        READWRITE(blockHeight);
        READWRITE(sigTime);
        READWRITE(txHash);
    }

    void SetNull() {
        requestId.clear();
        minerAddress.clear();
        responseHash.SetNull();
        blockHeight = 0;
        sigTime     = 0;
        txHash.SetNull();
    }

    bool IsNull() const { return requestId.empty(); }
};

/** Thread-safe in-memory cache of all OPoI records. */
class OPoICache {
public:
    mutable CCriticalSection cs;

    std::map<std::string, OPoIRequest>  mapRequests;   // requestId → OPoIRequest
    std::map<std::string, OPoIResponse> mapResponses;  // requestId → OPoIResponse

    OPoICache() = default;

    void SetNull() {
        LOCK(cs);
        mapRequests.clear();
        mapResponses.clear();
    }

    bool AddRequest(const OPoIRequest& req) {
        LOCK(cs);
        mapRequests[req.requestId] = req;
        return true;
    }

    bool AddResponse(const OPoIResponse& resp) {
        LOCK(cs);
        mapResponses[resp.requestId] = resp;
        // Mark the matching request as fulfilled
        auto it = mapRequests.find(resp.requestId);
        if (it != mapRequests.end())
            it->second.status = OPOI_STATUS_FULFILLED;
        return true;
    }

    bool GetRequest(const std::string& requestId, OPoIRequest& out) const {
        LOCK(cs);
        auto it = mapRequests.find(requestId);
        if (it == mapRequests.end()) return false;
        out = it->second;
        return true;
    }

    bool GetResponse(const std::string& requestId, OPoIResponse& out) const {
        LOCK(cs);
        auto it = mapResponses.find(requestId);
        if (it == mapResponses.end()) return false;
        out = it->second;
        return true;
    }

    std::vector<OPoIRequest> ListRequests(int8_t statusFilter = -1) const {
        LOCK(cs);
        std::vector<OPoIRequest> result;
        for (const auto& kv : mapRequests) {
            if (statusFilter < 0 || kv.second.status == statusFilter)
                result.push_back(kv.second);
        }
        return result;
    }

    std::vector<OPoIResponse> ListResponses() const {
        LOCK(cs);
        std::vector<OPoIResponse> result;
        result.reserve(mapResponses.size());
        for (const auto& kv : mapResponses)
            result.push_back(kv.second);
        return result;
    }

    size_t RequestCount()  const { LOCK(cs); return mapRequests.size(); }
    size_t ResponseCount() const { LOCK(cs); return mapResponses.size(); }
};

// Global instance (initialised in init.cpp alongside g_csappCache)
extern OPoICache g_opoiCache;

// Called from main.cpp ConnectBlock / DisconnectBlock
bool ProcessOPoITransaction(const CTransaction& tx, uint32_t blockHeight, bool fUndo = false);

// Called from init.cpp to rebuild from chain history
void RebuildOPoICache();

// Validate an OPoI tx (called from CheckTransaction)
bool CheckOPoITransaction(const CTransaction& tx, CValidationState& state);

#endif // CSCOIN_OPOI_H
