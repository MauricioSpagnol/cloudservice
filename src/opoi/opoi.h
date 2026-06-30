// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// OPoI (Optimistic Proof of Inference) subsystem.
// Maintains an in-memory index of:
//   Phase 2:
//     - Pending AI inference requests  (OPOI_REQUEST_TX_TYPE  = 1)
//     - Committed AI response proofs   (OPOI_RESPONSE_TX_TYPE = 2)
//   Phase 3:
//     - Miner stake registrations      (OPOI_STAKE_TX_TYPE    = 3)
//     - Unstake requests               (OPOI_UNSTAKE_TX_TYPE  = 4)
//     - Response challenges            (OPOI_CHALLENGE_TX_TYPE= 5)

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
#include "consensus/params.h"

// ── Status constants ──────────────────────────────────────────────────────────

static const int8_t OPOI_STATUS_PENDING    = 1;
static const int8_t OPOI_STATUS_FULFILLED  = 2;
static const int8_t OPOI_STATUS_EXPIRED    = 3;

static const int8_t OPOI_STAKE_ACTIVE      = 1;
static const int8_t OPOI_STAKE_UNSTAKING   = 2;
static const int8_t OPOI_STAKE_RELEASED    = 3;
static const int8_t OPOI_STAKE_SLASHED     = 4;

static const int8_t OPOI_CHALLENGE_OPEN    = 1;
static const int8_t OPOI_CHALLENGE_SLASHED = 2;
static const int8_t OPOI_CHALLENGE_EXPIRED = 3;

// ── Phase 2: request / response records ──────────────────────────────────────

struct OPoIRequest {
    std::string requestId;
    std::string requester;
    std::string model;
    uint256     promptHash;
    uint32_t    maxTokens;
    CAmount     payment;
    uint32_t    blockHeight;
    uint32_t    sigTime;
    uint256     txHash;
    int8_t      status;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(requester); READWRITE(model);
        READWRITE(promptHash); READWRITE(maxTokens); READWRITE(payment);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(status);
    }

    void SetNull() {
        requestId.clear(); requester.clear(); model.clear();
        promptHash.SetNull(); maxTokens = 0; payment = 0;
        blockHeight = 0; sigTime = 0; txHash.SetNull();
        status = OPOI_STATUS_PENDING;
    }
    bool IsNull() const { return requestId.empty(); }
};

struct OPoIResponse {
    std::string requestId;
    std::string minerAddress;
    uint256     responseHash;
    uint32_t    blockHeight;
    uint32_t    sigTime;
    uint256     txHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(minerAddress); READWRITE(responseHash);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
    }

    void SetNull() {
        requestId.clear(); minerAddress.clear(); responseHash.SetNull();
        blockHeight = 0; sigTime = 0; txHash.SetNull();
    }
    bool IsNull() const { return requestId.empty(); }
};

// ── Phase 3: stake / challenge records ───────────────────────────────────────

struct OPoIStake {
    std::string minerAddress;
    COutPoint   collateralIn;   // UTXO the miner has pledged
    CAmount     amount;         // pledged amount (at registration time)
    uint32_t    blockHeight;    // block where STAKE tx confirmed
    uint32_t    sigTime;
    uint256     txHash;
    int8_t      stakeStatus;    // ACTIVE / UNSTAKING / RELEASED / SLASHED
    uint32_t    unstakeHeight;  // block where UNSTAKE tx confirmed (0 if not unstaking)

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(minerAddress); READWRITE(collateralIn); READWRITE(amount);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(stakeStatus); READWRITE(unstakeHeight);
    }

    void SetNull() {
        minerAddress.clear(); collateralIn.SetNull(); amount = 0;
        blockHeight = 0; sigTime = 0; txHash.SetNull();
        stakeStatus = OPOI_STAKE_ACTIVE; unstakeHeight = 0;
    }
    bool IsNull()      const { return minerAddress.empty(); }
    bool IsActive()    const { return stakeStatus == OPOI_STAKE_ACTIVE; }
    bool IsUnstaking() const { return stakeStatus == OPOI_STAKE_UNSTAKING; }
    bool IsSlashed()   const { return stakeStatus == OPOI_STAKE_SLASHED; }
};

struct OPoIChallenge {
    std::string requestId;          // which RESPONSE is disputed
    std::string challengerAddress;
    uint256     claimedResponseHash; // what challenger claims was the correct response hash
    uint32_t    blockHeight;
    uint32_t    sigTime;
    uint256     txHash;
    int8_t      challengeStatus;    // OPEN / SLASHED / EXPIRED

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(challengerAddress); READWRITE(claimedResponseHash);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(challengeStatus);
    }

    void SetNull() {
        requestId.clear(); challengerAddress.clear(); claimedResponseHash.SetNull();
        blockHeight = 0; sigTime = 0; txHash.SetNull();
        challengeStatus = OPOI_CHALLENGE_OPEN;
    }
    bool IsNull() const { return requestId.empty(); }
    bool IsOpen() const { return challengeStatus == OPOI_CHALLENGE_OPEN; }
};

// ── Thread-safe cache ─────────────────────────────────────────────────────────

class OPoICache {
public:
    mutable CCriticalSection cs;

    // Phase 2
    std::map<std::string, OPoIRequest>  mapRequests;   // requestId → OPoIRequest
    std::map<std::string, OPoIResponse> mapResponses;  // requestId → OPoIResponse

    // Phase 3
    std::map<std::string, OPoIStake>     mapStakes;     // minerAddress → OPoIStake
    std::map<std::string, OPoIChallenge> mapChallenges; // requestId → OPoIChallenge

    OPoICache() = default;

    void SetNull() {
        LOCK(cs);
        mapRequests.clear(); mapResponses.clear();
        mapStakes.clear(); mapChallenges.clear();
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────────

    bool AddRequest(const OPoIRequest& req) {
        LOCK(cs); mapRequests[req.requestId] = req; return true;
    }

    bool AddResponse(const OPoIResponse& resp) {
        LOCK(cs);
        mapResponses[resp.requestId] = resp;
        auto it = mapRequests.find(resp.requestId);
        if (it != mapRequests.end())
            it->second.status = OPOI_STATUS_FULFILLED;
        return true;
    }

    bool GetRequest(const std::string& id, OPoIRequest& out) const {
        LOCK(cs);
        auto it = mapRequests.find(id);
        if (it == mapRequests.end()) return false;
        out = it->second; return true;
    }

    bool GetResponse(const std::string& id, OPoIResponse& out) const {
        LOCK(cs);
        auto it = mapResponses.find(id);
        if (it == mapResponses.end()) return false;
        out = it->second; return true;
    }

    std::vector<OPoIRequest> ListRequests(int8_t statusFilter = -1) const {
        LOCK(cs);
        std::vector<OPoIRequest> result;
        for (const auto& kv : mapRequests)
            if (statusFilter < 0 || kv.second.status == statusFilter)
                result.push_back(kv.second);
        return result;
    }

    std::vector<OPoIResponse> ListResponses() const {
        LOCK(cs);
        std::vector<OPoIResponse> result;
        result.reserve(mapResponses.size());
        for (const auto& kv : mapResponses) result.push_back(kv.second);
        return result;
    }

    size_t RequestCount()  const { LOCK(cs); return mapRequests.size(); }
    size_t ResponseCount() const { LOCK(cs); return mapResponses.size(); }

    // ── Phase 3: stakes ───────────────────────────────────────────────────────

    bool AddStake(const OPoIStake& stake) {
        LOCK(cs); mapStakes[stake.minerAddress] = stake; return true;
    }

    bool GetStake(const std::string& minerAddress, OPoIStake& out) const {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        if (it == mapStakes.end()) return false;
        out = it->second; return true;
    }

    bool IsActiveStaker(const std::string& minerAddress) const {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        return it != mapStakes.end() && it->second.IsActive();
    }

    bool StartUnstake(const std::string& minerAddress, uint32_t height) {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        if (it == mapStakes.end() || !it->second.IsActive()) return false;
        it->second.stakeStatus  = OPOI_STAKE_UNSTAKING;
        it->second.unstakeHeight = height;
        return true;
    }

    bool ReleaseStake(const std::string& minerAddress) {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        if (it == mapStakes.end()) return false;
        it->second.stakeStatus = OPOI_STAKE_RELEASED;
        return true;
    }

    bool SlashStake(const std::string& minerAddress) {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        if (it == mapStakes.end()) return false;
        it->second.stakeStatus = OPOI_STAKE_SLASHED;
        return true;
    }

    std::vector<OPoIStake> ListStakes() const {
        LOCK(cs);
        std::vector<OPoIStake> result;
        result.reserve(mapStakes.size());
        for (const auto& kv : mapStakes) result.push_back(kv.second);
        return result;
    }

    size_t StakeCount() const { LOCK(cs); return mapStakes.size(); }

    // ── Phase 3: challenges ───────────────────────────────────────────────────

    bool AddChallenge(const OPoIChallenge& ch) {
        LOCK(cs); mapChallenges[ch.requestId] = ch; return true;
    }

    bool GetChallenge(const std::string& requestId, OPoIChallenge& out) const {
        LOCK(cs);
        auto it = mapChallenges.find(requestId);
        if (it == mapChallenges.end()) return false;
        out = it->second; return true;
    }

    std::vector<OPoIChallenge> ListChallenges(int8_t statusFilter = -1) const {
        LOCK(cs);
        std::vector<OPoIChallenge> result;
        for (const auto& kv : mapChallenges)
            if (statusFilter < 0 || kv.second.challengeStatus == statusFilter)
                result.push_back(kv.second);
        return result;
    }

    size_t ChallengeCount() const { LOCK(cs); return mapChallenges.size(); }
};

// Global instance
extern OPoICache g_opoiCache;

// Called from main.cpp ConnectBlock / DisconnectBlock
bool ProcessOPoITransaction(const CTransaction& tx, uint32_t blockHeight,
                            bool fUndo = false,
                            const Consensus::Params* pparams = nullptr);

// Called from init.cpp / rebuilopoidb RPC to rescan chain
void RebuildOPoICache();

// Called from CheckTransactionWithoutProofVerification
bool CheckOPoITransaction(const CTransaction& tx, CValidationState& state);

// Called from ConnectBlock after processing each block to slash expired challenges
void ProcessExpiredChallenges(uint32_t blockHeight, const Consensus::Params& params);

#endif // CSCOIN_OPOI_H
