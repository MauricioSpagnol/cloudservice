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
#include <algorithm>
#include "serialize.h"
#include "uint256.h"
#include "amount.h"
#include "pubkey.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "consensus/validation.h"
#include "consensus/params.h"
#include "opoi_model_manifest.h"
#include "opoi_shard.h"

// ── Status constants ──────────────────────────────────────────────────────────

static const int8_t OPOI_STATUS_PENDING    = 1;
static const int8_t OPOI_STATUS_FULFILLED  = 2;
static const int8_t OPOI_STATUS_EXPIRED    = 3;

static const int8_t OPOI_STAKE_ACTIVE      = 1;
static const int8_t OPOI_STAKE_UNSTAKING   = 2;
static const int8_t OPOI_STAKE_RELEASED    = 3;
static const int8_t OPOI_STAKE_SLASHED     = 4;
static const int8_t OPOI_STAKE_SUSPENDED   = 5; // F9-F: 3 canary strikes — re-stake required

static const int8_t OPOI_CHALLENGE_OPEN    = 1;
static const int8_t OPOI_CHALLENGE_SLASHED = 2;
static const int8_t OPOI_CHALLENGE_EXPIRED = 3;

// task_type values — OPOI_TASK_OPEN / OPOI_TASK_VERIFIABLE now defined in
// primitives/transaction.h (needed there by CTransaction's template serializer)

// F15-G: task_class values — orthogonal to task_type. INTERACTIVE requests
// bound how deep a model's dense pipeline may be (nOPoIMaxPipelineDepth);
// deeper models must be requested as BATCH (no tight latency expectation).
static const uint8_t OPOI_TASKCLASS_INTERACTIVE = 0;
static const uint8_t OPOI_TASKCLASS_BATCH       = 1;

// FOTON verification result values
static const uint8_t FOTON_VERIFY_PASS    = 0;
static const uint8_t FOTON_VERIFY_FAIL    = 1;
static const uint8_t FOTON_VERIFY_TIMEOUT = 2;

// Canary audit strike threshold before stake suspension (not slash)
static const uint8_t OPOI_MAX_CANARY_STRIKES = 3;

// Known model identifiers (must match POM roots in consensus/params.h)
static const char* OPOI_MODEL_GEMMA_3_4B     = "GEMMA_3_4B";
static const char* OPOI_MODEL_DOLPHIN_8B     = "DOLPHIN_8B";
static const char* OPOI_MODEL_QWEN3_32B      = "QWEN3_32B";
static const char* OPOI_MODEL_LLAMA_3_3_70B  = "LLAMA_3_3_70B";

// ── Phase 2: request / response records ──────────────────────────────────────

struct OPoIRequest {
    std::string requestId;
    std::string requester;
    std::string model;
    uint256     promptHash;
    uint32_t    maxTokens;
    CAmount     payment;
    CAmount     feePerToken;      // per-token fee component (total = payment + tokenCount * feePerToken)
    int8_t      taskType;         // OPOI_TASK_OPEN or OPOI_TASK_VERIFIABLE
    uint8_t     taskClass;        // F15-G: OPOI_TASKCLASS_INTERACTIVE or _BATCH
    uint32_t    promptTokenCount; // F11-A: estimated tokens in prompt (for fee validation)
    uint8_t     isCanary;         // F9-F: 1=auto-generated canary audit request
    uint256     testSuite;        // F14-B: SHA256 of test suite (VERIFIABLE only)
    uint32_t    blockHeight;
    uint32_t    sigTime;
    uint256     txHash;
    int8_t      status;
    // Commit-reveal response tracking (F10-B)
    std::map<std::string, std::string> responseCommits;  // minerAddr → commitHash (phase=COMMIT)
    std::map<std::string, std::string> responseReveals;  // minerAddr → responseHash (phase=REVEAL)

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(requester); READWRITE(model);
        READWRITE(promptHash); READWRITE(maxTokens); READWRITE(payment);
        READWRITE(feePerToken); READWRITE(taskType); READWRITE(taskClass);
        READWRITE(promptTokenCount); READWRITE(isCanary); READWRITE(testSuite);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(status);
    }

    void SetNull() {
        requestId.clear(); requester.clear(); model.clear();
        promptHash.SetNull(); maxTokens = 0; payment = 0; feePerToken = 0; taskType = 0; taskClass = 0;
        promptTokenCount = 0; isCanary = 0; testSuite.SetNull();
        blockHeight = 0; sigTime = 0; txHash.SetNull();
        status = OPOI_STATUS_PENDING;
        responseCommits.clear(); responseReveals.clear();
    }
    bool IsNull()       const { return requestId.empty(); }
    bool IsPending()    const { return status == OPOI_STATUS_PENDING; }
    bool IsExpired()    const { return status == OPOI_STATUS_EXPIRED; }
    bool IsVerifiable() const { return taskType == OPOI_TASK_VERIFIABLE; }
};

struct OPoIResponse {
    std::string requestId;
    std::string minerAddress;
    uint256     responseHash;
    uint256     commitment;     // model_fixed_forward(SHA256(reqHash||respHash)) — anti-equivocation
    uint32_t    tokenCount;     // Actual tokens generated (for fee-per-token calculation)
    uint8_t     responsePhase;  // F10-B: 0=COMMIT seen, 1=REVEAL seen
    std::string responseCommitHash; // F10-B: SHA256(responseText||nonce) from COMMIT phase
    uint32_t    commitHeight;   // F10-B: block height of COMMIT tx
    uint32_t    blockHeight;
    uint32_t    sigTime;
    uint256     txHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(minerAddress); READWRITE(responseHash);
        READWRITE(commitment); READWRITE(tokenCount);
        READWRITE(responsePhase); READWRITE(responseCommitHash); READWRITE(commitHeight);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
    }

    void SetNull() {
        requestId.clear(); minerAddress.clear(); responseHash.SetNull();
        commitment.SetNull(); tokenCount = 0;
        responsePhase = 0; responseCommitHash.clear(); commitHeight = 0;
        blockHeight = 0; sigTime = 0; txHash.SetNull();
    }
    bool IsNull()     const { return requestId.empty(); }
    bool IsRevealed() const { return responsePhase == 1; }
};

// ── Phase 3: stake / challenge records ───────────────────────────────────────

struct OPoIStake {
    std::string minerAddress;
    COutPoint   collateralIn;     // UTXO the miner has pledged
    CAmount     amount;           // pledged amount (at registration time)
    std::string modelId;          // F9-B: declared model e.g. "GEMMA_3_4B"
    uint8_t     tier;             // F9-B: 0/1/2/3
    uint256     pomRoot;          // F9-B: Merkle root of GGUF verified by PoM
    uint32_t    blockHeight;      // block where STAKE tx confirmed
    uint32_t    lastRenewalHeight;// F9-E: block of last stake renewal (0 = same as blockHeight)
    uint32_t    sigTime;
    uint256     txHash;
    int8_t      stakeStatus;      // ACTIVE / UNSTAKING / RELEASED / SLASHED / SUSPENDED
    uint32_t    unstakeHeight;    // block where UNSTAKE tx confirmed (0 if not unstaking)
    // F10-C: Reputation tracking
    uint32_t    responsesTotal;
    uint32_t    responsesChallenged;
    uint32_t    responsesSlashed;
    // F9-F: Canary audit tracking
    uint8_t     canaryStrikes;    // strikes from failed canary audits (3 = suspended)
    // F10-D: pubkey recovered from the STAKE tx signature — needed for VRF
    // eligibility verification (VRF needs the actual point, not just its hash).
    CPubKey     minerPubKey;
    // F15-E: which MoE expert IDs this miner declared hosting (empty = dense-only)
    std::vector<uint32_t> hostedExpertIds;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(minerAddress); READWRITE(collateralIn); READWRITE(amount);
        READWRITE(modelId); READWRITE(tier); READWRITE(pomRoot);
        READWRITE(blockHeight); READWRITE(lastRenewalHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(stakeStatus); READWRITE(unstakeHeight);
        READWRITE(responsesTotal); READWRITE(responsesChallenged); READWRITE(responsesSlashed);
        READWRITE(canaryStrikes); READWRITE(minerPubKey); READWRITE(hostedExpertIds);
    }

    bool HostsExpert(uint32_t expertId) const {
        return std::find(hostedExpertIds.begin(), hostedExpertIds.end(), expertId) != hostedExpertIds.end();
    }

    void SetNull() {
        minerAddress.clear(); collateralIn.SetNull(); amount = 0;
        modelId.clear(); tier = 0; pomRoot.SetNull(); hostedExpertIds.clear();
        blockHeight = 0; lastRenewalHeight = 0; sigTime = 0; txHash.SetNull();
        stakeStatus = OPOI_STAKE_ACTIVE; unstakeHeight = 0;
        responsesTotal = 0; responsesChallenged = 0; responsesSlashed = 0;
        canaryStrikes = 0; minerPubKey = CPubKey();
    }
    bool IsNull()      const { return minerAddress.empty(); }
    bool IsActive()    const { return stakeStatus == OPOI_STAKE_ACTIVE; }
    bool IsUnstaking() const { return stakeStatus == OPOI_STAKE_UNSTAKING; }
    bool IsSlashed()   const { return stakeStatus == OPOI_STAKE_SLASHED; }
    bool IsSuspended() const { return stakeStatus == OPOI_STAKE_SUSPENDED; }

    // F10-C: Compute reputation score 0-100
    int ReputationScore() const {
        if (responsesTotal == 0) return 100;
        int score = 100;
        if (responsesSlashed    > 0) score -= (int)(responsesSlashed    * 20);
        if (responsesChallenged > 0) score -= (int)(responsesChallenged * 5);
        if (canaryStrikes       > 0) score -= (int)(canaryStrikes * 10);
        return score < 0 ? 0 : score;
    }
};

struct OPoIChallenge {
    std::string requestId;           // which RESPONSE is disputed
    std::string challengerAddress;
    uint256     claimedResponseHash; // what challenger claims was the correct response hash
    COutPoint   challengerCollateral;// F10-A: challenger's pledged UTXO (must stay locked until resolved)
    // F8-C: commit-reveal
    uint8_t     phase;               // 0=COMMIT received, 1=REVEAL received
    std::string commitHash;          // SHA256(proofData||nonce) stored from COMMIT
    uint32_t    commitHeight;        // block of COMMIT tx
    // Resolution
    uint32_t    blockHeight;         // block of initial CHALLENGE (COMMIT) tx
    uint32_t    sigTime;
    uint256     txHash;
    int8_t      challengeStatus;     // OPEN / SLASHED / EXPIRED

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(challengerAddress); READWRITE(claimedResponseHash);
        READWRITE(challengerCollateral);
        READWRITE(phase); READWRITE(commitHash); READWRITE(commitHeight);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(challengeStatus);
    }

    void SetNull() {
        requestId.clear(); challengerAddress.clear(); claimedResponseHash.SetNull();
        challengerCollateral.SetNull();
        phase = 0; commitHash.clear(); commitHeight = 0;
        blockHeight = 0; sigTime = 0; txHash.SetNull();
        challengeStatus = OPOI_CHALLENGE_OPEN;
    }
    bool IsNull()         const { return requestId.empty(); }
    bool IsOpen()         const { return challengeStatus == OPOI_CHALLENGE_OPEN; }
    bool IsCommitPhase()  const { return phase == 0; }
    bool IsRevealPhase()  const { return phase == 1; }
};

// ── F15-C: shard coordinator VRF self-claim ───────────────────────────────────
//
// A staked miner proves eligibility to coordinate a request's shard pipeline by
// submitting their own VRF proof (nobody else can compute it without the stake's
// private key). Multiple miners may end up eligible for the same request — that
// is by design (redundancy: nOPoICoordinatorThreshold is calibrated so ~3 self-
// select on average, matching the pattern already used for RESPONSE eligibility).
// NOTE: this only implements coordinator SELECTION. The relay/consensus part of
// the coordinator's job (distributing activations, publishing SHARD_COMMIT/REVEAL,
// misconduct proofs) depends on the shard execution protocol (F15-D/F15-H), which
// does not exist yet — a coordinator claim today is a verifiable on-chain fact,
// not yet an active role with real duties.
struct ShardCoordinatorClaim {
    std::string requestId;
    std::string minerAddress;
    uint32_t    blockHeight;
    uint256     txHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(minerAddress); READWRITE(blockHeight); READWRITE(txHash);
    }
};

// ── F15-D: shard boundary result submission ───────────────────────────────────
//
// A VRF-selected miner publishes the output hash it produced for one shard of
// a request's Model Execution Graph (F15-B). Once nOPoIShardMinSubmissions (R)
// independent miners have submitted for the same shard, the majority hash is
// the resolved boundary output; submitters whose hash disagrees are flagged as
// divergent (TIPO B by default — no fraud proof, no slash, just no visibility
// into whether it was hardware or malice; see F15-F for the challenge path,
// not implemented yet).
struct ShardResultSubmission {
    std::string minerAddress;
    uint256     boundaryOutputHash;
    uint256     routerLogitsHash;   // null if this shard isn't a MoE router boundary
    uint32_t    blockHeight;
    uint256     txHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(minerAddress); READWRITE(boundaryOutputHash); READWRITE(routerLogitsHash);
        READWRITE(blockHeight); READWRITE(txHash);
    }
};

// ── F14-C: FOTON verification record ─────────────────────────────────────────

static const int8_t OPOI_FOTON_STATUS_PENDING  = 0;
static const int8_t OPOI_FOTON_STATUS_COMPLETE = 1;
static const int8_t OPOI_FOTON_STATUS_SLASHED  = 2; // FOTON gave wrong answer vs majority

struct FotonVerification {
    std::string requestId;
    std::string fotonAddress;
    uint8_t     result;          // FOTON_VERIFY_PASS / FAIL / TIMEOUT
    COutPoint   fotonCollateral; // FOTON's pledged UTXO (locked during verification)
    uint32_t    blockHeight;
    uint256     txHash;
    int8_t      status;          // PENDING / COMPLETE / SLASHED

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(fotonAddress); READWRITE(result);
        READWRITE(fotonCollateral); READWRITE(blockHeight); READWRITE(txHash);
        READWRITE(status);
    }

    void SetNull() {
        requestId.clear(); fotonAddress.clear(); result = FOTON_VERIFY_PASS;
        fotonCollateral.SetNull(); blockHeight = 0; txHash.SetNull();
        status = OPOI_FOTON_STATUS_PENDING;
    }
    bool IsNull() const { return requestId.empty(); }
};

// ── Thread-safe cache ─────────────────────────────────────────────────────────

class OPoICache {
public:
    mutable CCriticalSection cs;

    // Phase 2
    std::map<std::string, OPoIRequest>  mapRequests;    // requestId → OPoIRequest
    std::map<std::string, OPoIResponse> mapResponses;   // requestId → OPoIResponse (REVEAL only)
    // Response commit-reveal pending (F10-B): requestId+minerAddr → commitHash
    std::map<std::string, std::string>  mapResponseCommits; // "reqId:minerAddr" → commitHash

    // Phase 3
    std::map<std::string, OPoIStake>     mapStakes;     // minerAddress → OPoIStake
    std::map<std::string, OPoIChallenge> mapChallenges; // requestId → OPoIChallenge

    // Phase 4: locked collateral UTXOs (miner cannot spend while staked or slashed)
    std::map<COutPoint, std::string> mapLockedUTXOs;    // collateral → ownerAddress

    // F14-C: FOTON verification results
    // Key = requestId, value = all FotonVerification records for that request
    std::map<std::string, std::vector<FotonVerification>> mapFotonVerifications;

    // F15-A: Model Manifests (dense/MoE/hybrid) — modelId → manifest
    std::map<std::string, ModelManifest> mapModelManifests;
    // F15-A2: votes cast per model — modelId → voterAddress → record
    std::map<std::string, std::map<std::string, ModelVoteRecord>> mapModelVotes;

    // F15-C: shard coordinator self-claims — requestId → list of accepted claims
    std::map<std::string, std::vector<ShardCoordinatorClaim>> mapCoordinatorClaims;

    // F15-D: shard boundary results — "requestId:shardIndex" → submissions
    std::map<std::string, std::vector<ShardResultSubmission>> mapShardResults;

    // F12-A: Treasury stats (accumulated totals, reset on -reindex)
    CAmount treasurySlashTotal  = 0;
    CAmount treasuryExpiryTotal = 0;
    CAmount treasuryFotonTotal  = 0;

    OPoICache() = default;

    void SetNull() {
        LOCK(cs);
        mapRequests.clear(); mapResponses.clear(); mapResponseCommits.clear();
        mapStakes.clear(); mapChallenges.clear();
        mapLockedUTXOs.clear(); mapFotonVerifications.clear();
        mapModelManifests.clear(); mapModelVotes.clear();
        mapCoordinatorClaims.clear(); mapShardResults.clear();
        treasurySlashTotal = 0; treasuryExpiryTotal = 0; treasuryFotonTotal = 0;
    }

    // ── F15-D: shard boundary results ────────────────────────────────────────

    static std::string ShardKey(const std::string& requestId, uint32_t shardIndex) {
        return requestId + ":" + std::to_string(shardIndex);
    }

    bool AddShardResult(const std::string& requestId, uint32_t shardIndex,
                        const ShardResultSubmission& sub) {
        LOCK(cs);
        auto& subs = mapShardResults[ShardKey(requestId, shardIndex)];
        for (const auto& existing : subs)
            if (existing.minerAddress == sub.minerAddress) return true; // one submission per miner
        subs.push_back(sub);
        return true;
    }

    std::vector<ShardResultSubmission> ListShardResults(const std::string& requestId, uint32_t shardIndex) const {
        LOCK(cs);
        auto it = mapShardResults.find(ShardKey(requestId, shardIndex));
        if (it == mapShardResults.end()) return {};
        return it->second;
    }

    // Returns true and fills majorityHash if >= minSubmissions are in and a
    // strict majority agree. divergent receives the addresses that disagreed.
    bool GetShardMajority(const std::string& requestId, uint32_t shardIndex, int minSubmissions,
                         uint256& majorityHash, std::vector<std::string>& divergent) const {
        LOCK(cs);
        auto it = mapShardResults.find(ShardKey(requestId, shardIndex));
        if (it == mapShardResults.end() || (int)it->second.size() < minSubmissions) return false;

        std::map<uint256, int> counts;
        for (const auto& s : it->second) counts[s.boundaryOutputHash]++;
        uint256 best; int bestCount = 0;
        for (const auto& kv : counts)
            if (kv.second > bestCount) { best = kv.first; bestCount = kv.second; }
        if (bestCount * 2 <= (int)it->second.size()) return false; // no strict majority yet

        majorityHash = best;
        divergent.clear();
        for (const auto& s : it->second)
            if (s.boundaryOutputHash != best) divergent.push_back(s.minerAddress);
        return true;
    }

    // ── F15-C: coordinator claims ────────────────────────────────────────────

    bool AddCoordinatorClaim(const ShardCoordinatorClaim& c) {
        LOCK(cs);
        // A miner only needs to claim once per request — ignore duplicates.
        auto& claims = mapCoordinatorClaims[c.requestId];
        for (const auto& existing : claims)
            if (existing.minerAddress == c.minerAddress) return true;
        claims.push_back(c);
        return true;
    }

    std::vector<ShardCoordinatorClaim> ListCoordinatorClaims(const std::string& requestId) const {
        LOCK(cs);
        auto it = mapCoordinatorClaims.find(requestId);
        if (it == mapCoordinatorClaims.end()) return {};
        return it->second;
    }

    bool IsClaimedCoordinator(const std::string& requestId, const std::string& minerAddress) const {
        LOCK(cs);
        auto it = mapCoordinatorClaims.find(requestId);
        if (it == mapCoordinatorClaims.end()) return false;
        for (const auto& c : it->second)
            if (c.minerAddress == minerAddress) return true;
        return false;
    }

    // ── F15-A: Model Manifests ────────────────────────────────────────────────

    // Sum of `amount` across all stakes with status ACTIVE — the voting base.
    CAmount TotalActiveStake() const {
        LOCK(cs);
        CAmount total = 0;
        for (const auto& kv : mapStakes)
            if (kv.second.IsActive()) total += kv.second.amount;
        return total;
    }

    // F15-F: how many ACTIVE stakers could possibly ever submit a result for a
    // given shard — used to detect "this expert will never reach full
    // redundancy" and degrade gracefully instead of waiting forever.
    int CountActiveStakers() const {
        LOCK(cs);
        int n = 0;
        for (const auto& kv : mapStakes) if (kv.second.IsActive()) n++;
        return n;
    }

    int CountActiveExpertHosts(uint32_t expertId) const {
        LOCK(cs);
        int n = 0;
        for (const auto& kv : mapStakes)
            if (kv.second.IsActive() && kv.second.HostsExpert(expertId)) n++;
        return n;
    }

    bool AddModelManifest(const ModelManifest& m) {
        LOCK(cs); mapModelManifests[m.modelId] = m; return true;
    }

    bool GetModelManifest(const std::string& modelId, ModelManifest& out) const {
        LOCK(cs);
        auto it = mapModelManifests.find(modelId);
        if (it == mapModelManifests.end()) return false;
        out = it->second; return true;
    }

    std::vector<ModelManifest> ListModelManifests(int8_t statusFilter = -1) const {
        LOCK(cs);
        std::vector<ModelManifest> result;
        for (const auto& kv : mapModelManifests)
            if (statusFilter < 0 || kv.second.status == statusFilter)
                result.push_back(kv.second);
        return result;
    }

    // Records/overwrites a voter's vote for modelId (re-voting is allowed).
    bool AddModelVote(const std::string& modelId, const ModelVoteRecord& rec) {
        LOCK(cs);
        if (!mapModelManifests.count(modelId)) return false;
        mapModelVotes[modelId][rec.voterAddress] = rec;
        return true;
    }

    // Weighted tally: returns {yesWeight, noWeight} across all recorded votes.
    void TallyModelVotes(const std::string& modelId, CAmount& yesWeight, CAmount& noWeight) const {
        LOCK(cs);
        yesWeight = 0; noWeight = 0;
        auto it = mapModelVotes.find(modelId);
        if (it == mapModelVotes.end()) return;
        for (const auto& kv : it->second) {
            if (kv.second.approve) yesWeight += kv.second.weight;
            else                   noWeight  += kv.second.weight;
        }
    }

    // Manifests with status VOTING whose voting window has just closed at blockHeight.
    std::vector<ModelManifest> ListManifestsDueForTally(uint32_t blockHeight) const {
        LOCK(cs);
        std::vector<ModelManifest> result;
        for (const auto& kv : mapModelManifests)
            if (kv.second.IsVoting() && kv.second.voteWindowEndHeight <= blockHeight)
                result.push_back(kv.second);
        return result;
    }

    bool SetModelManifestStatus(const std::string& modelId, int8_t status, uint32_t activationHeight = 0) {
        LOCK(cs);
        auto it = mapModelManifests.find(modelId);
        if (it == mapModelManifests.end()) return false;
        it->second.status = status;
        if (activationHeight > 0) it->second.activationHeight = activationHeight;
        return true;
    }

    // ── Phase 4: collateral locking ──────────────────────────────────────────

    void LockUTXO(const COutPoint& out, const std::string& minerAddress) {
        LOCK(cs);
        mapLockedUTXOs[out] = minerAddress;
    }

    void UnlockUTXO(const COutPoint& out) {
        LOCK(cs);
        mapLockedUTXOs.erase(out);
    }

    bool IsLockedUTXO(const COutPoint& out) const {
        LOCK(cs);
        return mapLockedUTXOs.count(out) > 0;
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────────

    bool AddRequest(const OPoIRequest& req) {
        LOCK(cs); mapRequests[req.requestId] = req; return true;
    }

    bool AddResponse(const OPoIResponse& resp) {
        LOCK(cs);
        mapResponses[resp.requestId] = resp;
        auto it = mapRequests.find(resp.requestId);
        if (it != mapRequests.end() && resp.IsRevealed())
            it->second.status = OPOI_STATUS_FULFILLED;
        // Remove pending commit when reveal is stored
        if (resp.IsRevealed()) {
            std::string key = resp.requestId + ":" + resp.minerAddress;
            mapResponseCommits.erase(key);
        }
        return true;
    }

    // F10-B: Store a RESPONSE_COMMIT (phase=0) before the REVEAL arrives
    bool AddResponseCommit(const std::string& requestId,
                           const std::string& minerAddress,
                           const std::string& commitHash,
                           uint32_t blockHeight) {
        LOCK(cs);
        std::string key = requestId + ":" + minerAddress;
        mapResponseCommits[key] = commitHash;
        // Track in request
        auto it = mapRequests.find(requestId);
        if (it != mapRequests.end())
            it->second.responseCommits[minerAddress] = commitHash;
        return true;
    }

    bool GetResponseCommit(const std::string& requestId,
                           const std::string& minerAddress,
                           std::string& outCommitHash) const {
        LOCK(cs);
        std::string key = requestId + ":" + minerAddress;
        auto it = mapResponseCommits.find(key);
        if (it == mapResponseCommits.end()) return false;
        outCommitHash = it->second;
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

    bool IsEligibleToRespond(const std::string& minerAddress) const {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        // Must be ACTIVE and not suspended (canary strikes < max)
        return it != mapStakes.end() && it->second.IsActive() &&
               it->second.canaryStrikes < OPOI_MAX_CANARY_STRIKES;
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

    // ── F14-C: FOTON verification ─────────────────────────────────────────────

    bool AddFotonVerification(const FotonVerification& fv) {
        LOCK(cs);
        mapFotonVerifications[fv.requestId].push_back(fv);
        // Lock FOTON's collateral
        if (!fv.fotonCollateral.IsNull())
            mapLockedUTXOs[fv.fotonCollateral] = fv.fotonAddress;
        return true;
    }

    // Returns all FotonVerification records for a request
    std::vector<FotonVerification> GetFotonVerifications(const std::string& requestId) const {
        LOCK(cs);
        auto it = mapFotonVerifications.find(requestId);
        if (it == mapFotonVerifications.end()) return {};
        return it->second;
    }

    // Returns the majority FOTON result for a request, or -1 if no quorum yet
    // Returns FOTON_VERIFY_PASS/FAIL/TIMEOUT or -1
    int GetFotonMajorityResult(const std::string& requestId, int minVerifiers) const {
        LOCK(cs);
        auto it = mapFotonVerifications.find(requestId);
        if (it == mapFotonVerifications.end()) return -1;
        const auto& verifs = it->second;
        int revealed = 0;
        int pass = 0, fail = 0, timeout = 0;
        for (const auto& fv : verifs) {
            if (fv.result == FOTON_VERIFY_PASS)    { pass++;    revealed++; }
            else if (fv.result == FOTON_VERIFY_FAIL) { fail++; revealed++; }
            else if (fv.result == FOTON_VERIFY_TIMEOUT) { timeout++; revealed++; }
        }
        if (revealed < minVerifiers) return -1; // no quorum yet
        if (pass    > (revealed / 2)) return FOTON_VERIFY_PASS;
        if (fail    > (revealed / 2)) return FOTON_VERIFY_FAIL;
        if (timeout > (revealed / 2)) return FOTON_VERIFY_TIMEOUT;
        return -1; // tie (shouldn't happen with odd minVerifiers)
    }

    std::vector<std::pair<std::string, std::vector<FotonVerification>>> ListAllFotonVerifications() const {
        LOCK(cs);
        std::vector<std::pair<std::string, std::vector<FotonVerification>>> result;
        for (const auto& kv : mapFotonVerifications)
            result.push_back(kv);
        return result;
    }

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

// Called from ConnectBlock to expire PENDING requests that received no RESPONSE
// within nOPoIRequestExpiryBlocks. After expiry, RESPONSE txs for that requestId
// are rejected by CheckOPoITransaction.
void ProcessExpiredRequests(uint32_t blockHeight, const Consensus::Params& params);

// Called from ConnectBlock to verify OPoI miner payments in the coinbase tx.
// For each RESPONSE tx in the block, verifies the coinbase has an output paying
// the miner the agreed amount, within the nOPoISubsidyPct budget for this block.
bool CheckOPoIPayments(const std::vector<CTransaction>& vtx,
                       int nHeight,
                       const Consensus::Params& params,
                       CValidationState& state);

// ── Phase 5: challenger rewards ───────────────────────────────────────────────

struct OPoIChallengerReward {
    std::string challengerAddress;
    CAmount     rewardAmount;
};

// Returns rewards owed for challenges that expire at blockHeight (i.e., will be
// slashed when this block is connected). Called from CreateNewBlock and
// CheckOPoIChallengerRewards so both use identical logic.
std::vector<OPoIChallengerReward> GetChallengerRewardsAtHeight(
    uint32_t blockHeight, const Consensus::Params& params);

// Called from ConnectBlock to verify challenger reward outputs in the coinbase.
bool CheckOPoIChallengerRewards(const std::vector<CTransaction>& vtx,
                                uint32_t blockHeight,
                                const Consensus::Params& params,
                                CValidationState& state);

// ── F15-A2: model governance ──────────────────────────────────────────────────

// Called from ConnectBlock: tallies any ModelManifest whose voting window closed
// at blockHeight. Approved manifests get activationHeight = blockHeight +
// nOPoIModelActivationDelayBlocks; otherwise the manifest is REJECTED.
void ProcessModelVotingWindows(uint32_t blockHeight, const Consensus::Params& params);

#endif // CSCOIN_OPOI_H
