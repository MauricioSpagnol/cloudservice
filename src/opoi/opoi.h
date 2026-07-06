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
#include <set>
#include <vector>
#include <algorithm>
#include "serialize.h"
#include "hash.h"
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

static const int8_t OPOI_CHALLENGE_OPEN             = 1; // COMMIT received, awaiting REVEAL
static const int8_t OPOI_CHALLENGE_SLASHED          = 2; // proven fraud (VERIFIABLE + Auditor FAIL) — miner slashed
static const int8_t OPOI_CHALLENGE_EXPIRED           = 3; // no REVEAL in time, or reveal didn't hold up — challenger slashed
static const int8_t OPOI_CHALLENGE_REVEALED_PENDING  = 4; // valid REVEAL, VERIFIABLE task, waiting on Auditor majority
static const int8_t OPOI_CHALLENGE_RESOLVED_NO_ORACLE= 5; // valid REVEAL, OPEN task — no fraud oracle exists (F10-C), no slash either side

// task_type values — OPOI_TASK_OPEN / OPOI_TASK_VERIFIABLE now defined in
// primitives/transaction.h (needed there by CTransaction's template serializer)

// F15-G: task_class values — orthogonal to task_type. INTERACTIVE requests
// bound how deep a model's dense pipeline may be (nOPoIMaxPipelineDepth);
// deeper models must be requested as BATCH (no tight latency expectation).
static const uint8_t OPOI_TASKCLASS_INTERACTIVE = 0;
static const uint8_t OPOI_TASKCLASS_BATCH       = 1;

// Auditor verification result values
static const uint8_t AUDITOR_VERIFY_PASS    = 0;
static const uint8_t AUDITOR_VERIFY_FAIL    = 1;
static const uint8_t AUDITOR_VERIFY_TIMEOUT = 2;

// Canary audit strike threshold before stake suspension (not slash)
static const uint8_t OPOI_MAX_CANARY_STRIKES = 3;

// F9-F: single pinned test suite for canary audits, the same across every
// network — an Auditor grades it off-chain either way (same as any other
// VERIFIABLE task, F14-C), so there's no reason mainnet/testnet/regtest
// would ever need a DIFFERENT one. A REQUEST claiming opoiIsCanary must use
// exactly this hash (see CheckOPoITransaction's REQUEST case) — otherwise
// "canary" would just be a free label with no actual guarantee that it
// tests the one thing the network agreed to test.
inline uint256 GetOPoICanaryTestSuiteHash() {
    static const std::string label = "OPoI-Canary-TestSuite-v1";
    return Hash(label.begin(), label.end());
}

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
    // F10-B: flips true once nOPoIResponseCommitWindowBlocks have passed since
    // blockHeight (see ProcessResponseCommitWindows). No COMMIT is valid once
    // this is true; no REVEAL is valid while it's still false — this closes
    // the commit phase for every miner at the same height, which is what
    // actually prevents copying (no REVEAL can be public before this flips).
    // In-class initializer (not just SetNull()) so a plain `OPoIRequest req;`
    // followed by manual field assignment (as ProcessOPoITransaction's REQUEST
    // apply does, never calling SetNull()) can't leave this as stack garbage —
    // the exact bug class already found once for OPoIStake's reputation fields.
    bool        commitWindowClosed = false;

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
        commitWindowClosed = false;
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
    // Bug fix (2026-07-05): txid of the UNSTAKE tx that put this staker into
    // UNSTAKING, so CheckOPoITransaction can tell a harmless late P2P
    // redelivery of that same tx (IsActiveStaker() now correctly false, since
    // this very tx is what flipped it) from a genuinely different UNSTAKE
    // racing in — same pattern as mapLockingTxHash above, for a check that
    // isn't keyed by a locked UTXO.
    uint256     unstakeTxHash;
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
    // F15-H: "host:port" this miner's cs-miner HTTP API is reachable at (empty
    // = not relay-reachable, e.g. behind NAT).
    std::string endpoint;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(minerAddress); READWRITE(collateralIn); READWRITE(amount);
        READWRITE(modelId); READWRITE(tier); READWRITE(pomRoot);
        READWRITE(blockHeight); READWRITE(lastRenewalHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(stakeStatus); READWRITE(unstakeHeight); READWRITE(unstakeTxHash);
        READWRITE(responsesTotal); READWRITE(responsesChallenged); READWRITE(responsesSlashed);
        READWRITE(canaryStrikes); READWRITE(minerPubKey); READWRITE(hostedExpertIds);
        READWRITE(endpoint);
    }

    bool HostsExpert(uint32_t expertId) const {
        return std::find(hostedExpertIds.begin(), hostedExpertIds.end(), expertId) != hostedExpertIds.end();
    }

    void SetNull() {
        minerAddress.clear(); collateralIn.SetNull(); amount = 0;
        modelId.clear(); tier = 0; pomRoot.SetNull(); hostedExpertIds.clear(); endpoint.clear();
        blockHeight = 0; lastRenewalHeight = 0; sigTime = 0; txHash.SetNull();
        stakeStatus = OPOI_STAKE_ACTIVE; unstakeHeight = 0; unstakeTxHash.SetNull();
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
    std::vector<uint8_t> fraudProof; // F8-C: challenger's revealed evidence (empty until REVEAL)
    COutPoint   challengerCollateral;// F10-A: challenger's pledged UTXO (must stay locked until resolved)
    // F8-C: commit-reveal
    uint8_t     phase;               // 0=COMMIT received, 1=REVEAL received
    std::string commitHash;          // SHA256(proofData||nonce) stored from COMMIT
    uint32_t    commitHeight;        // block of COMMIT tx
    // Resolution
    uint32_t    blockHeight;         // block of initial CHALLENGE (COMMIT) tx
    uint32_t    sigTime;
    uint256     txHash;              // the COMMIT tx's hash (never updated by REVEAL)
    int8_t      challengeStatus;     // OPEN / SLASHED / EXPIRED / REVEALED_PENDING / RESOLVED_NO_ORACLE
    // Bug fix (2026-07-05): the REVEAL tx's own hash, separate from txHash
    // above (which stays the COMMIT's forever) — needed to recognize a
    // harmless late P2P redelivery of this exact already-applied REVEAL.
    // Once REVEAL applies, challengeStatus always leaves OPEN (to SLASHED/
    // EXPIRED/REVEALED_PENDING/RESOLVED_NO_ORACLE), so without this a
    // redelivery would always hit "no open commit" even though it already
    // succeeded once.
    uint256     revealTxHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(challengerAddress); READWRITE(fraudProof);
        READWRITE(challengerCollateral);
        READWRITE(phase); READWRITE(commitHash); READWRITE(commitHeight);
        READWRITE(blockHeight); READWRITE(sigTime); READWRITE(txHash);
        READWRITE(challengeStatus); READWRITE(revealTxHash);
    }

    void SetNull() {
        requestId.clear(); challengerAddress.clear(); fraudProof.clear();
        challengerCollateral.SetNull();
        phase = 0; commitHash.clear(); commitHeight = 0;
        blockHeight = 0; sigTime = 0; txHash.SetNull();
        challengeStatus = OPOI_CHALLENGE_OPEN;
        revealTxHash.SetNull();
    }
    bool IsNull()               const { return requestId.empty(); }
    bool IsOpen()               const { return challengeStatus == OPOI_CHALLENGE_OPEN; }
    bool IsPendingResolution()  const { return challengeStatus == OPOI_CHALLENGE_REVEALED_PENDING; }
    bool IsCommitPhase()        const { return phase == 0; }
    bool IsRevealPhase()        const { return phase == 1; }
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
    uint32_t    tokenCount;         // F16: tokens generated by this shard's compute (fee-per-token)
    uint32_t    blockHeight;
    uint256     txHash;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(minerAddress); READWRITE(boundaryOutputHash); READWRITE(routerLogitsHash);
        READWRITE(tokenCount); READWRITE(blockHeight); READWRITE(txHash);
    }
};

// Pure majority computation over an arbitrary set of submissions — no cache
// access, so it can be run both against the persisted cache (OPoICache::
// GetShardMajority) and against a "cache + this block's own not-yet-applied
// SHARD_RESULT txs" combined view (F16 shard payments — see
// GetShardPaymentsForBlock in opoi.cpp), which need to resolve a shard using
// state that isn't in the cache yet.
//
// F16: the grouping key is (boundaryOutputHash, tokenCount), not just the
// hash — tokenCount directly drives the per-token fee, and self-declared
// tokenCount is otherwise unverifiable (same trust model RESPONSE already
// has). Folding it into the majority key means a miner who reports the
// right hash but an inflated tokenCount simply lands in its own bucket and
// needs OTHER independent miners to agree on that exact (hash, count) pair
// to get paid — same "no fraud proof, no reward" property divergent hashes
// already had, now covering token-count inflation too.
inline bool ComputeShardMajority(const std::vector<ShardResultSubmission>& subs, int minSubmissions,
                                 uint256& majorityHash, uint32_t& majorityTokenCount,
                                 std::vector<std::string>& agreeing,
                                 std::vector<std::string>& divergent) {
    if ((int)subs.size() < minSubmissions) return false;

    std::map<std::pair<uint256, uint32_t>, int> counts;
    for (const auto& s : subs) counts[{s.boundaryOutputHash, s.tokenCount}]++;
    std::pair<uint256, uint32_t> best; int bestCount = 0;
    for (const auto& kv : counts)
        if (kv.second > bestCount) { best = kv.first; bestCount = kv.second; }
    if (bestCount * 2 <= (int)subs.size()) return false; // no strict majority yet

    majorityHash       = best.first;
    majorityTokenCount = best.second;
    agreeing.clear();
    divergent.clear();
    for (const auto& s : subs) {
        if (s.boundaryOutputHash == best.first && s.tokenCount == best.second)
            agreeing.push_back(s.minerAddress);
        else
            divergent.push_back(s.minerAddress);
    }
    return true;
}

// F16: one payment owed to a miner for having contributed the (resolved)
// majority result of a shard. See GetShardPaymentsForBlock.
struct OPoIShardPayment {
    std::string requestId;
    uint32_t    shardIndex;
    std::string minerAddress;
    CAmount     amount;
};

// F14-C: one payment owed to a miner for a VERIFIABLE request's RESPONSE that
// just resolved an Auditor PASS majority. See GetVerifiablePaymentsForBlock.
struct OPoIResponsePayment {
    std::string requestId;
    std::string minerAddress;
    CAmount     amount;
};

// ── F14-C: Auditor verification record ───────────────────────────────────────

static const int8_t OPOI_AUDITOR_STATUS_PENDING  = 0;
static const int8_t OPOI_AUDITOR_STATUS_COMPLETE = 1;
static const int8_t OPOI_AUDITOR_STATUS_SLASHED  = 2; // Auditor gave wrong answer vs majority

struct AuditorVerification {
    std::string requestId;
    std::string auditorAddress;
    uint8_t     result;          // AUDITOR_VERIFY_PASS / FAIL / TIMEOUT
    COutPoint   auditorCollateral; // Auditor's pledged UTXO (locked during verification)
    uint32_t    blockHeight;
    uint256     txHash;
    int8_t      status;          // PENDING / COMPLETE / SLASHED

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(requestId); READWRITE(auditorAddress); READWRITE(result);
        READWRITE(auditorCollateral); READWRITE(blockHeight); READWRITE(txHash);
        READWRITE(status);
    }

    void SetNull() {
        requestId.clear(); auditorAddress.clear(); result = AUDITOR_VERIFY_PASS;
        auditorCollateral.SetNull(); blockHeight = 0; txHash.SetNull();
        status = OPOI_AUDITOR_STATUS_PENDING;
    }
    bool IsNull() const { return requestId.empty(); }
};

// ── OPoI relay (P2P delivery for NAT'd/CGNAT'd miners) ────────────────────────
// Deliberately NOT consensus/blockchain data: never touched by
// ProcessOPoITransaction/undo, never replayed by RebuildOPoICache. It's
// best-effort P2P-layer plumbing so a miner that never declared a reachable
// OPoIStake.endpoint can still receive a prompt in real time — instead of the
// requester POSTing straight to the miner's HTTP API, they submit this to
// THEIR OWN node (submitopoipendingdelivery RPC), which floods it exactly
// like the existing alert system (see alert.h/alert.cpp) to every peer; the
// destination miner's own cs-miner polls ITS OWN node's copy
// (getopoipendingdeliveries RPC) — no addressed routing to a specific "home
// node" needed, since flooding means every node ends up with a copy anyway.
static const uint8_t OPOI_DELIVERY_PROMPT              = 0;
static const uint8_t OPOI_DELIVERY_SHARD_ASSIGN        = 1; // F15-H fast-follow (2026-07-05): coordinator → miner
static const uint8_t OPOI_DELIVERY_SHARD_RESULT        = 2; // F15-H fast-follow (2026-07-05): miner → coordinator reply
// F15-H fast-follow, model distribution (2026-07-05): lets a miner fetch a
// model_id's GGUF/tokenizer from a staker who hosts it but never declared a
// reachable OPoIStake.endpoint (today, model_fetch.rs's direct-HTTP fetch
// simply never selects such a staker as a source — this is the P2P fallback).
// The file is split client-side into <=64KB-raw chunks (see model_fetch.rs's
// MODEL_CHUNK_SIZE) since a whole GGUF would blow past OPOI_DELIVERY_MAX_PAYLOAD_HEX
// by orders of magnitude; REQUEST asks a hosting peer for one artifact of one
// model_id, and it replies with one CHUNK delivery per piece (no further
// request/ack per chunk — see cs-miner's model_chunk_registry.rs for
// reassembly). Known, accepted cost of reusing the flood-relay mechanism
// as-is rather than building a new point-to-point protocol: every chunk is
// still flooded to the ENTIRE P2P mesh (same as PROMPT/SHARD_ASSIGN/
// SHARD_RESULT), so total network-wide bandwidth/storage for one transfer is
// file_size × node_count. Acceptable for the network sizes this project runs
// today; a true unicast/point-to-point relay would be a larger follow-up.
static const uint8_t OPOI_DELIVERY_MODEL_CHUNK_REQUEST = 3;
static const uint8_t OPOI_DELIVERY_MODEL_CHUNK         = 4;
static const size_t  OPOI_DELIVERY_MAX_PAYLOAD_HEX = 131072; // 64KB of raw payload, hex-encoded

struct PendingDelivery {
    std::string requestId;
    uint8_t     kind;
    std::string payloadHex;
    uint32_t    sigTime;
    // F15-H fast-follow: who signed this (the consumer's "reply to" address
    // for SHARD_ASSIGN/SHARD_RESULT — see COPoIDataMsg comment below). Empty
    // for PROMPT, where the signer is always the REQUEST's own requester and
    // doesn't need to be carried separately.
    std::string senderAddress;

    void SetNull() {
        requestId.clear(); kind = OPOI_DELIVERY_PROMPT; payloadHex.clear(); sigTime = 0;
        senderAddress.clear();
    }
};

// The P2P wire message itself (and the RPC-submitted equivalent — both paths
// share this one struct and the same validate/store/relay function in
// opoi.cpp). Signed the same way every other OPoI signature is (VerifyOPoISig,
// signmessage-compatible) so validation reuses the exact machinery
// CheckOPoITransaction already relies on for RESPONSE/CHALLENGE signatures —
// no new trust primitive.
//
// F15-H fast-follow (2026-07-05): senderAddress identifies who is claiming to
// have signed this. For PROMPT, the expected signer is always the REQUEST's
// requester (senderAddress is redundant there, but still checked for
// consistency). For SHARD_ASSIGN (a coordinator relaying a shard assignment
// to a miner with no reachable endpoint) and SHARD_RESULT (that miner's reply
// carrying the computed tensor back), there is no single address derivable
// from the requestId alone — a request can have multiple accepted
// coordinators (F15-C, VRF-selected redundancy) and any ACTIVE staker could
// be the assigned miner — so the message must say who it claims to be, and
// ProcessOPoIDataMessage checks that claim against the right on-chain role
// (IsClaimedCoordinator / IsActiveStaker) before trusting the signature.
// MODEL_CHUNK_REQUEST/MODEL_CHUNK (model distribution fast-follow) are the
// same story — no single address derivable from requestId alone (any ACTIVE
// staker could be fetching or hosting) — both require IsActiveStaker.
struct COPoIDataMsg {
    std::string destStakeAddress;
    std::string requestId;
    uint8_t     kind;
    std::string senderAddress;
    std::string payloadHex;
    uint32_t    sigTime;
    std::vector<unsigned char> sig;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(destStakeAddress); READWRITE(requestId); READWRITE(kind);
        READWRITE(senderAddress); READWRITE(payloadHex); READWRITE(sigTime); READWRITE(sig);
    }

    uint256 GetHash() const { return SerializeHash(*this); }
};

// Validates a COPoIDataMsg — signer authorization depends on kind (see
// COPoIDataMsg comment above) — and, if valid, stores it into g_opoiCache.
// Shared by the P2P receive handler (main.cpp, "opoidata" command) and the
// submitopoipendingdelivery RPC — same validation either way, only the entry
// point differs. Returns false (with a short machine-readable reason)
// without storing anything on any failure; callers use the return value to
// decide whether to flood-relay
// onward (never relay something that failed validation).
bool ProcessOPoIDataMessage(const COPoIDataMsg& msg, std::string& reason);

// Pure majority computation over an arbitrary set of Auditor verifications —
// no cache access, so it can run both against the persisted cache
// (OPoICache::GetAuditorMajorityResult) and against a "cache + this block's
// own not-yet-applied AUDITOR_VERIFY txs" combined view (F14-C payments — see
// GetVerifiablePaymentsForBlock in opoi.cpp), mirroring ComputeShardMajority's
// role for shard payments exactly (same reason: CreateNewBlock and
// CheckOPoIPayments must agree using the pre-this-block cache, while
// ProcessVerifiableResponsePayments runs after the cache already has this
// block's votes applied — the same merge must produce the same answer either way).
inline int ComputeAuditorMajority(const std::vector<AuditorVerification>& verifs, int minVerifiers) {
    int revealed = 0, pass = 0, fail = 0, timeout = 0;
    for (const auto& fv : verifs) {
        if (fv.result == AUDITOR_VERIFY_PASS)         { pass++;    revealed++; }
        else if (fv.result == AUDITOR_VERIFY_FAIL)    { fail++;    revealed++; }
        else if (fv.result == AUDITOR_VERIFY_TIMEOUT) { timeout++; revealed++; }
    }
    if (revealed < minVerifiers) return -1; // no quorum yet
    if (pass    > (revealed / 2)) return AUDITOR_VERIFY_PASS;
    if (fail    > (revealed / 2)) return AUDITOR_VERIFY_FAIL;
    if (timeout > (revealed / 2)) return AUDITOR_VERIFY_TIMEOUT;
    return -1; // tie (shouldn't happen with odd minVerifiers)
}

// ── Thread-safe cache ─────────────────────────────────────────────────────────

class OPoICache {
public:
    mutable CCriticalSection cs;

    // Phase 2
    std::map<std::string, OPoIRequest>  mapRequests;    // requestId → OPoIRequest
    std::map<std::string, OPoIResponse> mapResponses;   // requestId → OPoIResponse (REVEAL only)
    // Response commit-reveal pending (F10-B): requestId+minerAddr → commitHash
    std::map<std::string, std::string>  mapResponseCommits; // "reqId:minerAddr" → commitHash
    // Bug fix (2026-07-05): which tx applied this COMMIT — same
    // harmless-redelivery purpose as mapLockingTxHash/ModelVoteRecord.txHash.
    // Kept as a separate companion map (rather than changing
    // mapResponseCommits's value type) since the commit hash string is
    // already used/displayed elsewhere unchanged.
    std::map<std::string, uint256>      mapResponseCommitTxHash; // "reqId:minerAddr" → committing txid

    // Phase 3
    std::map<std::string, OPoIStake>     mapStakes;     // minerAddress → OPoIStake
    std::map<std::string, OPoIChallenge> mapChallenges; // requestId → OPoIChallenge

    // Phase 4: locked collateral UTXOs (miner cannot spend while staked or slashed)
    std::map<COutPoint, std::string> mapLockedUTXOs;    // collateral → ownerAddress
    // Bug fix (2026-07-05): which tx actually locked this UTXO. Needed so
    // CheckOPoITransaction can tell "this exact STAKE/CHALLENGE-COMMIT/
    // AUDITOR_VERIFY tx is being redelivered late via normal P2P relay" (harmless —
    // AlreadyHave()'s usual dedup can never catch this, since these tx types are
    // required to have empty vin/vout and HaveCoins() is always false for them)
    // apart from "a genuinely different tx is racing to lock the same UTXO" (a real
    // conflict). Without this, both cases hit the same DoS(100) rejection, which
    // alone reaches the default ban threshold and disconnects/bans an honest peer
    // for nothing more than ordinary tx-relay timing.
    std::map<COutPoint, uint256>     mapLockingTxHash;   // collateral → locking txid

    // F14-C: Auditor verification results
    // Key = requestId, value = all AuditorVerification records for that request
    std::map<std::string, std::vector<AuditorVerification>> mapAuditorVerifications;

    // F15-A: Model Manifests (dense/MoE/hybrid) — modelId → manifest
    std::map<std::string, ModelManifest> mapModelManifests;
    // F15-A2: votes cast per model — modelId → voterAddress → record
    std::map<std::string, std::map<std::string, ModelVoteRecord>> mapModelVotes;

    // F15-C: shard coordinator self-claims — requestId → list of accepted claims
    std::map<std::string, std::vector<ShardCoordinatorClaim>> mapCoordinatorClaims;

    // F15-D: shard boundary results — "requestId:shardIndex" → submissions
    std::map<std::string, std::vector<ShardResultSubmission>> mapShardResults;

    // F16: shards whose majority has already been paid out (coinbase), keyed
    // by ShardKey(requestId, shardIndex) — prevents paying the same resolved
    // shard again in a later block.
    std::set<std::string> setPaidShards;

    // F14-C: requestIds whose Auditor verification has already been resolved
    // (majority reached, collateral released/slashed) — prevents re-resolving
    // (and re-unlocking already-unlocked collateral) on a later block.
    std::set<std::string> setResolvedAuditorVerifications;

    // F14-C: requestIds whose VERIFIABLE RESPONSE has already been paid —
    // see IsResponsePaid/MarkResponsePaid/UnmarkResponsePaid below.
    std::set<std::string> setPaidResponses;

    // F10-A: requestIds whose challenger reward (on a proven CHALLENGE) has
    // already been paid — see IsChallengerRewardPaid/MarkChallengerRewardPaid/
    // UnmarkChallengerRewardPaid below. A CHALLENGE can sit in SLASHED state
    // across many blocks after resolution, unlike the old bare-timeout design
    // where resolution and reward happened at the same height.
    std::set<std::string> setPaidChallengerRewards;

    // F12-A: Treasury stats (accumulated totals, reset on -reindex)
    CAmount treasurySlashTotal  = 0;
    CAmount treasuryExpiryTotal = 0;
    CAmount treasuryAuditorTotal  = 0;

    // OPoI relay: pending deliveries, keyed by destination stake address —
    // see PendingDelivery/COPoIDataMsg above. Not consensus state.
    std::map<std::string, std::vector<PendingDelivery>> mapPendingDeliveries;
    // Dedup for the flood-relay itself (by COPoIDataMsg hash) — mirrors
    // mapAlreadyAskedFor-style hash sets elsewhere, needed because a node's
    // own local storage above is keyed by dest address (many messages per
    // key), not by message hash.
    std::set<uint256> setKnownOPoIDataHashes;

    OPoICache() = default;

    void SetNull() {
        LOCK(cs);
        mapRequests.clear(); mapResponses.clear(); mapResponseCommits.clear();
        mapResponseCommitTxHash.clear();
        mapStakes.clear(); mapChallenges.clear();
        mapLockedUTXOs.clear(); mapAuditorVerifications.clear();
        mapModelManifests.clear(); mapModelVotes.clear();
        mapCoordinatorClaims.clear(); mapShardResults.clear();
        setPaidShards.clear(); setResolvedAuditorVerifications.clear();
        setPaidResponses.clear(); setPaidChallengerRewards.clear();
        mapPendingDeliveries.clear(); setKnownOPoIDataHashes.clear();
        treasurySlashTotal = 0; treasuryExpiryTotal = 0; treasuryAuditorTotal = 0;
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

    // Returns true and fills majorityHash/majorityTokenCount if >= minSubmissions
    // are in and a strict majority agree. agreeing/divergent receive the
    // addresses that matched/disagreed with the majority (hash, tokenCount).
    bool GetShardMajority(const std::string& requestId, uint32_t shardIndex, int minSubmissions,
                         uint256& majorityHash, uint32_t& majorityTokenCount,
                         std::vector<std::string>& agreeing,
                         std::vector<std::string>& divergent) const {
        LOCK(cs);
        auto it = mapShardResults.find(ShardKey(requestId, shardIndex));
        if (it == mapShardResults.end()) return false;
        return ComputeShardMajority(it->second, minSubmissions, majorityHash, majorityTokenCount, agreeing, divergent);
    }

    // ── F16: shard payment "already paid" bookkeeping ────────────────────────
    // A shard is paid exactly once, the first time its majority resolves (see
    // GetShardPaymentsForBlock/ProcessShardPayments in opoi.cpp). Without this,
    // "resolved" stays true forever once reached and every later block would
    // try to pay it again.

    bool IsShardPaid(const std::string& requestId, uint32_t shardIndex) const {
        LOCK(cs);
        return setPaidShards.count(ShardKey(requestId, shardIndex)) > 0;
    }

    void MarkShardPaid(const std::string& requestId, uint32_t shardIndex) {
        LOCK(cs);
        setPaidShards.insert(ShardKey(requestId, shardIndex));
    }

    void UnmarkShardPaid(const std::string& requestId, uint32_t shardIndex) {
        LOCK(cs);
        setPaidShards.erase(ShardKey(requestId, shardIndex));
    }

    // ── F14-C: VERIFIABLE-response payment "already paid" bookkeeping ────────
    // A VERIFIABLE request's RESPONSE cannot be paid in its own confirming
    // block — Auditors can only vote on it after it's already on-chain, and
    // resolution (ProcessAuditorVerifications) itself only ever runs on a
    // later block. So unlike an OPEN response (paid same-block, no bookkeeping
    // needed), this is deferred/retried across blocks like shard payments —
    // paid exactly once, whichever block first sees the request resolved PASS.

    bool IsResponsePaid(const std::string& requestId) const {
        LOCK(cs);
        return setPaidResponses.count(requestId) > 0;
    }

    void MarkResponsePaid(const std::string& requestId) {
        LOCK(cs);
        setPaidResponses.insert(requestId);
    }

    void UnmarkResponsePaid(const std::string& requestId) {
        LOCK(cs);
        setPaidResponses.erase(requestId);
    }

    bool IsChallengerRewardPaid(const std::string& requestId) const {
        LOCK(cs);
        return setPaidChallengerRewards.count(requestId) > 0;
    }

    void MarkChallengerRewardPaid(const std::string& requestId) {
        LOCK(cs);
        setPaidChallengerRewards.insert(requestId);
    }

    void UnmarkChallengerRewardPaid(const std::string& requestId) {
        LOCK(cs);
        setPaidChallengerRewards.erase(requestId);
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

    // Bug fix (2026-07-05): true only if this exact tx already applied as
    // this voter's recorded vote — a genuinely new re-vote (different
    // txHash) returns false, since re-voting must still go through the
    // normal window-closed check.
    bool IsHarmlessModelVoteRedelivery(const std::string& modelId, const std::string& voterAddress,
                                       const uint256& txHash) const {
        LOCK(cs);
        auto it = mapModelVotes.find(modelId);
        if (it == mapModelVotes.end()) return false;
        auto voteIt = it->second.find(voterAddress);
        return voteIt != it->second.end() && voteIt->second.txHash == txHash;
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

    void LockUTXO(const COutPoint& out, const std::string& minerAddress, const uint256& txHash) {
        LOCK(cs);
        mapLockedUTXOs[out] = minerAddress;
        mapLockingTxHash[out] = txHash;
    }

    void UnlockUTXO(const COutPoint& out) {
        LOCK(cs);
        mapLockedUTXOs.erase(out);
        mapLockingTxHash.erase(out);
    }

    bool IsLockedUTXO(const COutPoint& out) const {
        LOCK(cs);
        return mapLockedUTXOs.count(out) > 0;
    }

    // Bug fix (2026-07-05): see mapLockingTxHash comment above.
    bool GetLockingTxHash(const COutPoint& out, uint256& outHash) const {
        LOCK(cs);
        auto it = mapLockingTxHash.find(out);
        if (it == mapLockingTxHash.end()) return false;
        outHash = it->second;
        return true;
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
        // F10-B: bug fix — this used to erase the pending commit here, on the
        // theory that a stored REVEAL makes the COMMIT moot. But that made a
        // reorg unrecoverable: if only the REVEAL's block gets disconnected
        // (fork point between COMMIT and REVEAL), ProcessOPoITransaction's
        // undo path has no way to reconstruct the erased commit, permanently
        // stranding a miner who genuinely committed on the surviving chain.
        // The commit record is now kept forever (mirrors how a CHALLENGE's
        // commitHash is never erased after its REVEAL either) — REVEAL
        // validity is decided by req.commitWindowClosed + hash match, not by
        // whether this map still has an entry.
        return true;
    }

    // F10-B: Store a RESPONSE_COMMIT (phase=0) before the REVEAL arrives
    bool AddResponseCommit(const std::string& requestId,
                           const std::string& minerAddress,
                           const std::string& commitHash,
                           uint32_t blockHeight,
                           const uint256& txHash) {
        LOCK(cs);
        std::string key = requestId + ":" + minerAddress;
        mapResponseCommits[key] = commitHash;
        mapResponseCommitTxHash[key] = txHash;
        // Track in request
        auto it = mapRequests.find(requestId);
        if (it != mapRequests.end())
            it->second.responseCommits[minerAddress] = commitHash;
        return true;
    }

    // Bug fix (2026-07-05): true only if this exact tx already applied as
    // this miner's recorded COMMIT — a genuinely new commit (changing the
    // committed hash before the window closes, which is allowed) has a
    // different txHash and still goes through the normal window-closed check.
    bool IsHarmlessResponseCommitRedelivery(const std::string& requestId, const std::string& minerAddress,
                                            const uint256& txHash) const {
        LOCK(cs);
        auto it = mapResponseCommitTxHash.find(requestId + ":" + minerAddress);
        return it != mapResponseCommitTxHash.end() && it->second == txHash;
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

    bool StartUnstake(const std::string& minerAddress, uint32_t height, const uint256& txHashIn) {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        if (it == mapStakes.end() || !it->second.IsActive()) return false;
        it->second.stakeStatus   = OPOI_STAKE_UNSTAKING;
        it->second.unstakeHeight = height;
        it->second.unstakeTxHash = txHashIn;
        return true;
    }

    // Bug fix (2026-07-05): same harmless-redelivery pattern as
    // mapLockingTxHash, but for UNSTAKE — which has no locked-UTXO of its own
    // to key off of. A stale P2P relay of an already-applied UNSTAKE tx would
    // otherwise find IsActiveStaker() now false (this very tx flipped it) and
    // get the full DoS(100) meant for a genuine conflict.
    bool IsHarmlessUnstakeRedelivery(const std::string& minerAddress, const uint256& txHash) {
        LOCK(cs);
        auto it = mapStakes.find(minerAddress);
        return it != mapStakes.end() && it->second.IsUnstaking() && it->second.unstakeTxHash == txHash;
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

    // ── F14-C: Auditor verification ───────────────────────────────────────────

    bool AddAuditorVerification(const AuditorVerification& fv) {
        LOCK(cs);
        auto& verifs = mapAuditorVerifications[fv.requestId];
        for (const auto& existing : verifs)
            if (existing.auditorAddress == fv.auditorAddress) return true; // one vote per Auditor
        verifs.push_back(fv);
        // Lock Auditor's collateral
        if (!fv.auditorCollateral.IsNull()) {
            mapLockedUTXOs[fv.auditorCollateral] = fv.auditorAddress;
            mapLockingTxHash[fv.auditorCollateral] = fv.txHash;
        }
        return true;
    }

    // Returns all AuditorVerification records for a request
    std::vector<AuditorVerification> GetAuditorVerifications(const std::string& requestId) const {
        LOCK(cs);
        auto it = mapAuditorVerifications.find(requestId);
        if (it == mapAuditorVerifications.end()) return {};
        return it->second;
    }

    // Returns the majority Auditor result for a request, or -1 if no quorum yet
    // Returns AUDITOR_VERIFY_PASS/FAIL/TIMEOUT or -1
    int GetAuditorMajorityResult(const std::string& requestId, int minVerifiers) const {
        LOCK(cs);
        auto it = mapAuditorVerifications.find(requestId);
        if (it == mapAuditorVerifications.end()) return -1;
        return ComputeAuditorMajority(it->second, minVerifiers);
    }

    std::vector<std::pair<std::string, std::vector<AuditorVerification>>> ListAllAuditorVerifications() const {
        LOCK(cs);
        std::vector<std::pair<std::string, std::vector<AuditorVerification>>> result;
        for (const auto& kv : mapAuditorVerifications)
            result.push_back(kv);
        return result;
    }

    // "Resolved" bookkeeping (mirrors setPaidShards): a requestId's Auditor
    // verification is resolved exactly once, the first time its majority
    // reaches quorum (see ProcessAuditorVerifications in opoi.cpp).
    bool IsAuditorResolved(const std::string& requestId) const {
        LOCK(cs);
        return setResolvedAuditorVerifications.count(requestId) > 0;
    }

    void MarkAuditorResolved(const std::string& requestId) {
        LOCK(cs);
        setResolvedAuditorVerifications.insert(requestId);
    }

    // ── OPoI relay: pending deliveries ────────────────────────────────────────

    // Stores a delivery once, whether it arrived over P2P (opoidata message)
    // or via the local submitopoipendingdelivery RPC — the caller
    // (ProcessOPoIDataMessage in opoi.cpp) has already validated the
    // signature and PENDING-request check before calling this. Dedup is by
    // message hash, done by the caller via setKnownOPoIDataHashes before
    // this is reached; this just appends.
    void AddPendingDelivery(const std::string& destStakeAddress, const PendingDelivery& d) {
        LOCK(cs);
        mapPendingDeliveries[destStakeAddress].push_back(d);
    }

    // Read-and-drain: returns everything queued for this address and clears
    // it. A poller calling this on its own node gets each delivery exactly
    // once per poll (not "forever", unlike GetRequest-style lookups) — that's
    // the right semantics here since PromptQueue insertion downstream is the
    // actual durable record once picked up.
    std::vector<PendingDelivery> GetAndDrainPendingDeliveries(const std::string& destStakeAddress) {
        LOCK(cs);
        auto it = mapPendingDeliveries.find(destStakeAddress);
        if (it == mapPendingDeliveries.end()) return {};
        std::vector<PendingDelivery> result = std::move(it->second);
        mapPendingDeliveries.erase(it);
        return result;
    }

    bool HasKnownOPoIDataHash(const uint256& hash) const {
        LOCK(cs);
        return setKnownOPoIDataHashes.count(hash) > 0;
    }

    void MarkOPoIDataHashKnown(const uint256& hash) {
        LOCK(cs);
        setKnownOPoIDataHashes.insert(hash);
    }

    // Called alongside ProcessExpiredRequests in ConnectBlock (main.cpp) — a
    // pending delivery decays in lockstep with the REQUEST it's attached to,
    // once that REQUEST is no longer PENDING. Not called from
    // RebuildOPoICache's replay: this map is never populated by replay in the
    // first place (it's P2P/RPC-layer data, not consensus state produced by
    // ProcessOPoITransaction), so there is nothing to prune there.
    void PruneExpiredPendingDeliveries() {
        LOCK(cs);
        for (auto it = mapPendingDeliveries.begin(); it != mapPendingDeliveries.end(); ) {
            // Each destAddress's queue can mix requestIds in principle; filter
            // per-entry rather than assuming a queue is single-request.
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(), [&](const PendingDelivery& d) {
                auto rit = mapRequests.find(d.requestId);
                return rit == mapRequests.end() || rit->second.status != OPOI_STATUS_PENDING;
            }), vec.end());
            if (vec.empty()) it = mapPendingDeliveries.erase(it);
            else ++it;
        }
    }

    void UnmarkAuditorResolved(const std::string& requestId) {
        LOCK(cs);
        setResolvedAuditorVerifications.erase(requestId);
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

// F10-B: called from ConnectBlock (and RebuildOPoICache replay) to close a
// REQUEST's commit window once nOPoIResponseCommitWindowBlocks have passed
// since it confirmed. CheckOPoITransaction reads req.commitWindowClosed
// rather than computing height live — same convention as request expiry and
// challenge timeouts above, and for the same reason the VRF seed anchor was
// fixed to a stable block hash: a live chainActive.Height() read inside
// CheckOPoITransaction is a moving target depending on whether it's called
// for a mempool candidate or for a block being connected.
void ProcessResponseCommitWindows(uint32_t blockHeight, const Consensus::Params& params);

// F9-E: called from ConnectBlock (and RebuildOPoICache replay), same
// convention as ProcessResponseCommitWindows above — suspends
// (stakeStatus -> OPOI_STAKE_SUSPENDED) an ACTIVE stake once
// nOPoIStakeRenewalBlocks have passed since its last renewal (or original
// STAKE, if never renewed) without a RENEW tx. Recoverable at any time via
// RENEW (see ProcessOPoITransaction), never slashed.
void ProcessStakeRenewals(uint32_t blockHeight, const Consensus::Params& params);

// Called from ConnectBlock to verify OPoI miner payments in the coinbase tx.
// For each RESPONSE tx in the block, verifies the coinbase has an output paying
// the miner the agreed amount, within the nOPoISubsidyPct budget for this block.
// Also verifies F16 shard payments (see GetShardPaymentsForBlock) against the
// same budget, since both are payment for real OPoI compute.
bool CheckOPoIPayments(const std::vector<CTransaction>& vtx,
                       int nHeight,
                       const Consensus::Params& params,
                       CValidationState& state);

// F11-B/C: called from ConnectBlock to cap how many REQUEST/RESPONSE txs a
// single block may contain, regardless of fee/priority — bounds how much of
// a block the OPoI subsystem can occupy. Purely a per-block tx-type count,
// independent of any other OPoI validation.
bool CheckOPoIBlockCaps(const std::vector<CTransaction>& vtx,
                        const Consensus::Params& params,
                        CValidationState& state);

// F15-F: how many submissions a shard actually needs before its majority is
// final — lowered from the configured nOPoIShardMinSubmissions when fewer
// miners could ever possibly submit (e.g. an expert hosted by only 1-2
// active stakers). Shared by getshardresult (RPC) and GetShardPaymentsForBlock.
int GetEffectiveShardMinSubmissions(const OPoIRequest& req, uint32_t shardIndex,
                                    const Consensus::Params& params);

// ── F16: shard-routed request payments ───────────────────────────────────────
//
// SHARD_RESULT (shard-routed pipeline, F15-D..H) never generated any coinbase
// payment before this — CheckOPoIPayments only ever paid OPOI_RESPONSE_TX_TYPE
// (whole-model flow). A miner doing real, expensive shard compute got nothing.
//
// Design (decided with the user 2026-07-03):
//   - Paid per shard, as soon as that shard's majority resolves — not deferred
//     until the whole pipeline finishes (a stuck/reduced-redundancy sibling
//     shard shouldn't block payment for shards already confirmed).
//   - req.payment (the base reward) is split across the shards of the request,
//     weighted by layer span for DENSE shards (a request whose model doesn't
//     resolve to an ACTIVE ModelManifest is treated as a single implicit
//     shard, same fallback CheckOPoITransaction already uses elsewhere).
//   - Only miners whose submission matches the resolved majority (hash AND
//     tokenCount — see ComputeShardMajority) are paid — divergent (TYPE B, no
//     fraud proof) miners are excluded by construction, simply absent from
//     `agreeing`.
//   - F16 follow-up (2026-07-03, same day): feePerToken IS now applied to
//     shards too — SHARD_RESULT gained a tokenCount field (reusing
//     opoiTokenCount, mirroring RESPONSE). Unlike the base payment, the
//     per-token fee is NOT divided across shards: each shard's miners ran a
//     real forward pass per token through their own slice of the model, so
//     token-based compensation applies per shard independently. tokenCount is
//     part of the majority-matching key (not just the hash) precisely
//     because it's self-declared and otherwise unverifiable — a miner
//     inflating their own tokenCount just lands in a different bucket and
//     needs independent peers to agree on that exact figure to get paid.
//
// Returns the payments newly owed for THIS block: shards that resolve for the
// first time when combining the pre-block cache with vtx's own SHARD_RESULT
// txs, excluding shards already in OPoICache::setPaidShards. Called by
// CreateNewBlock (to build the coinbase) and CheckOPoIPayments (to verify
// it) — both must see the same vtx to agree on the result.
std::vector<OPoIShardPayment> GetShardPaymentsForBlock(
    const std::vector<CTransaction>& vtx, const Consensus::Params& params);

// F14-C: VERIFIABLE-request RESPONSE payments newly owed — every cached
// response whose request IsVerifiable(), isn't in OPoICache::setPaidResponses
// yet, and whose Auditor verifications (pre-block cache combined with this
// block's own not-yet-applied AUDITOR_VERIFY txs, same idempotent merge
// GetShardPaymentsForBlock uses — see ComputeAuditorMajority) resolve to a
// PASS majority. Called by CreateNewBlock and CheckOPoIPayments, which must
// see the same vtx to agree on the result.
std::vector<OPoIResponsePayment> GetVerifiablePaymentsForBlock(
    const std::vector<CTransaction>& vtx, const Consensus::Params& params);

// Called from ConnectBlock/RebuildOPoICache after the per-tx apply loop —
// marks every shard paid this block (per GetShardPaymentsForBlock) so it is
// never paid again. Must run after ProcessOPoITransaction has applied this
// block's own SHARD_RESULT txs, mirroring ProcessExpiredChallenges etc.
void ProcessShardPayments(const std::vector<CTransaction>& vtx, const Consensus::Params& params);

// F14-C: called from ConnectBlock/RebuildOPoICache after the per-tx apply loop
// — marks every VERIFIABLE response paid this block (per
// GetVerifiablePaymentsForBlock).
void ProcessVerifiableResponsePayments(const std::vector<CTransaction>& vtx, const Consensus::Params& params);

// F14-C: called from ConnectBlock/RebuildOPoICache after the per-tx apply loop —
// resolves any requestId whose Auditor verifications just reached quorum
// (unlock majority collateral, slash minority). See opoi.cpp for full rationale.
// Order relative to ProcessVerifiableResponsePayments (above) doesn't matter —
// GetVerifiablePaymentsForBlock recomputes the majority itself either way.
void ProcessAuditorVerifications(uint32_t blockHeight, const Consensus::Params& params);

// ── Phase 5: challenger rewards ───────────────────────────────────────────────

struct OPoIChallengerReward {
    std::string challengerAddress;
    CAmount     rewardAmount;
    std::string requestId;
    // F12-A: the other half of the slashed miner's stake, owed to the OPoI
    // treasury (GetOPoITreasuryAddress()) for this same proven CHALLENGE.
    // Aggregated across all rewards in the block into a single coinbase
    // output (see miner.cpp) rather than one output per requestId.
    CAmount     treasuryAmount;
};

// Returns rewards owed for CHALLENGEs proven at blockHeight (REVEAL verified +
// Auditor majority FAIL for VERIFIABLE tasks). Called from CreateNewBlock and
// CheckOPoIChallengerRewards so both use identical logic.
std::vector<OPoIChallengerReward> GetChallengerRewardsAtHeight(
    const std::vector<CTransaction>& vtx, uint32_t blockHeight, const Consensus::Params& params);

// Called from ConnectBlock to verify challenger reward outputs in the coinbase.
bool CheckOPoIChallengerRewards(const std::vector<CTransaction>& vtx,
                                uint32_t blockHeight,
                                const Consensus::Params& params,
                                CValidationState& state);

// Called from ConnectBlock (after ProcessExpiredChallenges) to mark this
// block's challenger rewards paid, so they aren't paid again in a later block.
void ProcessChallengerRewardPayments(const std::vector<CTransaction>& vtx, uint32_t blockHeight,
                                     const Consensus::Params& params);

// ── F15-A2: model governance ──────────────────────────────────────────────────

// Called from ConnectBlock: tallies any ModelManifest whose voting window closed
// at blockHeight. Approved manifests get activationHeight = blockHeight +
// nOPoIModelActivationDelayBlocks; otherwise the manifest is REJECTED.
void ProcessModelVotingWindows(uint32_t blockHeight, const Consensus::Params& params);

#endif // CSCOIN_OPOI_H
