// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "opoi.h"
#include "primitives/transaction.h"
#include "main.h"
#include "util.h"
#include "key.h"         // CPubKey::RecoverCompact
#include "key_io.h"      // DecodeDestination / CKeyID
#include "script/standard.h"    // GetScriptForDestination / IsValidDestination
#include "utilmoneystr.h"       // FormatMoney
#include "consensus/upgrades.h" // NetworkUpgradeActive / UPGRADE_OPOI
#include "opoi_vrf.h"
#include "chainparams.h"
#include "arith_uint256.h"
#include "crypto/sha256.h"
#include "utilstrencodings.h" // HexStr
#include <algorithm>

OPoICache g_opoiCache;

// ── Signature verification (no wallet access needed) ──────────────────────────

static bool VerifyOPoISig(const std::string& address,
                          const std::string& message,
                          const std::vector<unsigned char>& vchSig,
                          CPubKey* outPubKey = nullptr)
{
    if (vchSig.empty()) return false;

    CTxDestination dest = DecodeDestination(address);
    const CKeyID* pKeyID = boost::get<CKeyID>(&dest);
    if (!pKeyID) return false;                // not P2PKH

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << message;

    CPubKey recovered;
    if (!recovered.RecoverCompact(ss.GetHash(), vchSig)) return false;
    if (recovered.GetID() != *pKeyID) return false;
    if (outPubKey) *outPubKey = recovered;
    return true;
}

// ── F10-D / F15-C: shared VRF sortition check ──────────────────────────────────
//
// Used by both RESPONSE eligibility (seedSuffix="") and coordinator self-claim
// (seedSuffix="COORD") — same mechanism, different domain-separated VRF message,
// so a proof valid for one role can never be replayed as proof for the other.
// outReason is one of: "no-pubkey" | "no-vrf-proof" | "no-chain-tip" |
// "vrf-invalid" | "not-eligible" (used by callers to pick DoS score / reject reason).
// Bug fix (2026-07-02): this used to hash chainActive.Tip() internally — the
// CURRENT tip at verification time. Since the tip advances with every new
// block, a proof computed when the tx entered the mempool would silently stop
// verifying the moment even ONE more block was mined before it confirmed
// (found via real testing: a SHARD_RESULT tx sat one extra block and then
// permanently failed with bad-txns-opoi-shard-vrf-invalid, forever, since its
// proof could never match a moving target again). Fix: the caller now passes
// a STABLE seedBlockHash — the hash of the block the referenced OPoIRequest
// confirmed in (see GetOPoIRequestSeedHash below) — which never changes once
// mined, so a proof computed against it stays valid no matter how long the tx
// takes to confirm.
static bool CheckVrfSortition(const std::string& minerAddress,
                              const std::string& requestId,
                              const uint256& seedBlockHash,
                              const std::string& seedSuffix,
                              const std::vector<unsigned char>& vrfProof,
                              const std::string& thresholdHex,
                              std::string& outReason)
{
    OPoIStake stake;
    if (!g_opoiCache.GetStake(minerAddress, stake) || stake.minerPubKey.size() != 33) {
        outReason = "no-pubkey";
        return false;
    }
    if (vrfProof.size() != OPOI_VRF_PROOF_SIZE) {
        outReason = "no-vrf-proof";
        return false;
    }
    unsigned char seed[32];
    {
        CSHA256 hasher;
        hasher.Write(seedBlockHash.begin(), 32);
        hasher.Write((const unsigned char*)requestId.data(), requestId.size());
        if (!seedSuffix.empty())
            hasher.Write((const unsigned char*)seedSuffix.data(), seedSuffix.size());
        hasher.Finalize(seed);
    }
    unsigned char vrfOutput[32];
    if (!OPoIVRFVerify(stake.minerPubKey.begin(), seed, 32, vrfProof, vrfOutput)) {
        outReason = "vrf-invalid";
        return false;
    }
    arith_uint256 outputNum = UintToArith256(uint256(std::vector<unsigned char>(vrfOutput, vrfOutput + 32)));
    arith_uint256 threshold;
    threshold.SetHex(thresholdHex);
    if (!(outputNum < threshold)) {
        outReason = "miner-not-eligible";
        return false;
    }
    return true;
}

// Stable VRF seed anchor for a request: the hash of the block the REQUEST
// itself confirmed in. Unlike chainActive.Tip(), this never changes once the
// request is mined, so proofs computed against it stay valid regardless of
// how many blocks pass before the dependent tx (RESPONSE/COORDINATOR_CLAIM/
// SHARD_RESULT) confirms.
static bool GetOPoIRequestSeedHash(const std::string& requestId, uint256& outHash)
{
    OPoIRequest req;
    if (!g_opoiCache.GetRequest(requestId, req)) return false;
    CBlockIndex* pIndex = chainActive[req.blockHeight];
    if (!pIndex) return false;
    outHash = pIndex->GetBlockHash();
    return true;
}

// ── ProcessOPoITransaction ────────────────────────────────────────────────────

bool ProcessOPoITransaction(const CTransaction& tx, uint32_t blockHeight,
                            bool fUndo, const Consensus::Params* pparams)
{
    if (tx.nVersion != OPOI_TX_VERSION) return false;

    // ── UNDO ──────────────────────────────────────────────────────────────────
    if (fUndo) {
        LOCK(g_opoiCache.cs);
        if (tx.nType == OPOI_REQUEST_TX_TYPE) {
            g_opoiCache.mapRequests.erase(tx.opoiRequestId);

        } else if (tx.nType == OPOI_RESPONSE_TX_TYPE) {
            g_opoiCache.mapResponses.erase(tx.opoiRequestId);
            auto it = g_opoiCache.mapRequests.find(tx.opoiRequestId);
            if (it != g_opoiCache.mapRequests.end())
                it->second.status = OPOI_STATUS_PENDING;

        } else if (tx.nType == OPOI_STAKE_TX_TYPE) {
            g_opoiCache.mapStakes.erase(tx.opoiMinerAddress);
            g_opoiCache.UnlockUTXO(tx.opoiCollateralIn); // release lock on undo

        } else if (tx.nType == OPOI_UNSTAKE_TX_TYPE) {
            // Revert unstake: restore to ACTIVE
            auto it = g_opoiCache.mapStakes.find(tx.opoiMinerAddress);
            if (it != g_opoiCache.mapStakes.end()) {
                it->second.stakeStatus  = OPOI_STAKE_ACTIVE;
                it->second.unstakeHeight = 0;
            }

        } else if (tx.nType == OPOI_CHALLENGE_TX_TYPE) {
            g_opoiCache.mapChallenges.erase(tx.opoiRequestId);

        } else if (tx.nType == OPOI_MODEL_REGISTER_TX_TYPE) {
            g_opoiCache.mapModelManifests.erase(tx.opoiModelId);
            g_opoiCache.mapModelVotes.erase(tx.opoiModelId);

        } else if (tx.nType == OPOI_MODEL_VOTE_TX_TYPE) {
            auto it = g_opoiCache.mapModelVotes.find(tx.opoiModelId);
            if (it != g_opoiCache.mapModelVotes.end())
                it->second.erase(tx.opoiRequester);

        } else if (tx.nType == OPOI_COORDINATOR_CLAIM_TX_TYPE) {
            auto it = g_opoiCache.mapCoordinatorClaims.find(tx.opoiRequestId);
            if (it != g_opoiCache.mapCoordinatorClaims.end()) {
                auto& claims = it->second;
                claims.erase(std::remove_if(claims.begin(), claims.end(),
                    [&](const ShardCoordinatorClaim& c) { return c.minerAddress == tx.opoiMinerAddress; }),
                    claims.end());
            }

        } else if (tx.nType == OPOI_SHARD_RESULT_TX_TYPE) {
            std::string key = OPoICache::ShardKey(tx.opoiRequestId, tx.opoiShardIndex);
            auto it = g_opoiCache.mapShardResults.find(key);
            if (it != g_opoiCache.mapShardResults.end()) {
                auto& subs = it->second;
                subs.erase(std::remove_if(subs.begin(), subs.end(),
                    [&](const ShardResultSubmission& s) { return s.minerAddress == tx.opoiMinerAddress; }),
                    subs.end());
            }
        }
        return true;
    }

    // ── APPLY ─────────────────────────────────────────────────────────────────
    if (tx.nType == OPOI_REQUEST_TX_TYPE) {
        OPoIRequest req;
        req.requestId   = tx.opoiRequestId;
        req.requester   = tx.opoiRequester;
        req.model       = tx.opoiModel;
        req.promptHash  = tx.opoiPromptHash;
        req.maxTokens   = tx.opoiMaxTokens;
        req.payment     = tx.opoiPayment;
        req.feePerToken = tx.opoiFeePerToken;
        req.taskType    = tx.opoiTaskType;
        req.taskClass   = tx.opoiTaskClass; // F15-G
        req.blockHeight = blockHeight;
        req.sigTime     = tx.opoiSigTime;
        req.txHash      = tx.GetHash();
        req.status      = OPOI_STATUS_PENDING;
        g_opoiCache.AddRequest(req);
        LogPrintf("OPoI: REQUEST %s (model=%s type=%s) at height %u\n",
                  tx.opoiRequestId, tx.opoiModel,
                  (tx.opoiTaskType == OPOI_TASK_VERIFIABLE ? "VERIFIABLE" : "OPEN"),
                  blockHeight);

    } else if (tx.nType == OPOI_RESPONSE_TX_TYPE && tx.opoiResponsePhase == 0) {
        // COMMIT phase (F10-B) — no response hash yet, just record the commitment.
        g_opoiCache.AddResponseCommit(tx.opoiRequestId, tx.opoiMinerAddress,
                                       HexStr(tx.opoiResponseCommitHash), blockHeight);
        LogPrintf("OPoI: RESPONSE_COMMIT for %s by %s at height %u\n",
                  tx.opoiRequestId, tx.opoiMinerAddress, blockHeight);

    } else if (tx.nType == OPOI_RESPONSE_TX_TYPE) {
        // REVEAL phase — bug fix (2026-07-02): responsePhase was never set here
        // (OPoIResponse has no default member initializer for it), so
        // resp.IsRevealed() read an indeterminate value and the parent REQUEST
        // never transitioned to FULFILLED.
        OPoIResponse resp;
        resp.requestId     = tx.opoiRequestId;
        resp.minerAddress  = tx.opoiMinerAddress;
        resp.responseHash  = tx.opoiResponseHash;
        resp.commitment    = tx.opoiCommitment;
        resp.tokenCount    = tx.opoiTokenCount;
        resp.responsePhase = 1;
        resp.blockHeight   = blockHeight;
        resp.sigTime       = tx.opoiSigTime;
        resp.txHash        = tx.GetHash();
        g_opoiCache.AddResponse(resp);
        LogPrintf("OPoI: RESPONSE for %s by %s (tokens=%u) at height %u\n",
                  tx.opoiRequestId, tx.opoiMinerAddress, tx.opoiTokenCount, blockHeight);

    } else if (tx.nType == OPOI_STAKE_TX_TYPE) {
        OPoIStake stake;
        stake.minerAddress  = tx.opoiMinerAddress;
        stake.collateralIn  = tx.opoiCollateralIn;
        stake.amount        = tx.opoiPayment;
        stake.modelId       = tx.opoiModelId;   // F9-B (was never copied before — fixed 2026-07-02)
        stake.tier          = tx.opoiTier;
        stake.pomRoot       = tx.opoiPomRoot;
        stake.hostedExpertIds = tx.opoiHostedExpertIds; // F15-E
        stake.blockHeight   = blockHeight;
        stake.sigTime       = tx.opoiSigTime;
        stake.txHash        = tx.GetHash();
        stake.stakeStatus   = OPOI_STAKE_ACTIVE;
        stake.unstakeHeight = 0;
        // F10-D: recover the signer's pubkey so VRF eligibility can be verified later.
        // (Same sigMsg formula CheckOPoITransaction uses to verify this STAKE's signature.)
        {
            std::string sigMsg = tx.opoiMinerAddress + tx.opoiCollateralIn.hash.GetHex()
                               + strprintf("%u", tx.opoiCollateralIn.n);
            VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig, &stake.minerPubKey);
        }
        g_opoiCache.AddStake(stake);
        g_opoiCache.LockUTXO(tx.opoiCollateralIn, tx.opoiMinerAddress); // lock collateral
        LogPrintf("OPoI: STAKE by %s (%.4f CS) at height %u — collateral %s:%u locked\n",
                  tx.opoiMinerAddress, (double)tx.opoiPayment / COIN, blockHeight,
                  tx.opoiCollateralIn.hash.GetHex(), tx.opoiCollateralIn.n);

    } else if (tx.nType == OPOI_UNSTAKE_TX_TYPE) {
        if (g_opoiCache.StartUnstake(tx.opoiMinerAddress, blockHeight))
            LogPrintf("OPoI: UNSTAKE requested by %s at height %u\n",
                      tx.opoiMinerAddress, blockHeight);

    } else if (tx.nType == OPOI_CHALLENGE_TX_TYPE) {
        OPoIChallenge ch;
        ch.requestId           = tx.opoiRequestId;
        ch.challengerAddress   = tx.opoiRequester;
        ch.claimedResponseHash = tx.opoiResponseHash;
        ch.blockHeight         = blockHeight;
        ch.sigTime             = tx.opoiSigTime;
        ch.txHash              = tx.GetHash();
        ch.challengeStatus     = OPOI_CHALLENGE_OPEN;
        g_opoiCache.AddChallenge(ch);
        LogPrintf("OPoI: CHALLENGE for request %s by %s at height %u\n",
                  tx.opoiRequestId, tx.opoiRequester, blockHeight);

    } else if (tx.nType == OPOI_MODEL_REGISTER_TX_TYPE) {
        ModelManifest m;
        m.modelId              = tx.opoiModelId;
        m.archType             = tx.opoiModelArchType;
        m.totalParams          = tx.opoiModelTotalParams;
        m.activeParamsPerToken = tx.opoiModelActiveParamsPerToken;
        m.numLayers            = tx.opoiModelNumLayers;
        m.numDenseShards       = tx.opoiModelNumDenseShards;
        m.numExperts           = tx.opoiModelNumExperts;
        m.topKExperts          = tx.opoiModelTopKExperts;
        m.backbonePomRoot      = tx.opoiPomRoot;
        m.expertPomRoots       = tx.opoiModelExpertPomRoots;
        m.minRewardPerToken    = tx.opoiModelMinRewardPerToken;
        m.proposer             = tx.opoiRequester;
        m.proposedHeight       = blockHeight;
        uint32_t voteWindow    = pparams ? pparams->nOPoIModelVoteWindowBlocks : 200;
        m.voteWindowEndHeight  = blockHeight + voteWindow;
        m.activationHeight     = 0;
        // F15-B: derived, not trusted from the tx — any node recomputes the same value.
        m.shardTopologyHash    = ComputeShardTopologyHash(m);
        m.txHash               = tx.GetHash();
        m.status               = OPOI_MODEL_STATUS_VOTING;
        g_opoiCache.AddModelManifest(m);
        LogPrintf("OPoI: MODEL_REGISTER %s (arch=%d, experts=%u) by %s — voting closes at height %u\n",
                  tx.opoiModelId, (int)tx.opoiModelArchType, tx.opoiModelNumExperts,
                  tx.opoiRequester, m.voteWindowEndHeight);

    } else if (tx.nType == OPOI_MODEL_VOTE_TX_TYPE) {
        ModelVoteRecord rec;
        rec.voterAddress = tx.opoiRequester;
        rec.approve      = (tx.opoiModelVoteApprove != 0);
        rec.blockHeight  = blockHeight;
        OPoIStake voterStake;
        rec.weight = g_opoiCache.GetStake(tx.opoiRequester, voterStake) && voterStake.IsActive()
                     ? voterStake.amount : 0;
        g_opoiCache.AddModelVote(tx.opoiModelId, rec);
        LogPrintf("OPoI: MODEL_VOTE %s=%s by %s (weight=%.4f CS) at height %u\n",
                  tx.opoiModelId, rec.approve ? "YES" : "NO", tx.opoiRequester,
                  (double)rec.weight / COIN, blockHeight);

    } else if (tx.nType == OPOI_COORDINATOR_CLAIM_TX_TYPE) {
        ShardCoordinatorClaim claim;
        claim.requestId    = tx.opoiRequestId;
        claim.minerAddress = tx.opoiMinerAddress;
        claim.blockHeight  = blockHeight;
        claim.txHash       = tx.GetHash();
        g_opoiCache.AddCoordinatorClaim(claim);
        LogPrintf("OPoI: COORDINATOR_CLAIM for %s by %s at height %u\n",
                  tx.opoiRequestId, tx.opoiMinerAddress, blockHeight);

    } else if (tx.nType == OPOI_SHARD_RESULT_TX_TYPE) {
        ShardResultSubmission sub;
        sub.minerAddress       = tx.opoiMinerAddress;
        sub.boundaryOutputHash = tx.opoiResponseHash;
        sub.routerLogitsHash   = tx.opoiCommitment;
        sub.blockHeight        = blockHeight;
        sub.txHash             = tx.GetHash();
        g_opoiCache.AddShardResult(tx.opoiRequestId, tx.opoiShardIndex, sub);
        LogPrintf("OPoI: SHARD_RESULT for %s shard %u by %s (hash=%s) at height %u\n",
                  tx.opoiRequestId, tx.opoiShardIndex, tx.opoiMinerAddress,
                  tx.opoiResponseHash.GetHex(), blockHeight);
    }

    return true;
}

// ── RebuildOPoICache ──────────────────────────────────────────────────────────

void RebuildOPoICache()
{
    LogPrintf("OPoI: rebuilding cache from chain...\n");
    g_opoiCache.SetNull();

    const Consensus::Params& params = Params().GetConsensus();
    CBlockIndex* pindex = chainActive.Genesis();
    while (pindex) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindex, params)) {
            for (const CTransaction& tx : block.vtx) {
                if (tx.nVersion == OPOI_TX_VERSION)
                    ProcessOPoITransaction(tx, (uint32_t)pindex->nHeight, /*fUndo=*/false, &params);
            }
            // Replay per-block state transitions (challenge expiry, unstake release, request expiry)
            if (NetworkUpgradeActive(pindex->nHeight, params, Consensus::UPGRADE_OPOI)) {
                ProcessExpiredChallenges((uint32_t)pindex->nHeight, params);
                ProcessExpiredRequests((uint32_t)pindex->nHeight, params);
                ProcessModelVotingWindows((uint32_t)pindex->nHeight, params);
            }
        }
        pindex = chainActive.Next(pindex);
    }
    LogPrintf("OPoI: cache rebuilt — %zu request(s), %zu response(s), %zu stake(s), %zu challenge(s)\n",
              g_opoiCache.RequestCount(), g_opoiCache.ResponseCount(),
              g_opoiCache.StakeCount(), g_opoiCache.ChallengeCount());
}

// ── ProcessExpiredChallenges ──────────────────────────────────────────────────
//
// Called from ConnectBlock at the end of each block. For every open CHALLENGE
// whose window has elapsed (blockHeight >= challenge.blockHeight + window),
// the miner who submitted the RESPONSE is slashed: their stake is marked
// SLASHED and they can no longer submit RESPONSE txs until they re-stake.

void ProcessExpiredChallenges(uint32_t blockHeight, const Consensus::Params& params)
{
    LOCK(g_opoiCache.cs);
    for (auto& kv : g_opoiCache.mapChallenges) {
        OPoIChallenge& ch = kv.second;
        if (!ch.IsOpen()) continue;
        if ((int)(blockHeight - ch.blockHeight) < params.nOPoIChallengeWindowBlocks) continue;

        // Window elapsed — find the miner who submitted the challenged RESPONSE
        auto respIt = g_opoiCache.mapResponses.find(ch.requestId);
        if (respIt != g_opoiCache.mapResponses.end()) {
            const std::string& minerAddr = respIt->second.minerAddress;
            auto stakeIt = g_opoiCache.mapStakes.find(minerAddr);
            if (stakeIt != g_opoiCache.mapStakes.end() && stakeIt->second.IsActive()) {
                stakeIt->second.stakeStatus = OPOI_STAKE_SLASHED;
                // Collateral stays locked permanently on slash (coins effectively burned)
                LogPrintf("OPoI: SLASH miner %s — unanswered challenge for request %s at height %u"
                          " — collateral %s:%u permanently locked\n",
                          minerAddr, ch.requestId, blockHeight,
                          stakeIt->second.collateralIn.hash.GetHex(), stakeIt->second.collateralIn.n);
            }
        }
        ch.challengeStatus = OPOI_CHALLENGE_SLASHED;
    }

    // Also release stakes whose unstake cooldown has elapsed
    for (auto& kv : g_opoiCache.mapStakes) {
        OPoIStake& stake = kv.second;
        if (!stake.IsUnstaking()) continue;
        if ((int)(blockHeight - stake.unstakeHeight) >= params.nOPoIUnstakeCooldownBlocks) {
            stake.stakeStatus = OPOI_STAKE_RELEASED;
            // Unlock collateral so miner can spend it again
            g_opoiCache.mapLockedUTXOs.erase(stake.collateralIn);
            LogPrintf("OPoI: stake released for %s at height %u — collateral %s:%u unlocked\n",
                      stake.minerAddress, blockHeight,
                      stake.collateralIn.hash.GetHex(), stake.collateralIn.n);
        }
    }
}

// ── ProcessExpiredRequests ────────────────────────────────────────────────────
//
// Called from ConnectBlock. Marks PENDING requests as EXPIRED when they have
// been waiting for a RESPONSE longer than nOPoIRequestExpiryBlocks. Once
// expired, CheckOPoITransaction rejects any RESPONSE for that requestId.
// The locked payment is accounted for in the treasury (see CheckOPoIPayments).

void ProcessExpiredRequests(uint32_t blockHeight, const Consensus::Params& params)
{
    if (params.nOPoIRequestExpiryBlocks <= 0) return;
    LOCK(g_opoiCache.cs);
    for (auto& kv : g_opoiCache.mapRequests) {
        OPoIRequest& req = kv.second;
        if (!req.IsPending()) continue;
        if ((int)(blockHeight - req.blockHeight) < params.nOPoIRequestExpiryBlocks) continue;
        req.status = OPOI_STATUS_EXPIRED;
        // The fee is effectively returned to treasury at this block height.
        // PoW miners include the treasury payout in the coinbase (see miner.cpp).
        LogPrintf("OPoI: REQUEST %s expired at height %u — payment %.4f CS → treasury\n",
                  req.requestId, blockHeight, (double)req.payment / COIN);
    }
}

// ── ProcessModelVotingWindows (F15-A2) ────────────────────────────────────────
//
// Tallies every ModelManifest whose voting window closed at blockHeight.
// Approval requires yesWeight >= nOPoIModelApprovalPct% of the TOTAL active
// stake in the network at tally time (not just of the votes cast — an
// abstention counts against approval, same principle as a supermajority quorum).
void ProcessModelVotingWindows(uint32_t blockHeight, const Consensus::Params& params)
{
    for (const auto& m : g_opoiCache.ListManifestsDueForTally(blockHeight)) {
        CAmount yesWeight = 0, noWeight = 0;
        g_opoiCache.TallyModelVotes(m.modelId, yesWeight, noWeight);
        CAmount totalActiveStake = g_opoiCache.TotalActiveStake();

        bool approved = totalActiveStake > 0 &&
            // Compare as yesWeight*100 >= totalActiveStake*pct to avoid floating point
            ((double)yesWeight * 100.0) >= ((double)totalActiveStake * (double)params.nOPoIModelApprovalPct);

        if (approved) {
            uint32_t activationHeight = blockHeight + params.nOPoIModelActivationDelayBlocks;
            g_opoiCache.SetModelManifestStatus(m.modelId, OPOI_MODEL_STATUS_APPROVED, activationHeight);
            LogPrintf("OPoI: MODEL %s APPROVED (yes=%.4f CS / total=%.4f CS) — activates at height %u\n",
                      m.modelId, (double)yesWeight / COIN, (double)totalActiveStake / COIN, activationHeight);
        } else {
            g_opoiCache.SetModelManifestStatus(m.modelId, OPOI_MODEL_STATUS_REJECTED);
            LogPrintf("OPoI: MODEL %s REJECTED (yes=%.4f CS / total=%.4f CS, needed %d%%)\n",
                      m.modelId, (double)yesWeight / COIN, (double)totalActiveStake / COIN,
                      params.nOPoIModelApprovalPct);
        }
    }

    // Separately: any APPROVED manifest that has now reached its activationHeight becomes ACTIVE.
    for (const auto& m : g_opoiCache.ListModelManifests(OPOI_MODEL_STATUS_APPROVED)) {
        if (m.activationHeight > 0 && blockHeight >= m.activationHeight) {
            g_opoiCache.SetModelManifestStatus(m.modelId, OPOI_MODEL_STATUS_ACTIVE);
            LogPrintf("OPoI: MODEL %s is now ACTIVE at height %u\n", m.modelId, blockHeight);
        }
    }
}

// ── CheckOPoITransaction ──────────────────────────────────────────────────────

bool CheckOPoITransaction(const CTransaction& tx, CValidationState& state)
{
    if (tx.nVersion != OPOI_TX_VERSION) return true;

    // All OPoI txs must have empty UTXO vectors
    if (!tx.vin.empty() || !tx.vout.empty() || !tx.vJoinSplit.empty())
        return state.DoS(10, error("CheckOPoITransaction(): OPoI tx has non-empty vectors"),
                         REJECT_INVALID, "bad-txns-opoi-not-empty");

    switch (tx.nType) {

    case OPOI_REQUEST_TX_TYPE: {
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): REQUEST missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-no-request-id");
        if (tx.opoiRequester.empty())
            return state.DoS(10, error("CheckOPoITransaction(): REQUEST missing requester"),
                             REJECT_INVALID, "bad-txns-opoi-no-requester");
        if (tx.opoiModel.empty())
            return state.DoS(10, error("CheckOPoITransaction(): REQUEST missing model"),
                             REJECT_INVALID, "bad-txns-opoi-no-model");
        if (tx.opoiPromptHash.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): REQUEST missing promptHash"),
                             REJECT_INVALID, "bad-txns-opoi-no-prompt-hash");
        if (tx.opoiPayment <= 0)
            return state.DoS(10, error("CheckOPoITransaction(): REQUEST payment must be positive"),
                             REJECT_INVALID, "bad-txns-opoi-zero-payment");
        // F15-G: if opoiModel names an ACTIVE Model Manifest whose dense pipeline is
        // deeper than nOPoIMaxPipelineDepth, an INTERACTIVE request cannot use it —
        // commit-reveal adds +1 block per sequential shard, so a deep pipeline would
        // blow past any reasonable interactive latency budget. BATCH has no such limit.
        if (!fIsVerifying) {
            ModelManifest manifest;
            if (g_opoiCache.GetModelManifest(tx.opoiModel, manifest) && manifest.IsActive()
                && tx.opoiTaskClass == OPOI_TASKCLASS_INTERACTIVE
                && (int)manifest.numDenseShards > Params().GetConsensus().nOPoIMaxPipelineDepth)
                return state.DoS(10, error("CheckOPoITransaction(): REQUEST model %s pipeline too deep "
                                           "(%u dense shards) for INTERACTIVE — use BATCH",
                                           manifest.modelId, manifest.numDenseShards),
                                 REJECT_INVALID, "bad-txns-opoi-request-pipeline-too-deep-for-interactive");
        }
        // Verify requester's signature. Bug fix (2026-07-02): this previously omitted
        // feePerToken and taskType from the signed message (a mismatch with what
        // submitopoirequest actually signs — see rpc/opoi.cpp), so every REQUEST
        // submitted via that RPC failed signature verification unconditionally.
        {
            std::string sigMsg = tx.opoiRequestId + tx.opoiRequester + tx.opoiModel
                               + tx.opoiPromptHash.GetHex()
                               + strprintf("%u%d%d%d%d", tx.opoiMaxTokens, tx.opoiPayment,
                                           tx.opoiFeePerToken, (int)tx.opoiTaskType, (int)tx.opoiTaskClass);
            if (!VerifyOPoISig(tx.opoiRequester, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): REQUEST invalid signature for %s",
                                            tx.opoiRequester),
                                 REJECT_INVALID, "bad-txns-opoi-request-bad-sig");
        }
        break;
    }

    case OPOI_RESPONSE_TX_TYPE: {
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-no-request-id");
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing minerAddress"),
                             REJECT_INVALID, "bad-txns-opoi-no-miner");
        // Phase 3: miner must be an active staker (skip cache check during VerifyDB startup)
        if (!fIsVerifying && !g_opoiCache.IsActiveStaker(tx.opoiMinerAddress))
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE from non-staked miner %s",
                                       tx.opoiMinerAddress),
                             REJECT_INVALID, "bad-txns-opoi-miner-not-staked");
        // Phase 6: reject RESPONSE for an expired REQUEST
        if (!fIsVerifying) {
            OPoIRequest req;
            if (g_opoiCache.GetRequest(tx.opoiRequestId, req) && req.IsExpired())
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE for expired REQUEST %s",
                                            tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-request-expired");
        }

        // F10-B: bug fix (2026-07-02) — this switch previously ignored opoiResponsePhase
        // entirely and always required opoiResponseHash. Since transaction.h only
        // serializes opoiResponseHash/opoiCommitment/opoiTokenCount when phase==1
        // (REVEAL), any tx that round-tripped through real wire/disk serialization
        // with the (default) phase==0 would lose those fields and get rejected here
        // — i.e. RESPONSE txs silently broke for every node except the one that
        // originated them (which still had the in-memory object, never actually
        // serialized). submitopoiresponse now explicitly sets phase=1 (see rpc/opoi.cpp).
        if (tx.opoiResponsePhase == 0) {
            // COMMIT phase (F10-B anti-copy protocol; not yet exposed via RPC —
            // this branch exists so a well-formed COMMIT tx is at least structurally
            // validated instead of falling through to "invalid nType").
            if (tx.opoiResponseCommitHash.size() != 32)
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE COMMIT missing commit hash"),
                                 REJECT_INVALID, "bad-txns-opoi-response-no-commit-hash");
            std::string sigMsg = tx.opoiRequestId + tx.opoiMinerAddress + HexStr(tx.opoiResponseCommitHash);
            if (!VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): RESPONSE COMMIT invalid signature for %s",
                                            tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-response-bad-sig");
            break;
        }

        // REVEAL phase (phase == 1)
        if (tx.opoiResponseHash.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing responseHash"),
                             REJECT_INVALID, "bad-txns-opoi-no-response-hash");

        // F10-D: VRF eligibility — only the sortition selected by ECVRF may respond.
        // Skipped during VerifyDB (fIsVerifying), same convention as the staker check
        // above: VerifyDB replays historical blocks where the cache isn't populated yet.
        if (!fIsVerifying) {
            uint256 seedHash;
            if (!GetOPoIRequestSeedHash(tx.opoiRequestId, seedHash))
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE cannot derive VRF seed for %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-response-no-seed");
            std::string reason;
            if (!CheckVrfSortition(tx.opoiMinerAddress, tx.opoiRequestId, seedHash, "", tx.opoiVrfProof,
                                    Params().GetConsensus().nOPoIVrfThreshold, reason))
                return state.DoS(reason == "vrf-invalid" ? 100 : 10,
                                 error("CheckOPoITransaction(): RESPONSE VRF check failed (%s) for %s",
                                       reason, tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-response-" + reason);
        }

        // Verify miner's signature. Bug fix (2026-07-02): previously only covered
        // requestId+minerAddress+responseHash, leaving opoiCommitment and
        // opoiTokenCount unauthenticated even though tokenCount directly drives the
        // fee-per-token payment — a relay could tamper with either post-signature.
        {
            std::string sigMsg = tx.opoiRequestId + tx.opoiMinerAddress + tx.opoiResponseHash.GetHex()
                                + tx.opoiCommitment.GetHex() + strprintf("%u", tx.opoiTokenCount);
            if (!VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): RESPONSE invalid signature for %s",
                                            tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-response-bad-sig");
        }
        break;
    }

    case OPOI_STAKE_TX_TYPE: {
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): STAKE missing minerAddress"),
                             REJECT_INVALID, "bad-txns-opoi-stake-no-miner");
        if (tx.opoiCollateralIn.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): STAKE missing collateralIn"),
                             REJECT_INVALID, "bad-txns-opoi-stake-no-collateral");
        if (tx.opoiPayment <= 0)
            return state.DoS(10, error("CheckOPoITransaction(): STAKE payment must be positive"),
                             REJECT_INVALID, "bad-txns-opoi-stake-zero-amount");
        // Collateral must not be already locked by another stake
        if (!fIsVerifying && g_opoiCache.IsLockedUTXO(tx.opoiCollateralIn))
            return state.DoS(100, error("CheckOPoITransaction(): STAKE collateral %s:%u already locked",
                                        tx.opoiCollateralIn.hash.GetHex(), tx.opoiCollateralIn.n),
                             REJECT_INVALID, "bad-txns-opoi-stake-collateral-locked");
        // Verify miner owns the collateral address
        {
            std::string sigMsg = tx.opoiMinerAddress + tx.opoiCollateralIn.hash.GetHex()
                               + strprintf("%u", tx.opoiCollateralIn.n);
            if (!VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): STAKE invalid signature for %s",
                                            tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-stake-bad-sig");
        }
        break;
    }

    case OPOI_UNSTAKE_TX_TYPE: {
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): UNSTAKE missing minerAddress"),
                             REJECT_INVALID, "bad-txns-opoi-unstake-no-miner");
        if (!fIsVerifying && !g_opoiCache.IsActiveStaker(tx.opoiMinerAddress))
            return state.DoS(100, error("CheckOPoITransaction(): UNSTAKE from non-active staker %s",
                                       tx.opoiMinerAddress),
                             REJECT_INVALID, "bad-txns-opoi-unstake-not-staked");
        // Verify miner's intent to unstake
        {
            std::string sigMsg = std::string("UNSTAKE") + tx.opoiMinerAddress;
            if (!VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): UNSTAKE invalid signature for %s",
                                            tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-unstake-bad-sig");
        }
        break;
    }

    case OPOI_CHALLENGE_TX_TYPE: {
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-request-id");
        if (tx.opoiRequester.empty())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing challenger"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-challenger");
        if (tx.opoiResponseHash.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing claimedResponseHash"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-hash");
        if (!fIsVerifying) {
            OPoIResponse resp;
            if (!g_opoiCache.GetResponse(tx.opoiRequestId, resp))
                return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE for unknown response %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-challenge-unknown-response");
        }
        // Verify challenger's signature
        {
            std::string sigMsg = tx.opoiRequestId + tx.opoiRequester + tx.opoiResponseHash.GetHex();
            if (!VerifyOPoISig(tx.opoiRequester, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): CHALLENGE invalid signature for %s",
                                            tx.opoiRequester),
                                 REJECT_INVALID, "bad-txns-opoi-challenge-bad-sig");
        }
        break;
    }

    case OPOI_MODEL_REGISTER_TX_TYPE: {
        if (tx.opoiModelId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_REGISTER missing modelId"),
                             REJECT_INVALID, "bad-txns-opoi-model-no-id");
        if (tx.opoiRequester.empty())
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_REGISTER missing proposer"),
                             REJECT_INVALID, "bad-txns-opoi-model-no-proposer");
        if (tx.opoiModelArchType != OPOI_ARCH_DENSE && tx.opoiModelArchType != OPOI_ARCH_MOE
            && tx.opoiModelArchType != OPOI_ARCH_HYBRID)
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_REGISTER invalid archType %d",
                                       (int)tx.opoiModelArchType),
                             REJECT_INVALID, "bad-txns-opoi-model-bad-arch-type");
        if (tx.opoiModelArchType == OPOI_ARCH_DENSE) {
            if (tx.opoiModelNumExperts != 0 || tx.opoiModelTopKExperts != 0
                || !tx.opoiModelExpertPomRoots.empty())
                return state.DoS(10, error("CheckOPoITransaction(): DENSE model must not declare experts"),
                                 REJECT_INVALID, "bad-txns-opoi-model-dense-has-experts");
        } else {
            if (tx.opoiModelNumExperts == 0 || tx.opoiModelTopKExperts == 0
                || tx.opoiModelTopKExperts > tx.opoiModelNumExperts)
                return state.DoS(10, error("CheckOPoITransaction(): MOE/HYBRID model has invalid expert counts"),
                                 REJECT_INVALID, "bad-txns-opoi-model-bad-expert-count");
            if (tx.opoiModelExpertPomRoots.size() != tx.opoiModelNumExperts)
                return state.DoS(10, error("CheckOPoITransaction(): expertPomRoots size mismatch (%d != %u)",
                                           (int)tx.opoiModelExpertPomRoots.size(), tx.opoiModelNumExperts),
                                 REJECT_INVALID, "bad-txns-opoi-model-expert-root-count-mismatch");
        }
        // F15-B: numDenseShards defines the pipeline split of the backbone (see opoi_shard.h).
        // Must be at least 1 and cannot exceed numLayers (a shard needs >= 1 layer).
        if (tx.opoiModelNumLayers == 0)
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_REGISTER numLayers must be > 0"),
                             REJECT_INVALID, "bad-txns-opoi-model-zero-layers");
        if (tx.opoiModelNumDenseShards == 0 || tx.opoiModelNumDenseShards > tx.opoiModelNumLayers)
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_REGISTER invalid numDenseShards %u for %u layers",
                                       tx.opoiModelNumDenseShards, tx.opoiModelNumLayers),
                             REJECT_INVALID, "bad-txns-opoi-model-bad-shard-count");
        if (tx.opoiPomRoot.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_REGISTER missing backbonePomRoot"),
                             REJECT_INVALID, "bad-txns-opoi-model-no-pom-root");
        if (!fIsVerifying) {
            ModelManifest existing;
            if (g_opoiCache.GetModelManifest(tx.opoiModelId, existing))
                return state.DoS(10, error("CheckOPoITransaction(): model %s already registered",
                                           tx.opoiModelId),
                                 REJECT_INVALID, "bad-txns-opoi-model-already-registered");
            if (!g_opoiCache.IsActiveStaker(tx.opoiRequester))
                return state.DoS(10, error("CheckOPoITransaction(): MODEL_REGISTER proposer %s not staked",
                                           tx.opoiRequester),
                                 REJECT_INVALID, "bad-txns-opoi-model-proposer-not-staked");
        }
        // Verify proposer's signature
        {
            std::string sigMsg = tx.opoiModelId + tx.opoiRequester + strprintf("%d", (int)tx.opoiModelArchType)
                               + tx.opoiPomRoot.GetHex();
            if (!VerifyOPoISig(tx.opoiRequester, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): MODEL_REGISTER invalid signature for %s",
                                            tx.opoiRequester),
                                 REJECT_INVALID, "bad-txns-opoi-model-bad-sig");
        }
        break;
    }

    case OPOI_MODEL_VOTE_TX_TYPE: {
        if (tx.opoiModelId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_VOTE missing modelId"),
                             REJECT_INVALID, "bad-txns-opoi-model-vote-no-id");
        if (tx.opoiRequester.empty())
            return state.DoS(10, error("CheckOPoITransaction(): MODEL_VOTE missing voter"),
                             REJECT_INVALID, "bad-txns-opoi-model-vote-no-voter");
        if (!fIsVerifying) {
            ModelManifest m;
            if (!g_opoiCache.GetModelManifest(tx.opoiModelId, m))
                return state.DoS(10, error("CheckOPoITransaction(): MODEL_VOTE for unknown model %s",
                                           tx.opoiModelId),
                                 REJECT_INVALID, "bad-txns-opoi-model-vote-unknown-model");
            if (!m.IsVoting())
                return state.DoS(10, error("CheckOPoITransaction(): MODEL_VOTE window closed for %s",
                                           tx.opoiModelId),
                                 REJECT_INVALID, "bad-txns-opoi-model-vote-window-closed");
            if (!g_opoiCache.IsActiveStaker(tx.opoiRequester))
                return state.DoS(10, error("CheckOPoITransaction(): MODEL_VOTE voter %s not staked",
                                           tx.opoiRequester),
                                 REJECT_INVALID, "bad-txns-opoi-model-vote-not-staked");
        }
        // Verify voter's signature
        {
            std::string sigMsg = tx.opoiModelId + tx.opoiRequester + strprintf("%d", (int)tx.opoiModelVoteApprove);
            if (!VerifyOPoISig(tx.opoiRequester, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): MODEL_VOTE invalid signature for %s",
                                            tx.opoiRequester),
                                 REJECT_INVALID, "bad-txns-opoi-model-vote-bad-sig");
        }
        break;
    }

    case OPOI_COORDINATOR_CLAIM_TX_TYPE: {
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): COORDINATOR_CLAIM missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-coord-no-request-id");
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): COORDINATOR_CLAIM missing miner"),
                             REJECT_INVALID, "bad-txns-opoi-coord-no-miner");
        if (!fIsVerifying) {
            if (!g_opoiCache.IsActiveStaker(tx.opoiMinerAddress))
                return state.DoS(10, error("CheckOPoITransaction(): COORDINATOR_CLAIM by non-staked %s",
                                           tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-coord-not-staked");
            OPoIRequest req;
            if (!g_opoiCache.GetRequest(tx.opoiRequestId, req))
                return state.DoS(10, error("CheckOPoITransaction(): COORDINATOR_CLAIM for unknown request %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-coord-unknown-request");
            // F15-C: VRF self-claim — "COORD" domain-separates this from RESPONSE
            // eligibility so a response proof can never be replayed as a coordinator claim.
            uint256 seedHash;
            if (!GetOPoIRequestSeedHash(tx.opoiRequestId, seedHash))
                return state.DoS(10, error("CheckOPoITransaction(): COORDINATOR_CLAIM cannot derive VRF seed for %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-coord-no-seed");
            std::string reason;
            if (!CheckVrfSortition(tx.opoiMinerAddress, tx.opoiRequestId, seedHash, "COORD", tx.opoiVrfProof,
                                    Params().GetConsensus().nOPoICoordinatorThreshold, reason))
                return state.DoS(reason == "vrf-invalid" ? 100 : 10,
                                 error("CheckOPoITransaction(): COORDINATOR_CLAIM VRF check failed (%s) for %s",
                                       reason, tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-coord-" + reason);
        }
        // Verify claimant's signature
        {
            std::string sigMsg = std::string("COORD") + tx.opoiRequestId + tx.opoiMinerAddress;
            if (!VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): COORDINATOR_CLAIM invalid signature for %s",
                                            tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-coord-bad-sig");
        }
        break;
    }

    case OPOI_SHARD_RESULT_TX_TYPE: {
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-shard-no-request-id");
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT missing miner"),
                             REJECT_INVALID, "bad-txns-opoi-shard-no-miner");
        if (tx.opoiResponseHash.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT missing boundaryOutputHash"),
                             REJECT_INVALID, "bad-txns-opoi-shard-no-output-hash");
        if (!fIsVerifying) {
            if (!g_opoiCache.IsActiveStaker(tx.opoiMinerAddress))
                return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT by non-staked %s",
                                           tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-shard-not-staked");
            OPoIRequest req;
            if (!g_opoiCache.GetRequest(tx.opoiRequestId, req))
                return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT for unknown request %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-shard-unknown-request");
            // F15-D: VRF self-claim, domain-separated per shard index so eligibility
            // for shard N says nothing about eligibility for shard M (or for RESPONSE
            // / COORDINATOR_CLAIM, which use different seed suffixes entirely).
            uint256 seedHash;
            if (!GetOPoIRequestSeedHash(tx.opoiRequestId, seedHash))
                return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT cannot derive VRF seed for %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-shard-no-seed");
            std::string reason;
            std::string seedSuffix = "SHARD" + strprintf("%u", tx.opoiShardIndex);
            if (!CheckVrfSortition(tx.opoiMinerAddress, tx.opoiRequestId, seedHash, seedSuffix, tx.opoiVrfProof,
                                    Params().GetConsensus().nOPoIShardThreshold, reason))
                return state.DoS(reason == "vrf-invalid" ? 100 : 10,
                                 error("CheckOPoITransaction(): SHARD_RESULT VRF check failed (%s) for %s",
                                       reason, tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-shard-" + reason);
            // F15-E: if req.model happens to name an ACTIVE Model Manifest (governed
            // model, F15-A), cross-check shardIndex against its MEG (F15-B). Requests
            // using a free-text model name unrelated to any manifest skip this check
            // entirely — F15-D's generic VRF-eligibility gate above already applies.
            ModelManifest manifest;
            if (g_opoiCache.GetModelManifest(req.model, manifest) && manifest.IsActive()) {
                auto meg = BuildModelExecutionGraph(manifest);
                if (tx.opoiShardIndex >= meg.size())
                    return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT shardIndex %u out of range for model %s",
                                               tx.opoiShardIndex, manifest.modelId),
                                     REJECT_INVALID, "bad-txns-opoi-shard-index-out-of-range");
                const ShardDescriptor& d = meg[tx.opoiShardIndex];
                if (d.shardType == OPOI_SHARD_EXPERT) {
                    OPoIStake stake;
                    if (!g_opoiCache.GetStake(tx.opoiMinerAddress, stake) || !stake.HostsExpert(d.expertId))
                        return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT miner %s does not host expert %u",
                                                   tx.opoiMinerAddress, d.expertId),
                                         REJECT_INVALID, "bad-txns-opoi-shard-expert-not-hosted");
                }
            }
        }
        // Verify submitter's signature
        {
            std::string sigMsg = std::string("SHARD") + tx.opoiRequestId + strprintf("%u", tx.opoiShardIndex)
                                + tx.opoiMinerAddress + tx.opoiResponseHash.GetHex() + tx.opoiCommitment.GetHex();
            if (!VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): SHARD_RESULT invalid signature for %s",
                                            tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-shard-bad-sig");
        }
        break;
    }

    default:
        return state.DoS(10, error("CheckOPoITransaction(): invalid nType %d", tx.nType),
                         REJECT_INVALID, "bad-txns-opoi-invalid-type");
    }

    return true;
}

// ── CheckOPoIPayments ─────────────────────────────────────────────────────────
// Verifies that for each RESPONSE tx in vtx[1..], the coinbase (vtx[0]) contains
// an output paying the miner:
//   total_payment = request.payment + tx.opoiTokenCount * request.feePerToken
// Called from ConnectBlock before the tx processing loop, using the pre-block cache.

bool CheckOPoIPayments(const std::vector<CTransaction>& vtx,
                       int nHeight,
                       const Consensus::Params& params,
                       CValidationState& state)
{
    if (vtx.empty()) return true;
    const CTransaction& coinbase = vtx[0];

    // OPoI budget: up to nOPoISubsidyPct (10%) of block subsidy — halving-aware.
    const CAmount blockSubsidy  = GetBlockSubsidy(nHeight, params);
    const CAmount opoiBudget    = static_cast<CAmount>(blockSubsidy * params.nOPoISubsidyPct);
    CAmount totalPaymentsChecked = 0;

    for (size_t i = 1; i < vtx.size(); ++i) {
        const CTransaction& tx = vtx[i];
        if (tx.nVersion != OPOI_TX_VERSION || tx.nType != OPOI_RESPONSE_TX_TYPE)
            continue;

        OPoIRequest req;
        if (!g_opoiCache.GetRequest(tx.opoiRequestId, req) || req.payment <= 0) {
            LogPrint("opoi", "CheckOPoIPayments: no cached REQUEST for %s, skipping\n",
                     tx.opoiRequestId);
            continue;
        }

        // Total payment = baseFee + tokenCount * feePerToken
        CAmount totalPayment = req.payment;
        if (req.feePerToken > 0 && tx.opoiTokenCount > 0)
            totalPayment += (CAmount)tx.opoiTokenCount * req.feePerToken;

        // Mirror CreateNewBlock: skip if payment would exceed OPoI budget
        if (totalPaymentsChecked + totalPayment > opoiBudget) {
            LogPrint("opoi", "CheckOPoIPayments: payment %s exceeds OPoI budget; RESPONSE tx not paid\n",
                     FormatMoney(totalPayment));
            continue;
        }

        CTxDestination minerDest = DecodeDestination(tx.opoiMinerAddress);
        if (!IsValidDestination(minerDest))
            return state.DoS(100, error("CheckOPoIPayments(): RESPONSE has invalid miner address %s",
                                        tx.opoiMinerAddress),
                             REJECT_INVALID, "bad-cb-opoi-invalid-miner-addr");

        CScript expectedScript = GetScriptForDestination(minerDest);
        bool found = false;
        for (const CTxOut& out : coinbase.vout) {
            if (out.scriptPubKey == expectedScript && out.nValue == totalPayment) {
                found = true;
                break;
            }
        }

        if (!found) {
            return state.DoS(100, error("CheckOPoIPayments(): coinbase missing OPoI payment of %s to %s for request %s",
                                        FormatMoney(totalPayment), tx.opoiMinerAddress, tx.opoiRequestId),
                             REJECT_INVALID, "bad-cb-opoi-missing-payment");
        }
        totalPaymentsChecked += totalPayment;
    }

    return true;
}

// ── GetChallengerRewardsAtHeight ──────────────────────────────────────────────
//
// Returns the list of challenger rewards owed for challenges that expire at
// blockHeight. A challenge "expires" when blockHeight - ch.blockHeight >= window.
// The reward is nOPoIChallengerRewardPct % of the miner's staked amount.
// Used by both CreateNewBlock (to add coinbase outputs) and
// CheckOPoIChallengerRewards (to validate them).

std::vector<OPoIChallengerReward> GetChallengerRewardsAtHeight(
    uint32_t blockHeight, const Consensus::Params& params)
{
    std::vector<OPoIChallengerReward> rewards;
    if (params.nOPoIChallengerRewardPct <= 0) return rewards;

    LOCK(g_opoiCache.cs);
    for (const auto& kv : g_opoiCache.mapChallenges) {
        const OPoIChallenge& ch = kv.second;
        if (!ch.IsOpen()) continue;
        if ((int)(blockHeight - ch.blockHeight) < params.nOPoIChallengeWindowBlocks) continue;

        // Find the miner that was challenged (the one who submitted the RESPONSE)
        auto respIt = g_opoiCache.mapResponses.find(ch.requestId);
        if (respIt == g_opoiCache.mapResponses.end()) continue;

        auto stakeIt = g_opoiCache.mapStakes.find(respIt->second.minerAddress);
        if (stakeIt == g_opoiCache.mapStakes.end()) continue;
        if (!stakeIt->second.IsActive()) continue; // already slashed/released

        CAmount stakedAmount = stakeIt->second.amount;
        CAmount reward = (stakedAmount * params.nOPoIChallengerRewardPct) / 100;
        if (reward <= 0) continue;

        rewards.push_back({ch.challengerAddress, reward});
        LogPrint("opoi", "GetChallengerRewardsAtHeight: height=%u challenger=%s reward=%s\n",
                 blockHeight, ch.challengerAddress, FormatMoney(reward));
    }
    return rewards;
}

// ── CheckOPoIChallengerRewards ────────────────────────────────────────────────

bool CheckOPoIChallengerRewards(const std::vector<CTransaction>& vtx,
                                uint32_t blockHeight,
                                const Consensus::Params& params,
                                CValidationState& state)
{
    if (vtx.empty()) return true;
    const CTransaction& coinbase = vtx[0];

    CAmount totalCoinbaseValue = 0;
    for (const CTxOut& out : coinbase.vout)
        totalCoinbaseValue += out.nValue;

    auto rewards = GetChallengerRewardsAtHeight(blockHeight, params);
    CAmount checkedTotal = 0;

    for (const auto& reward : rewards) {
        // Mirror CreateNewBlock: skip if reward exceeds remaining coinbase value
        if (checkedTotal + reward.rewardAmount > totalCoinbaseValue) {
            LogPrint("opoi", "CheckOPoIChallengerRewards: reward %s exceeds coinbase, skipping\n",
                     FormatMoney(reward.rewardAmount));
            continue;
        }

        CTxDestination dest = DecodeDestination(reward.challengerAddress);
        if (!IsValidDestination(dest))
            return state.DoS(100, error("CheckOPoIChallengerRewards(): invalid challenger address %s",
                                        reward.challengerAddress),
                             REJECT_INVALID, "bad-cb-opoi-invalid-challenger-addr");

        CScript expectedScript = GetScriptForDestination(dest);
        bool found = false;
        for (const CTxOut& out : coinbase.vout) {
            if (out.scriptPubKey == expectedScript && out.nValue == reward.rewardAmount) {
                found = true;
                break;
            }
        }

        if (!found)
            return state.DoS(100, error("CheckOPoIChallengerRewards(): coinbase missing challenger reward"
                                        " of %s to %s", FormatMoney(reward.rewardAmount),
                                        reward.challengerAddress),
                             REJECT_INVALID, "bad-cb-opoi-missing-challenger-reward");

        checkedTotal += reward.rewardAmount;
    }

    return true;
}
