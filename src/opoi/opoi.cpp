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

// Bug fix (2026-07-05): distinguishes a harmless late P2P redelivery of a tx that
// already locked this UTXO from a genuinely different, conflicting tx. Bitcoin
// Core's normal defense against re-validating an already-known/confirmed tx
// (AlreadyHave() checking mempool/pcoinsTip->HaveCoins) can never recognize an
// OPoI tx as "already seen", because these tx types are required to have empty
// vin/vout (HaveCoins() is defined as "!vout.empty()", always false here). So a
// stale tx-relay message for an already-mined STAKE/CHALLENGE-COMMIT/
// AUDITOR_VERIFY — ordinary P2P timing, not an attack — always reaches
// CheckOPoITransaction again and used to be rejected with DoS(100), which alone
// reaches the default ban threshold (banscore=100) and disconnects the honest
// relaying peer. Confirmed causing a real, unintended reorg in multi-node testing
// (2026-07-05): a node got banned by its own peers mid-block-production and kept
// mining a divergent chain alone. This only suppresses the DoS score for the
// EXACT same txid being redelivered — a different tx racing for the same UTXO
// still gets the full DoS(100) below, since that's a genuine conflict.
static bool IsHarmlessRedelivery(const COutPoint& collateral, const uint256& txHash)
{
    uint256 lockingTxHash;
    return g_opoiCache.GetLockingTxHash(collateral, lockingTxHash) && lockingTxHash == txHash;
}

// ── OPoI relay (2026-07-05): P2P delivery for NAT'd/CGNAT'd miners ────────────
// Shared by the "opoidata" P2P receive handler (main.cpp) and the
// submitopoipendingdelivery RPC (rpc/opoi.cpp) — same validation either way.
// Ties spam-prevention to real on-chain state for free, but WHICH on-chain
// role must have signed depends on kind (see COPoIDataMsg comment in
// opoi.h): PROMPT is always the REQUEST's own requester; SHARD_ASSIGN (F15-H
// fast-follow) must be an accepted coordinator for this requestId
// (IsClaimedCoordinator — a request can have several by design, VRF
// redundancy, so this isn't derivable from the requestId alone); SHARD_RESULT
// (the assigned miner's reply, carrying the computed tensor back) must be an
// ACTIVE staker. The REQUEST must still be PENDING either way — no
// requestId, wrong/unauthorized signer, or already-resolved request means
// this is dropped before ever being stored or relayed, the same way
// CheckOPoITransaction already validates RESPONSE/CHALLENGE signatures.
bool ProcessOPoIDataMessage(const COPoIDataMsg& msg, std::string& reason)
{
    if (msg.destStakeAddress.empty() || msg.requestId.empty()) {
        reason = "missing-fields";
        return false;
    }
    if (msg.payloadHex.size() > OPOI_DELIVERY_MAX_PAYLOAD_HEX) {
        reason = "payload-too-large";
        return false;
    }

    OPoIRequest req;
    if (!g_opoiCache.GetRequest(msg.requestId, req)) {
        reason = "unknown-request";
        return false;
    }
    if (!req.IsPending()) {
        reason = "request-not-pending";
        return false;
    }

    std::string expectedSigner;
    switch (msg.kind) {
    case OPOI_DELIVERY_PROMPT:
        expectedSigner = req.requester;
        break;
    case OPOI_DELIVERY_SHARD_ASSIGN:
        if (msg.senderAddress.empty() || !g_opoiCache.IsClaimedCoordinator(msg.requestId, msg.senderAddress)) {
            reason = "not-a-coordinator";
            return false;
        }
        expectedSigner = msg.senderAddress;
        break;
    case OPOI_DELIVERY_SHARD_RESULT:
        if (msg.senderAddress.empty() || !g_opoiCache.IsActiveStaker(msg.senderAddress)) {
            reason = "not-an-active-staker";
            return false;
        }
        expectedSigner = msg.senderAddress;
        break;
    default:
        reason = "bad-kind";
        return false;
    }

    std::string sigMsg = std::string("OPOIDATA") + msg.requestId + msg.destStakeAddress
                        + strprintf("%u", msg.kind) + msg.senderAddress + msg.payloadHex;
    if (!VerifyOPoISig(expectedSigner, sigMsg, msg.sig)) {
        reason = "bad-sig";
        return false;
    }

    PendingDelivery d;
    d.requestId     = msg.requestId;
    d.kind          = msg.kind;
    d.payloadHex    = msg.payloadHex;
    d.sigTime       = msg.sigTime;
    d.senderAddress = msg.senderAddress;
    g_opoiCache.AddPendingDelivery(msg.destStakeAddress, d);
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
            if (tx.opoiResponsePhase == 0) {
                // F10-B: undo COMMIT — remove the pending commitment as if it
                // never happened. Necessary for reorg correctness: without
                // this, a fork whose split point falls between this COMMIT
                // and its REVEAL would leave a stale commit record that no
                // longer corresponds to any transaction on the active chain.
                std::string key = tx.opoiRequestId + ":" + tx.opoiMinerAddress;
                g_opoiCache.mapResponseCommits.erase(key);
                auto it = g_opoiCache.mapRequests.find(tx.opoiRequestId);
                if (it != g_opoiCache.mapRequests.end())
                    it->second.responseCommits.erase(tx.opoiMinerAddress);
            } else {
                g_opoiCache.mapResponses.erase(tx.opoiRequestId);
                auto it = g_opoiCache.mapRequests.find(tx.opoiRequestId);
                if (it != g_opoiCache.mapRequests.end()) {
                    it->second.status = OPOI_STATUS_PENDING;
                    it->second.responseReveals.erase(tx.opoiMinerAddress); // F10-B
                }
                // F14-C: undo "paid" bookkeeping for a VERIFIABLE response too (mirrors
                // UnmarkShardPaid below) — if this reconnects differently, it must be
                // payable again.
                g_opoiCache.UnmarkResponsePaid(tx.opoiRequestId);
                // F10-C: reverse the reputation counter this REVEAL's apply bumped —
                // a pre-existing gap (F10-C never added this) that matters more now
                // that F10-B relies on the same undo branch being split by phase.
                auto stakeIt = g_opoiCache.mapStakes.find(tx.opoiMinerAddress);
                if (stakeIt != g_opoiCache.mapStakes.end() && stakeIt->second.responsesTotal > 0)
                    --stakeIt->second.responsesTotal;
            }

        } else if (tx.nType == OPOI_STAKE_TX_TYPE) {
            g_opoiCache.mapStakes.erase(tx.opoiMinerAddress);
            g_opoiCache.UnlockUTXO(tx.opoiCollateralIn); // release lock on undo

        } else if (tx.nType == OPOI_UNSTAKE_TX_TYPE) {
            // Revert unstake: restore to ACTIVE
            auto it = g_opoiCache.mapStakes.find(tx.opoiMinerAddress);
            if (it != g_opoiCache.mapStakes.end()) {
                it->second.stakeStatus   = OPOI_STAKE_ACTIVE;
                it->second.unstakeHeight = 0;
                it->second.unstakeTxHash.SetNull();
            }

        } else if (tx.nType == OPOI_CHALLENGE_TX_TYPE) {
            if (tx.opoiChallengePhase == 0) {
                // Undo COMMIT: the challenge never existed before this tx.
                g_opoiCache.UnlockUTXO(tx.opoiChallengerCollateralIn);
                g_opoiCache.mapChallenges.erase(tx.opoiRequestId);
            } else {
                // Undo REVEAL: reverse whatever resolution it produced, then
                // roll the challenge back to its pre-reveal (OPEN/COMMIT) state.
                auto it = g_opoiCache.mapChallenges.find(tx.opoiRequestId);
                if (it != g_opoiCache.mapChallenges.end()) {
                    OPoIChallenge& ch = it->second;
                    if (ch.challengeStatus == OPOI_CHALLENGE_SLASHED) {
                        // Reverse the immediate miner slash + collateral unlock.
                        auto respIt = g_opoiCache.mapResponses.find(tx.opoiRequestId);
                        if (respIt != g_opoiCache.mapResponses.end()) {
                            auto stakeIt = g_opoiCache.mapStakes.find(respIt->second.minerAddress);
                            if (stakeIt != g_opoiCache.mapStakes.end())
                                stakeIt->second.stakeStatus = OPOI_STAKE_ACTIVE;
                        }
                        g_opoiCache.LockUTXO(ch.challengerCollateral, ch.challengerAddress, ch.txHash);
                        g_opoiCache.UnmarkChallengerRewardPaid(tx.opoiRequestId);
                    } else if (ch.challengeStatus == OPOI_CHALLENGE_RESOLVED_NO_ORACLE) {
                        // Reverse the "no fault" collateral release.
                        g_opoiCache.LockUTXO(ch.challengerCollateral, ch.challengerAddress, ch.txHash);
                    }
                    // EXPIRED-via-PASS and REVEALED_PENDING never touched any lock —
                    // nothing to reverse there beyond the field resets below.
                    ch.phase = 0;
                    ch.fraudProof.clear();
                    ch.challengeStatus = OPOI_CHALLENGE_OPEN;
                }
            }

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
            // F16: undo the block that resolved this shard's payment too —
            // removing a submission can drop it back below majority, and the
            // coinbase that paid it is itself being disconnected right now.
            g_opoiCache.UnmarkShardPaid(tx.opoiRequestId, tx.opoiShardIndex);

        } else if (tx.nType == OPOI_AUDITOR_VERIFY_TX_TYPE) {
            auto it = g_opoiCache.mapAuditorVerifications.find(tx.opoiRequestId);
            if (it != g_opoiCache.mapAuditorVerifications.end()) {
                auto& verifs = it->second;
                verifs.erase(std::remove_if(verifs.begin(), verifs.end(),
                    [&](const AuditorVerification& v) { return v.auditorAddress == tx.opoiAuditorAddress; }),
                    verifs.end());
            }
            // Release the lock this vote applied. NOTE (known v1 gap, same class
            // already accepted for CHALLENGE slashing — see ProcessExpiredChallenges):
            // if this vote had already been resolved as the SLASHED minority,
            // this incorrectly unlocks collateral that was meant to stay burned
            // forever. Only matters for a reorg deep enough to disconnect past a
            // resolved verification — not handled in v1.
            g_opoiCache.UnlockUTXO(tx.opoiAuditorCollateralIn);
            g_opoiCache.UnmarkAuditorResolved(tx.opoiRequestId);
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
        req.testSuite   = tx.opoiTestSuite; // F14-B/C — was never copied before this fix
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
        // F10-C: reputation tracking — count this responder's completed RESPONSE.
        {
            auto stakeIt = g_opoiCache.mapStakes.find(tx.opoiMinerAddress);
            if (stakeIt != g_opoiCache.mapStakes.end())
                ++stakeIt->second.responsesTotal;
        }
        // F10-B: record the reveal against the REQUEST (visibility only — REVEAL
        // validity itself is decided in CheckOPoITransaction before this ever runs).
        {
            auto reqIt = g_opoiCache.mapRequests.find(tx.opoiRequestId);
            if (reqIt != g_opoiCache.mapRequests.end())
                reqIt->second.responseReveals[tx.opoiMinerAddress] = tx.opoiResponseHash.GetHex();
        }
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
        stake.endpoint = tx.opoiEndpoint; // F15-H
        stake.blockHeight   = blockHeight;
        stake.sigTime       = tx.opoiSigTime;
        stake.txHash        = tx.GetHash();
        stake.stakeStatus   = OPOI_STAKE_ACTIVE;
        stake.unstakeHeight = 0;
        // Bug fix (2026-07): OPoIStake has no default member initializers, so a
        // plain `OPoIStake stake;` leaves every POD field not assigned above as
        // indeterminate stack garbage — not zero. These four were always left
        // uninitialized (a real, pre-existing bug), invisible until now because
        // nothing ever read them (F9-E renewal, F9-F canary, F10-C reputation
        // were all dead code). F10-C's new increments (++stakeIt->second.responsesTotal
        // etc.) add 1 to garbage and stay garbage, which is exactly what surfaced
        // this while testing F10-C.
        stake.lastRenewalHeight    = 0;
        stake.responsesTotal       = 0;
        stake.responsesChallenged  = 0;
        stake.responsesSlashed     = 0;
        stake.canaryStrikes        = 0;
        // F10-D: recover the signer's pubkey so VRF eligibility can be verified later.
        // (Same sigMsg formula CheckOPoITransaction uses to verify this STAKE's signature.)
        {
            std::string sigMsg = tx.opoiMinerAddress + tx.opoiCollateralIn.hash.GetHex()
                               + strprintf("%u", tx.opoiCollateralIn.n);
            VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig, &stake.minerPubKey);
        }
        g_opoiCache.AddStake(stake);
        g_opoiCache.LockUTXO(tx.opoiCollateralIn, tx.opoiMinerAddress, tx.GetHash()); // lock collateral
        LogPrintf("OPoI: STAKE by %s (%.4f CS) at height %u — collateral %s:%u locked\n",
                  tx.opoiMinerAddress, (double)tx.opoiPayment / COIN, blockHeight,
                  tx.opoiCollateralIn.hash.GetHex(), tx.opoiCollateralIn.n);

    } else if (tx.nType == OPOI_UNSTAKE_TX_TYPE) {
        if (g_opoiCache.StartUnstake(tx.opoiMinerAddress, blockHeight, tx.GetHash()))
            LogPrintf("OPoI: UNSTAKE requested by %s at height %u\n",
                      tx.opoiMinerAddress, blockHeight);

    } else if (tx.nType == OPOI_CHALLENGE_TX_TYPE && tx.opoiChallengePhase == 0) {
        // COMMIT — open the challenge and lock the challenger's collateral.
        OPoIChallenge ch;
        ch.requestId           = tx.opoiRequestId;
        ch.challengerAddress   = tx.opoiRequester;
        ch.challengerCollateral= tx.opoiChallengerCollateralIn;
        ch.phase                = 0;
        ch.commitHash           = HexStr(tx.opoiCommitHash);
        ch.commitHeight         = blockHeight;
        ch.blockHeight          = blockHeight;
        ch.sigTime              = tx.opoiSigTime;
        ch.txHash               = tx.GetHash();
        ch.challengeStatus      = OPOI_CHALLENGE_OPEN;
        g_opoiCache.AddChallenge(ch);
        g_opoiCache.LockUTXO(tx.opoiChallengerCollateralIn, tx.opoiRequester, tx.GetHash());
        // F10-C: reputation tracking — count a CHALLENGE opened against the
        // responder of this requestId (if a RESPONSE is even cached yet).
        {
            auto respIt = g_opoiCache.mapResponses.find(tx.opoiRequestId);
            if (respIt != g_opoiCache.mapResponses.end()) {
                auto stakeIt = g_opoiCache.mapStakes.find(respIt->second.minerAddress);
                if (stakeIt != g_opoiCache.mapStakes.end())
                    ++stakeIt->second.responsesChallenged;
            }
        }
        LogPrintf("OPoI: CHALLENGE COMMIT for request %s by %s at height %u — collateral %s:%u locked\n",
                  tx.opoiRequestId, tx.opoiRequester, blockHeight,
                  tx.opoiChallengerCollateralIn.hash.GetHex(), tx.opoiChallengerCollateralIn.n);

    } else if (tx.nType == OPOI_CHALLENGE_TX_TYPE) {
        // REVEAL — verify already done in CheckOPoITransaction; here we record
        // the disclosed proof and attempt immediate resolution. For VERIFIABLE
        // tasks the real fraud oracle is the Auditor majority (F14-C) — a
        // matching commitment can never prove inference fraud by itself (a
        // dishonest miner's own commitment always matches their own garbage
        // output), it only proves the challenger's claim hasn't changed since
        // COMMIT. For OPEN tasks there is no on-chain fraud oracle yet (that's
        // F10-C reputation, not built) — the reveal is accepted but resolves
        // to "no fault either side", matching the plan's own guidance.
        auto it = g_opoiCache.mapChallenges.find(tx.opoiRequestId);
        if (it != g_opoiCache.mapChallenges.end()) {
            OPoIChallenge& ch = it->second;
            ch.phase       = 1;
            ch.fraudProof  = tx.opoiProofData;

            OPoIRequest req;
            bool haveReq = g_opoiCache.GetRequest(tx.opoiRequestId, req);
            if (haveReq && req.IsVerifiable() && pparams) {
                int majority = g_opoiCache.GetAuditorMajorityResult(tx.opoiRequestId, pparams->nOPoIMinAuditors);
                if (majority == AUDITOR_VERIFY_FAIL) {
                    auto respIt = g_opoiCache.mapResponses.find(tx.opoiRequestId);
                    if (respIt != g_opoiCache.mapResponses.end()) {
                        auto stakeIt = g_opoiCache.mapStakes.find(respIt->second.minerAddress);
                        if (stakeIt != g_opoiCache.mapStakes.end() && stakeIt->second.IsActive()) {
                            stakeIt->second.stakeStatus = OPOI_STAKE_SLASHED;
                            ++stakeIt->second.responsesSlashed; // F10-C
                        }
                    }
                    g_opoiCache.UnlockUTXO(ch.challengerCollateral);
                    ch.challengeStatus = OPOI_CHALLENGE_SLASHED;
                    LogPrintf("OPoI: CHALLENGE proven for request %s — miner slashed, challenger %s vindicated\n",
                              tx.opoiRequestId, tx.opoiRequester);
                } else if (majority == AUDITOR_VERIFY_PASS) {
                    // Auditor already validated the response — this challenge
                    // couldn't substantiate fraud. Challenger's collateral stays
                    // locked forever (burned), same treatment as a SLASHED
                    // Auditor minority — no separate reward is minted.
                    ch.challengeStatus = OPOI_CHALLENGE_EXPIRED;
                    LogPrintf("OPoI: CHALLENGE dismissed for request %s — Auditor majority PASS, "
                              "challenger %s collateral %s:%u permanently locked\n",
                              tx.opoiRequestId, tx.opoiRequester,
                              ch.challengerCollateral.hash.GetHex(), ch.challengerCollateral.n);
                } else {
                    // Auditor hasn't reached quorum yet — re-checked every block
                    // by ProcessExpiredChallenges until it resolves.
                    ch.challengeStatus = OPOI_CHALLENGE_REVEALED_PENDING;
                }
            } else {
                // OPEN task (or unknown request during VerifyDB replay): no
                // fraud oracle exists — resolve as "no fault", return collateral.
                g_opoiCache.UnlockUTXO(ch.challengerCollateral);
                ch.challengeStatus = OPOI_CHALLENGE_RESOLVED_NO_ORACLE;
            }
            LogPrintf("OPoI: CHALLENGE REVEAL for request %s by %s at height %u\n",
                      tx.opoiRequestId, tx.opoiRequester, blockHeight);
        }

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
        sub.tokenCount         = tx.opoiTokenCount;
        sub.blockHeight        = blockHeight;
        sub.txHash             = tx.GetHash();
        g_opoiCache.AddShardResult(tx.opoiRequestId, tx.opoiShardIndex, sub);
        LogPrintf("OPoI: SHARD_RESULT for %s shard %u by %s (hash=%s) at height %u\n",
                  tx.opoiRequestId, tx.opoiShardIndex, tx.opoiMinerAddress,
                  tx.opoiResponseHash.GetHex(), blockHeight);

    } else if (tx.nType == OPOI_AUDITOR_VERIFY_TX_TYPE) {
        AuditorVerification fv;
        fv.requestId       = tx.opoiRequestId;
        fv.auditorAddress  = tx.opoiAuditorAddress;
        fv.result          = tx.opoiAuditorVerifyResult;
        fv.auditorCollateral = tx.opoiAuditorCollateralIn;
        fv.blockHeight     = blockHeight;
        fv.txHash          = tx.GetHash();
        fv.status          = OPOI_AUDITOR_STATUS_PENDING;
        g_opoiCache.AddAuditorVerification(fv); // also locks the collateral
        LogPrintf("OPoI: AUDITOR_VERIFY for %s by %s (result=%d) at height %u\n",
                  tx.opoiRequestId, tx.opoiAuditorAddress, (int)tx.opoiAuditorVerifyResult, blockHeight);
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
                ProcessResponseCommitWindows((uint32_t)pindex->nHeight, params);
                ProcessModelVotingWindows((uint32_t)pindex->nHeight, params);
                ProcessShardPayments(block.vtx, params);
                ProcessVerifiableResponsePayments(block.vtx, params);
                ProcessAuditorVerifications((uint32_t)pindex->nHeight, params);
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
// Called from ConnectBlock at the end of each block.
//
// F10-A/F8-C (2026-07-05): rewritten. Previously ANY open challenge — proof or
// not — slashed the miner on a bare timeout, a free griefing vector (a
// malicious challenger with nothing at stake could slash any miner just by
// waiting). Now:
//   - A COMMIT that never gets a valid REVEAL within
//     nOPoIChallengeCommitRevealBlocks is dismissed: the CHALLENGER's own
//     collateral is what gets burned (locked forever), not the miner's stake.
//   - A REVEAL that resolved immediately (ProcessOPoITransaction, VERIFIABLE
//     with an already-decided Auditor majority, or OPEN with no oracle) never
//     reaches this function in the OPEN state — nothing to do here for it.
//   - A REVEAL for a VERIFIABLE task whose Auditor majority wasn't decided yet
//     at reveal time (OPOI_CHALLENGE_REVEALED_PENDING) is re-checked here on
//     every block until the Auditor resolves.

void ProcessExpiredChallenges(uint32_t blockHeight, const Consensus::Params& params)
{
    LOCK(g_opoiCache.cs);
    for (auto& kv : g_opoiCache.mapChallenges) {
        OPoIChallenge& ch = kv.second;

        if (ch.IsOpen()) {
            // Still COMMIT-only — dismiss if REVEAL never showed up in time.
            if ((int)(blockHeight - ch.commitHeight) < params.nOPoIChallengeCommitRevealBlocks) continue;
            ch.challengeStatus = OPOI_CHALLENGE_EXPIRED; // challenger's collateral stays locked forever
            LogPrintf("OPoI: CHALLENGE dismissed for request %s — no REVEAL within %d blocks — "
                      "challenger %s collateral %s:%u permanently locked\n",
                      ch.requestId, params.nOPoIChallengeCommitRevealBlocks, ch.challengerAddress,
                      ch.challengerCollateral.hash.GetHex(), ch.challengerCollateral.n);
            continue;
        }

        if (ch.IsPendingResolution()) {
            int majority = g_opoiCache.GetAuditorMajorityResult(ch.requestId, params.nOPoIMinAuditors);
            if (majority == AUDITOR_VERIFY_FAIL) {
                auto respIt = g_opoiCache.mapResponses.find(ch.requestId);
                if (respIt != g_opoiCache.mapResponses.end()) {
                    auto stakeIt = g_opoiCache.mapStakes.find(respIt->second.minerAddress);
                    if (stakeIt != g_opoiCache.mapStakes.end() && stakeIt->second.IsActive()) {
                        stakeIt->second.stakeStatus = OPOI_STAKE_SLASHED;
                        ++stakeIt->second.responsesSlashed; // F10-C
                    }
                }
                g_opoiCache.UnlockUTXO(ch.challengerCollateral);
                ch.challengeStatus = OPOI_CHALLENGE_SLASHED;
                LogPrintf("OPoI: CHALLENGE proven for request %s (Auditor resolved after reveal) — "
                          "miner slashed, challenger %s vindicated\n", ch.requestId, ch.challengerAddress);
            } else if (majority == AUDITOR_VERIFY_PASS) {
                ch.challengeStatus = OPOI_CHALLENGE_EXPIRED;
                LogPrintf("OPoI: CHALLENGE dismissed for request %s (Auditor resolved PASS after reveal) — "
                          "challenger %s collateral %s:%u permanently locked\n",
                          ch.requestId, ch.challengerAddress,
                          ch.challengerCollateral.hash.GetHex(), ch.challengerCollateral.n);
            }
            // else: Auditor still hasn't reached quorum — keep waiting.
        }
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

// ── ProcessResponseCommitWindows (F10-B) ──────────────────────────────────────
//
// Called from ConnectBlock (and RebuildOPoICache replay). Flips a REQUEST's
// commitWindowClosed flag once nOPoIResponseCommitWindowBlocks have passed
// since it confirmed. CheckOPoITransaction reads this flag instead of ever
// computing "current height" itself — every REQUEST closes its commit phase
// at the same height for every miner, which is the actual anti-copy property:
// no REVEAL is ever valid while the flag is still false, so there is no
// public answer yet for a copier to steal while commits are still open.
//
// Like ProcessExpiredRequests/ProcessExpiredChallenges, this is one-directional
// (not reversed on reorg) — a deep-enough disconnect past the closing height
// leaves the flag set even though the chain no longer confirms it; same
// accepted v1 gap already noted elsewhere for challenge/auditor state.

void ProcessResponseCommitWindows(uint32_t blockHeight, const Consensus::Params& params)
{
    if (params.nOPoIResponseCommitWindowBlocks <= 0) return;
    LOCK(g_opoiCache.cs);
    for (auto& kv : g_opoiCache.mapRequests) {
        OPoIRequest& req = kv.second;
        if (req.commitWindowClosed) continue;
        if ((uint32_t)(blockHeight - req.blockHeight) < (uint32_t)params.nOPoIResponseCommitWindowBlocks) continue;
        req.commitWindowClosed = true;
        LogPrint("opoi", "OPoI: RESPONSE commit window closed for %s at height %u\n",
                 req.requestId, blockHeight);
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
        // F14-B: VERIFIABLE tasks (code/math/SQL) are checked by an Auditor against a
        // test suite (F14-C) — without a test suite hash there is nothing to check.
        if (tx.opoiTaskType == OPOI_TASK_VERIFIABLE && tx.opoiTestSuite.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): VERIFIABLE REQUEST missing testSuite"),
                             REJECT_INVALID, "bad-txns-opoi-request-verifiable-needs-test-suite");
        // F15-G: if opoiModel names an ACTIVE Model Manifest whose dense pipeline is
        // deeper than nOPoIMaxPipelineDepth, an INTERACTIVE request cannot use it —
        // commit-reveal adds +1 block per sequential shard, so a deep pipeline would
        // blow past any reasonable interactive latency budget. BATCH has no such limit.
        // MoE/HYBRID manifests are excluded: BuildModelExecutionGraph always gives
        // them exactly one real shard now (whole-model per miner, see opoi_shard.h),
        // so numDenseShards no longer reflects the real pipeline depth for them —
        // gating on it here would reject MoE INTERACTIVE requests for a chain length
        // (numDenseShards) that isn't actually executed.
        if (!fIsVerifying) {
            ModelManifest manifest;
            if (g_opoiCache.GetModelManifest(tx.opoiModel, manifest) && manifest.IsActive()
                && !manifest.IsMoE()
                && tx.opoiTaskClass == OPOI_TASKCLASS_INTERACTIVE
                && (int)manifest.numDenseShards > Params().GetConsensus().nOPoIMaxPipelineDepth)
                return state.DoS(10, error("CheckOPoITransaction(): REQUEST model %s pipeline too deep "
                                           "(%u dense shards) for INTERACTIVE — use BATCH",
                                           manifest.modelId, manifest.numDenseShards),
                                 REJECT_INVALID, "bad-txns-opoi-request-pipeline-too-deep-for-interactive");
            // F9-D: a Model Manifest can declare a minimum per-token reward it
            // requires (minRewardPerToken) — a REQUEST offering less than that
            // floor would never attract an honest staker for this model, and
            // undercuts the price other requesters already agreed to respect.
            if (g_opoiCache.GetModelManifest(tx.opoiModel, manifest) && manifest.IsActive()
                && manifest.minRewardPerToken > 0 && tx.opoiFeePerToken < manifest.minRewardPerToken)
                return state.DoS(10, error("CheckOPoITransaction(): REQUEST feePerToken %s below model %s "
                                           "minimum %s",
                                           FormatMoney(tx.opoiFeePerToken), manifest.modelId,
                                           FormatMoney(manifest.minRewardPerToken)),
                                 REJECT_INVALID, "bad-txns-opoi-request-fee-below-model-minimum");
        }
        // Verify requester's signature. Bug fix (2026-07-02): this previously omitted
        // feePerToken and taskType from the signed message (a mismatch with what
        // submitopoirequest actually signs — see rpc/opoi.cpp), so every REQUEST
        // submitted via that RPC failed signature verification unconditionally.
        {
            std::string sigMsg = tx.opoiRequestId + tx.opoiRequester + tx.opoiModel
                               + tx.opoiPromptHash.GetHex()
                               + strprintf("%u%d%d%d%d", tx.opoiMaxTokens, tx.opoiPayment,
                                           tx.opoiFeePerToken, (int)tx.opoiTaskType, (int)tx.opoiTaskClass)
                               + tx.opoiTestSuite.GetHex();
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
        // Phase 6: reject RESPONSE for an expired REQUEST. req/haveReq are also
        // used below by the F10-B commit-reveal window checks in both phases.
        OPoIRequest req;
        bool haveReq = !fIsVerifying && g_opoiCache.GetRequest(tx.opoiRequestId, req);
        if (!fIsVerifying) {
            if (haveReq && req.IsExpired())
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE for expired REQUEST %s",
                                            tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-request-expired");
            // F9-C: the responder's staked model must match the REQUEST's model —
            // a miner staked for GEMMA_3_4B has no business answering a request
            // that specifically asked for QWEN25_1_5B (different weights, different
            // inference result entirely). Only enforced when both sides of the
            // comparison are known; an empty req.model means the REQUEST itself
            // wasn't found in cache (e.g. VerifyDB replay ordering) — nothing to
            // compare against, so let the existing REQUEST-side checks be authoritative.
            OPoIStake stake;
            if (haveReq && !req.model.empty() && g_opoiCache.GetStake(tx.opoiMinerAddress, stake)
                && !stake.modelId.empty() && stake.modelId != req.model)
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE miner %s staked for model %s, "
                                           "REQUEST %s asked for model %s",
                                           tx.opoiMinerAddress, stake.modelId, tx.opoiRequestId, req.model),
                                 REJECT_INVALID, "bad-txns-opoi-response-model-mismatch");
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
            // COMMIT phase — hides the response content behind a hash until the
            // commit window closes for everyone at once (see below), which is the
            // actual anti-copy property: no REVEAL is ever public while COMMITs
            // for this REQUEST are still being accepted.
            if (tx.opoiResponseCommitHash.size() != 32)
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE COMMIT missing commit hash"),
                                 REJECT_INVALID, "bad-txns-opoi-response-no-commit-hash");
            if (!fIsVerifying && haveReq && req.commitWindowClosed)
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE COMMIT for %s arrived after "
                                           "the commit window closed", tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-response-commit-window-closed");
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

        // F10-B: the commit window must have closed before ANY reveal is accepted
        // — this, not the hash check below, is what actually blocks copying: since
        // no REVEAL can become public while the window is still open, there is
        // never an already-revealed answer for a copier to steal while honest
        // miners are still deciding what to commit to.
        if (!fIsVerifying) {
            if (!haveReq || !req.commitWindowClosed)
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE REVEAL for %s arrived before "
                                           "the commit window closed", tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-response-reveal-too-early");

            // Bug fix (2026-07-05): without this, a miner who already revealed
            // (and got paid) for this requestId can broadcast a SECOND, distinct
            // REVEAL tx — same requestId/minerAddress/responseHash/commitment/
            // tokenCount/nonce, so it still matches the one stored COMMIT (never
            // erased) and passes every check below unchanged, but a different txid
            // (e.g. different sigTime) — and it gets accepted as a brand-new valid
            // REVEAL, paying the same miner for the same requestId a second time.
            // Confirmed live: after a REVEAL was mined and paid, resubmitting via
            // submitopoiresponse with the same params produced a different txid and
            // was accepted right up to this point before this fix existed. Simple
            // reorg-then-remine of the *same* tx is not this bug — undo already
            // clears this exact map entry, so re-mining it is a legitimate redo, not
            // a duplicate. req.responseReveals is keyed by minerAddress, so an
            // existing entry here can only mean this miner already revealed for
            // this request before — and since only that miner's own key can ever
            // produce a signature this check's caller (VerifyOPoISig below) will
            // accept for them, there is no genuine-conflict case to preserve here,
            // unlike the STAKE/UNSTAKE/CHALLENGE UTXO-lock redeliveries.
            if (haveReq && req.responseReveals.count(tx.opoiMinerAddress))
                return state.Invalid(error("CheckOPoITransaction(): RESPONSE REVEAL for %s by %s already known",
                                           tx.opoiRequestId, tx.opoiMinerAddress),
                                     REJECT_DUPLICATE, "bad-txns-opoi-response-reveal-already-known");

            std::string committedHash;
            if (!g_opoiCache.GetResponseCommit(tx.opoiRequestId, tx.opoiMinerAddress, committedHash))
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE REVEAL for %s by %s with no "
                                           "prior COMMIT", tx.opoiRequestId, tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-response-no-commit");
            if (tx.opoiResponseNonce.empty())
                return state.DoS(10, error("CheckOPoITransaction(): RESPONSE REVEAL missing nonce"),
                                 REJECT_INVALID, "bad-txns-opoi-response-no-nonce");

            unsigned char computed[32];
            {
                CSHA256 hasher;
                hasher.Write(tx.opoiResponseHash.begin(), 32);
                hasher.Write(tx.opoiCommitment.begin(), 32);
                std::string tokenStr = strprintf("%u", tx.opoiTokenCount);
                hasher.Write((const unsigned char*)tokenStr.data(), tokenStr.size());
                hasher.Write(tx.opoiResponseNonce.data(), tx.opoiResponseNonce.size());
                hasher.Finalize(computed);
            }
            if (committedHash != HexStr(computed, computed + 32))
                return state.DoS(100, error("CheckOPoITransaction(): RESPONSE REVEAL for %s by %s does not "
                                            "match its COMMIT", tx.opoiRequestId, tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-response-commit-mismatch");
        }

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
        if (!fIsVerifying && g_opoiCache.IsLockedUTXO(tx.opoiCollateralIn)) {
            if (IsHarmlessRedelivery(tx.opoiCollateralIn, tx.GetHash()))
                return state.Invalid(error("CheckOPoITransaction(): STAKE %s already known",
                                           tx.GetHash().GetHex()),
                                     REJECT_DUPLICATE, "bad-txns-opoi-stake-already-known");
            return state.DoS(100, error("CheckOPoITransaction(): STAKE collateral %s:%u already locked",
                                        tx.opoiCollateralIn.hash.GetHex(), tx.opoiCollateralIn.n),
                             REJECT_INVALID, "bad-txns-opoi-stake-collateral-locked");
        }
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
        if (!fIsVerifying && !g_opoiCache.IsActiveStaker(tx.opoiMinerAddress)) {
            if (g_opoiCache.IsHarmlessUnstakeRedelivery(tx.opoiMinerAddress, tx.GetHash()))
                return state.Invalid(error("CheckOPoITransaction(): UNSTAKE %s already known",
                                           tx.GetHash().GetHex()),
                                     REJECT_DUPLICATE, "bad-txns-opoi-unstake-already-known");
            return state.DoS(100, error("CheckOPoITransaction(): UNSTAKE from non-active staker %s",
                                       tx.opoiMinerAddress),
                             REJECT_INVALID, "bad-txns-opoi-unstake-not-staked");
        }
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
        // F8-C/F10-A: two-phase commit-reveal challenge with mandatory challenger
        // collateral. COMMIT posts collateral + a hash of the (not-yet-disclosed)
        // fraud proof; REVEAL discloses the proof + nonce and must match. A
        // challenge that never reaches a valid REVEAL in time is dismissed —
        // ProcessExpiredChallenges slashes the CHALLENGER's collateral, not the
        // miner's stake (fixes a free-griefing hole: previously ANY challenge,
        // proof or not, slashed the miner on a bare timeout).
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-request-id");
        if (tx.opoiRequester.empty())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing challenger"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-challenger");
        if (tx.opoiChallengerCollateralIn.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing collateralIn"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-collateral");
        if (!fIsVerifying) {
            OPoIResponse resp;
            if (!g_opoiCache.GetResponse(tx.opoiRequestId, resp))
                return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE for unknown response %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-challenge-unknown-response");
        }

        if (tx.opoiChallengePhase == 0) {
            // ── COMMIT ──
            if (tx.opoiCommitHash.size() != 32)
                return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE COMMIT missing commit hash"),
                                 REJECT_INVALID, "bad-txns-opoi-challenge-no-commit-hash");
            if (!fIsVerifying) {
                if (g_opoiCache.IsLockedUTXO(tx.opoiChallengerCollateralIn)) {
                    if (IsHarmlessRedelivery(tx.opoiChallengerCollateralIn, tx.GetHash()))
                        return state.Invalid(error("CheckOPoITransaction(): CHALLENGE COMMIT %s already known",
                                                   tx.GetHash().GetHex()),
                                             REJECT_DUPLICATE, "bad-txns-opoi-challenge-already-known");
                    return state.DoS(100, error("CheckOPoITransaction(): CHALLENGE collateral %s:%u already locked",
                                                tx.opoiChallengerCollateralIn.hash.GetHex(),
                                                tx.opoiChallengerCollateralIn.n),
                                     REJECT_INVALID, "bad-txns-opoi-challenge-collateral-locked");
                }
                OPoIChallenge existing;
                if (g_opoiCache.GetChallenge(tx.opoiRequestId, existing) && existing.IsOpen())
                    return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE already open for request %s",
                                               tx.opoiRequestId),
                                     REJECT_INVALID, "bad-txns-opoi-challenge-already-open");
            }
            std::string sigMsg = tx.opoiRequestId + tx.opoiRequester + HexStr(tx.opoiCommitHash)
                               + tx.opoiChallengerCollateralIn.hash.GetHex()
                               + strprintf("%u", tx.opoiChallengerCollateralIn.n);
            if (!VerifyOPoISig(tx.opoiRequester, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): CHALLENGE COMMIT invalid signature for %s",
                                            tx.opoiRequester),
                                 REJECT_INVALID, "bad-txns-opoi-challenge-bad-sig");
        } else {
            // ── REVEAL ──
            if (tx.opoiProofData.empty() || tx.opoiChallengeNonce.empty())
                return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE REVEAL missing proof/nonce"),
                                 REJECT_INVALID, "bad-txns-opoi-challenge-no-reveal-data");
            if (!fIsVerifying) {
                OPoIChallenge existing;
                if (!g_opoiCache.GetChallenge(tx.opoiRequestId, existing) || !existing.IsOpen())
                    return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE REVEAL with no open COMMIT for %s",
                                               tx.opoiRequestId),
                                     REJECT_INVALID, "bad-txns-opoi-challenge-no-open-commit");
                if (existing.challengerAddress != tx.opoiRequester)
                    return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE REVEAL challenger mismatch for %s",
                                               tx.opoiRequestId),
                                     REJECT_INVALID, "bad-txns-opoi-challenge-challenger-mismatch");
                unsigned char computed[32];
                {
                    CSHA256 hasher;
                    hasher.Write(tx.opoiProofData.data(), tx.opoiProofData.size());
                    hasher.Write(tx.opoiChallengeNonce.data(), tx.opoiChallengeNonce.size());
                    hasher.Finalize(computed);
                }
                if (existing.commitHash != HexStr(computed, computed + 32))
                    return state.DoS(100, error("CheckOPoITransaction(): CHALLENGE REVEAL hash mismatch for %s",
                                                tx.opoiRequestId),
                                     REJECT_INVALID, "bad-txns-opoi-challenge-reveal-mismatch");
            }
            std::string sigMsg = tx.opoiRequestId + tx.opoiRequester
                               + HexStr(tx.opoiProofData) + HexStr(tx.opoiChallengeNonce);
            if (!VerifyOPoISig(tx.opoiRequester, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): CHALLENGE REVEAL invalid signature for %s",
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

                    // F15-H (real routing, first slice): hosting the expert is necessary
                    // but not sufficient — it must also have been SELECTED for this
                    // request's token by the (placeholder) router. Without this, any
                    // miner hosting any expert could submit for a shard the router never
                    // routed to, defeating the entire point of MoE (only topK experts of
                    // numExperts should ever do work for a given request).
                    auto selected = SelectTopKExperts(tx.opoiRequestId, req.promptHash,
                                                       manifest.numExperts, manifest.topKExperts);
                    if (std::find(selected.begin(), selected.end(), d.expertId) == selected.end())
                        return state.DoS(10, error("CheckOPoITransaction(): SHARD_RESULT expert %u not selected "
                                                   "by router for request %s", d.expertId, tx.opoiRequestId),
                                         REJECT_INVALID, "bad-txns-opoi-shard-expert-not-selected");
                }
            }
        }
        // Verify submitter's signature. F16: covers tokenCount too — it directly
        // drives the per-token fee component of shard payments, same reasoning
        // as the RESPONSE sigMsg bug fix (see comment there).
        {
            std::string sigMsg = std::string("SHARD") + tx.opoiRequestId + strprintf("%u", tx.opoiShardIndex)
                                + tx.opoiMinerAddress + tx.opoiResponseHash.GetHex() + tx.opoiCommitment.GetHex()
                                + strprintf("%u", tx.opoiTokenCount);
            if (!VerifyOPoISig(tx.opoiMinerAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): SHARD_RESULT invalid signature for %s",
                                            tx.opoiMinerAddress),
                                 REJECT_INVALID, "bad-txns-opoi-shard-bad-sig");
        }
        break;
    }

    case OPOI_AUDITOR_VERIFY_TX_TYPE: {
        // F14-C: Auditor verifies a VERIFIABLE-task RESPONSE against the REQUEST's
        // test suite (sandbox execution is off-chain, F14-E — this only records the
        // verdict on-chain). Permissionless: any address that locks the required
        // collateral may audit, no CSNode-tier or OPoI-stake requirement.
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): AUDITOR_VERIFY missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-auditor-no-request-id");
        if (tx.opoiAuditorAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): AUDITOR_VERIFY missing auditorAddress"),
                             REJECT_INVALID, "bad-txns-opoi-auditor-no-address");
        if (tx.opoiAuditorVerifyResult != AUDITOR_VERIFY_PASS &&
            tx.opoiAuditorVerifyResult != AUDITOR_VERIFY_FAIL &&
            tx.opoiAuditorVerifyResult != AUDITOR_VERIFY_TIMEOUT)
            return state.DoS(10, error("CheckOPoITransaction(): AUDITOR_VERIFY invalid result %d",
                                       (int)tx.opoiAuditorVerifyResult),
                             REJECT_INVALID, "bad-txns-opoi-auditor-invalid-result");
        if (tx.opoiAuditorCollateralIn.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): AUDITOR_VERIFY missing collateralIn"),
                             REJECT_INVALID, "bad-txns-opoi-auditor-no-collateral");
        if (!fIsVerifying) {
            // Only tasks the requester flagged VERIFIABLE (F14-B) get an on-chain
            // verdict — an Auditor has nothing to check on an OPEN (prose) task.
            OPoIRequest req;
            if (!g_opoiCache.GetRequest(tx.opoiRequestId, req) || !req.IsVerifiable())
                return state.DoS(10, error("CheckOPoITransaction(): AUDITOR_VERIFY for non-VERIFIABLE/unknown request %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-auditor-not-verifiable");
            // Collateral must not already be locked by another stake/audit.
            if (g_opoiCache.IsLockedUTXO(tx.opoiAuditorCollateralIn)) {
                if (IsHarmlessRedelivery(tx.opoiAuditorCollateralIn, tx.GetHash()))
                    return state.Invalid(error("CheckOPoITransaction(): AUDITOR_VERIFY %s already known",
                                               tx.GetHash().GetHex()),
                                         REJECT_DUPLICATE, "bad-txns-opoi-auditor-already-known");
                return state.DoS(100, error("CheckOPoITransaction(): AUDITOR_VERIFY collateral %s:%u already locked",
                                            tx.opoiAuditorCollateralIn.hash.GetHex(), tx.opoiAuditorCollateralIn.n),
                                 REJECT_INVALID, "bad-txns-opoi-auditor-collateral-locked");
            }
        }
        // Verify the Auditor owns the collateral address — same shape as STAKE's
        // ownership proof (opoi.cpp, OPOI_STAKE_TX_TYPE above).
        {
            std::string sigMsg = tx.opoiAuditorAddress + tx.opoiRequestId
                               + tx.opoiAuditorCollateralIn.hash.GetHex()
                               + strprintf("%u", tx.opoiAuditorCollateralIn.n);
            if (!VerifyOPoISig(tx.opoiAuditorAddress, sigMsg, tx.opoiSig))
                return state.DoS(100, error("CheckOPoITransaction(): AUDITOR_VERIFY invalid signature for %s",
                                            tx.opoiAuditorAddress),
                                 REJECT_INVALID, "bad-txns-opoi-auditor-bad-sig");
        }
        break;
    }

    default:
        return state.DoS(10, error("CheckOPoITransaction(): invalid nType %d", tx.nType),
                         REJECT_INVALID, "bad-txns-opoi-invalid-type");
    }

    return true;
}

// ── CheckOPoIBlockCaps ────────────────────────────────────────────────────────
// F11-B/C: bounds how many REQUEST/RESPONSE txs a single block may contain.
// Stateless count over this block's own vtx — no cache lookup needed, since
// the cap is about block occupancy, not any cross-block resource.

bool CheckOPoIBlockCaps(const std::vector<CTransaction>& vtx,
                        const Consensus::Params& params,
                        CValidationState& state)
{
    int nRequests = 0, nResponses = 0;
    for (const CTransaction& tx : vtx) {
        if (tx.nVersion != OPOI_TX_VERSION) continue;
        if (tx.nType == OPOI_REQUEST_TX_TYPE) ++nRequests;
        else if (tx.nType == OPOI_RESPONSE_TX_TYPE) ++nResponses;
    }

    if (params.nOPoIMaxRequestsPerBlock > 0 && nRequests > params.nOPoIMaxRequestsPerBlock)
        return state.DoS(10, error("CheckOPoIBlockCaps(): %d REQUEST txs exceeds cap %d",
                                   nRequests, params.nOPoIMaxRequestsPerBlock),
                         REJECT_INVALID, "bad-cb-opoi-too-many-requests");

    if (params.nOPoIMaxResponsesPerBlock > 0 && nResponses > params.nOPoIMaxResponsesPerBlock)
        return state.DoS(10, error("CheckOPoIBlockCaps(): %d RESPONSE txs exceeds cap %d",
                                   nResponses, params.nOPoIMaxResponsesPerBlock),
                         REJECT_INVALID, "bad-cb-opoi-too-many-responses");

    return true;
}

// ── CheckOPoIPayments ─────────────────────────────────────────────────────────
// Verifies that for each RESPONSE tx in vtx[1..], the coinbase (vtx[0]) contains
// an output paying the miner:
//   total_payment = request.payment + tx.opoiTokenCount * request.feePerToken
// Called from ConnectBlock before the tx processing loop, using the pre-block cache.
//
// F16: also verifies shard-routed payments (see GetShardPaymentsForBlock),
// against the same opoiBudget — RESPONSE (whole-model) and SHARD_RESULT
// (shard-routed pipeline) both pay for real OPoI compute out of one budget.
//
// Each coinbase output can satisfy at most one obligation (outUsed) — without
// this, two different obligations that happen to want the same (address,
// amount) — plausible now that shard payments can coincide with a RESPONSE
// payment, or with each other — could both silently pass by matching the same
// single output twice, letting the block underpay.

bool CheckOPoIPayments(const std::vector<CTransaction>& vtx,
                       int nHeight,
                       const Consensus::Params& params,
                       CValidationState& state)
{
    if (vtx.empty()) return true;
    const CTransaction& coinbase = vtx[0];
    std::vector<bool> outUsed(coinbase.vout.size(), false);

    auto findAndClaimOutput = [&](const CScript& expectedScript, CAmount amount) {
        for (size_t j = 0; j < coinbase.vout.size(); ++j) {
            if (!outUsed[j] && coinbase.vout[j].scriptPubKey == expectedScript &&
                coinbase.vout[j].nValue == amount) {
                outUsed[j] = true;
                return true;
            }
        }
        return false;
    };

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

        // F14-C: a VERIFIABLE request's RESPONSE can never be paid in this same
        // block — an Auditor can only vote on it after it's already confirmed
        // on-chain, and resolution (ProcessAuditorVerifications) itself only
        // ever runs on a later block. Handled entirely by the deferred pass
        // below (GetVerifiablePaymentsForBlock) instead.
        if (req.IsVerifiable())
            continue;

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

        if (!findAndClaimOutput(GetScriptForDestination(minerDest), totalPayment)) {
            return state.DoS(100, error("CheckOPoIPayments(): coinbase missing OPoI payment of %s to %s for request %s",
                                        FormatMoney(totalPayment), tx.opoiMinerAddress, tx.opoiRequestId),
                             REJECT_INVALID, "bad-cb-opoi-missing-payment");
        }
        totalPaymentsChecked += totalPayment;
    }

    // F16: shard-routed payments, aggregated per miner address (a miner can be
    // in the resolved majority of more than one shard in the same block).
    {
        auto shardPayments = GetShardPaymentsForBlock(vtx, params);
        std::map<std::string, CAmount> aggregated;
        for (const auto& p : shardPayments) aggregated[p.minerAddress] += p.amount;

        for (const auto& kv : aggregated) {
            const std::string& minerAddress = kv.first;
            CAmount totalPayment = kv.second;

            if (totalPaymentsChecked + totalPayment > opoiBudget) {
                LogPrint("opoi", "CheckOPoIPayments: shard payment %s to %s exceeds OPoI budget, skipping\n",
                         FormatMoney(totalPayment), minerAddress);
                continue;
            }

            CTxDestination minerDest = DecodeDestination(minerAddress);
            if (!IsValidDestination(minerDest))
                return state.DoS(100, error("CheckOPoIPayments(): SHARD_RESULT has invalid miner address %s",
                                            minerAddress),
                                 REJECT_INVALID, "bad-cb-opoi-invalid-shard-miner-addr");

            if (!findAndClaimOutput(GetScriptForDestination(minerDest), totalPayment)) {
                return state.DoS(100, error("CheckOPoIPayments(): coinbase missing shard payment of %s to %s",
                                            FormatMoney(totalPayment), minerAddress),
                                 REJECT_INVALID, "bad-cb-opoi-missing-shard-payment");
            }
            totalPaymentsChecked += totalPayment;
        }
    }

    // F14-C: VERIFIABLE-request RESPONSE payments, deferred until an Auditor
    // PASS majority resolves (never in the RESPONSE's own confirming block —
    // see the `continue` above). Uses the same pre-block cache snapshot as
    // the loop above; no need to combine with this block's own txs the way
    // GetShardPaymentsForBlock does, because resolution (ProcessAuditorVerifications)
    // only ever completes on an *earlier* block than the one being validated here.
    {
        for (const auto& p : GetVerifiablePaymentsForBlock(vtx, params)) {
            if (totalPaymentsChecked + p.amount > opoiBudget) {
                LogPrint("opoi", "CheckOPoIPayments: verifiable payment %s to %s exceeds OPoI budget, skipping\n",
                         FormatMoney(p.amount), p.minerAddress);
                continue;
            }
            CTxDestination minerDest = DecodeDestination(p.minerAddress);
            if (!IsValidDestination(minerDest))
                return state.DoS(100, error("CheckOPoIPayments(): VERIFIABLE RESPONSE has invalid miner address %s",
                                            p.minerAddress),
                                 REJECT_INVALID, "bad-cb-opoi-invalid-verifiable-miner-addr");
            if (!findAndClaimOutput(GetScriptForDestination(minerDest), p.amount)) {
                return state.DoS(100, error("CheckOPoIPayments(): coinbase missing verifiable payment of %s to %s for request %s",
                                            FormatMoney(p.amount), p.minerAddress, p.requestId),
                                 REJECT_INVALID, "bad-cb-opoi-missing-verifiable-payment");
            }
            totalPaymentsChecked += p.amount;
        }
    }

    return true;
}

// ── GetEffectiveShardMinSubmissions ───────────────────────────────────────────
// F15-F: how many submissions a shard actually needs before its majority is
// final — lowered from the configured nOPoIShardMinSubmissions when fewer
// miners could ever possibly submit (e.g. an expert hosted by only 1-2 active
// stakers). Shared by getshardresult (RPC) and GetShardPaymentsForBlock so
// "resolved" always means the same thing whether queried or paid.

int GetEffectiveShardMinSubmissions(const OPoIRequest& req, uint32_t shardIndex,
                                    const Consensus::Params& params)
{
    int configuredMin = params.nOPoIShardMinSubmissions;
    ModelManifest manifest;
    if (!g_opoiCache.GetModelManifest(req.model, manifest) || !manifest.IsActive())
        return configuredMin;

    auto meg = BuildModelExecutionGraph(manifest);
    if (shardIndex >= meg.size())
        return configuredMin;

    const ShardDescriptor& d = meg[shardIndex];
    int available = (d.shardType == OPOI_SHARD_EXPERT)
        ? g_opoiCache.CountActiveExpertHosts(d.expertId)
        : g_opoiCache.CountActiveStakers();
    if (available > 0 && available < configuredMin)
        return available;
    return configuredMin;
}

// ── GetShardPaymentsForBlock ───────────────────────────────────────────────────
// See the design notes on this declaration in opoi.h.

std::vector<OPoIShardPayment> GetShardPaymentsForBlock(const std::vector<CTransaction>& vtx,
                                                        const Consensus::Params& params)
{
    std::vector<OPoIShardPayment> out;

    // Distinct (requestId, shardIndex) touched by a SHARD_RESULT tx in this
    // block — a shard with no new submission this block can't have newly
    // resolved (if it was already resolved, it was already paid).
    std::set<std::pair<std::string, uint32_t>> touched;
    for (size_t i = 1; i < vtx.size(); ++i) {
        const CTransaction& tx = vtx[i];
        if (tx.nVersion == OPOI_TX_VERSION && tx.nType == OPOI_SHARD_RESULT_TX_TYPE)
            touched.insert({tx.opoiRequestId, tx.opoiShardIndex});
    }

    for (const auto& key : touched) {
        const std::string& requestId  = key.first;
        uint32_t            shardIndex = key.second;
        if (g_opoiCache.IsShardPaid(requestId, shardIndex))
            continue; // already paid in a previous block

        OPoIRequest req;
        if (!g_opoiCache.GetRequest(requestId, req) || req.payment <= 0)
            continue;

        // Combine the pre-block cache with this block's own SHARD_RESULT txs
        // for this exact shard — same anti-equivocation rule AddShardResult
        // already enforces (one submission per miner, first one wins). This
        // works whether called pre-apply (CreateNewBlock/CheckOPoIPayments,
        // cache doesn't have this block's txs yet) or post-apply
        // (ProcessShardPayments, cache already has them — the `seen` set just
        // makes the second pass a no-op).
        std::vector<ShardResultSubmission> subs = g_opoiCache.ListShardResults(requestId, shardIndex);
        std::set<std::string> seen;
        for (const auto& s : subs) seen.insert(s.minerAddress);
        for (size_t i = 1; i < vtx.size(); ++i) {
            const CTransaction& tx = vtx[i];
            if (tx.nVersion != OPOI_TX_VERSION || tx.nType != OPOI_SHARD_RESULT_TX_TYPE)
                continue;
            if (tx.opoiRequestId != requestId || tx.opoiShardIndex != shardIndex)
                continue;
            if (!seen.insert(tx.opoiMinerAddress).second)
                continue;
            ShardResultSubmission sub;
            sub.minerAddress       = tx.opoiMinerAddress;
            sub.boundaryOutputHash = tx.opoiResponseHash;
            sub.tokenCount         = tx.opoiTokenCount;
            subs.push_back(sub);
        }

        int effectiveMin = GetEffectiveShardMinSubmissions(req, shardIndex, params);
        uint256 majorityHash;
        uint32_t majorityTokenCount = 0;
        std::vector<std::string> agreeing, divergent;
        if (!ComputeShardMajority(subs, effectiveMin, majorityHash, majorityTokenCount, agreeing, divergent) || agreeing.empty())
            continue; // not resolved yet

        // This shard's share of req.payment: weighted by layer span for DENSE
        // shards. A request whose model doesn't resolve to an ACTIVE
        // ModelManifest is treated as a single implicit shard (the whole
        // payment) — same fallback CheckOPoITransaction already applies for
        // free-text model names unrelated to any manifest.
        CAmount shardShare = req.payment;
        ModelManifest manifest;
        if (g_opoiCache.GetModelManifest(req.model, manifest) && manifest.IsActive()) {
            auto meg = BuildModelExecutionGraph(manifest);
            uint64_t totalWeight = 0, myWeight = 0;
            bool found = false;
            for (const auto& d : meg) {
                uint64_t w = (d.shardType == OPOI_SHARD_DENSE) ? (uint64_t)(d.layerEnd - d.layerStart) : 1;
                totalWeight += w;
                if (d.shardIndex == shardIndex) { myWeight = w; found = true; }
            }
            if (!found || totalWeight == 0)
                continue; // shardIndex out of range for this manifest — CheckOPoITransaction already gates this, shouldn't happen
            shardShare = (CAmount)(req.payment * (CAmount)myWeight / (CAmount)totalWeight);
        }
        if (shardShare <= 0)
            continue;

        // F16: per-token fee, NOT divided across shards like the base payment
        // is — each shard's miners ran a real forward pass per token through
        // their own slice of the model, so token-based compensation applies
        // per shard independently (mirrors RESPONSE's total = payment +
        // tokenCount * feePerToken, just scoped to this one shard).
        CAmount perShardTotal = shardShare;
        if (req.feePerToken > 0 && majorityTokenCount > 0)
            perShardTotal += (CAmount)majorityTokenCount * req.feePerToken;

        CAmount perMiner = perShardTotal / (CAmount)agreeing.size();
        if (perMiner <= 0)
            continue;

        for (const auto& addr : agreeing)
            out.push_back({requestId, shardIndex, addr, perMiner});
    }

    return out;
}

// ── ProcessShardPayments ───────────────────────────────────────────────────────
// Called from ConnectBlock/RebuildOPoICache after ProcessOPoITransaction has
// applied this block's own SHARD_RESULT txs. Marks every shard paid this
// block so GetShardPaymentsForBlock never returns it again.

void ProcessShardPayments(const std::vector<CTransaction>& vtx, const Consensus::Params& params)
{
    for (const auto& p : GetShardPaymentsForBlock(vtx, params))
        g_opoiCache.MarkShardPaid(p.requestId, p.shardIndex);
}

// ── GetVerifiablePaymentsForBlock / ProcessVerifiableResponsePayments (F14-C) ──
// Mirrors GetShardPaymentsForBlock's combine-cache-with-this-block's-own-txs
// pattern exactly (see ComputeAuditorMajority in opoi.h for why): without
// this, a vote that itself completes quorum would be invisible to the
// pre-apply callers (CreateNewBlock/CheckOPoIPayments) but visible to the
// post-apply caller (ProcessVerifiableResponsePayments), letting the latter
// mark a response "paid" that the block's own coinbase never actually paid.

std::vector<OPoIResponsePayment> GetVerifiablePaymentsForBlock(const std::vector<CTransaction>& vtx,
                                                                const Consensus::Params& params)
{
    std::vector<OPoIResponsePayment> out;
    LOCK(g_opoiCache.cs);
    for (const auto& resp : g_opoiCache.ListResponses()) {
        if (g_opoiCache.IsResponsePaid(resp.requestId)) continue;

        OPoIRequest req;
        if (!g_opoiCache.GetRequest(resp.requestId, req) || !req.IsVerifiable() || req.payment <= 0)
            continue; // OPEN responses are paid same-block, above

        std::vector<AuditorVerification> verifs = g_opoiCache.GetAuditorVerifications(resp.requestId);
        std::set<std::string> seen;
        for (const auto& v : verifs) seen.insert(v.auditorAddress);
        for (size_t i = 1; i < vtx.size(); ++i) {
            const CTransaction& tx = vtx[i];
            if (tx.nVersion != OPOI_TX_VERSION || tx.nType != OPOI_AUDITOR_VERIFY_TX_TYPE) continue;
            if (tx.opoiRequestId != resp.requestId) continue;
            if (!seen.insert(tx.opoiAuditorAddress).second) continue; // already in cache
            AuditorVerification v;
            v.auditorAddress = tx.opoiAuditorAddress;
            v.result         = tx.opoiAuditorVerifyResult;
            verifs.push_back(v);
        }

        if (ComputeAuditorMajority(verifs, params.nOPoIMinAuditors) != AUDITOR_VERIFY_PASS)
            continue; // not resolved PASS yet

        CAmount totalPayment = req.payment;
        if (req.feePerToken > 0 && resp.tokenCount > 0)
            totalPayment += (CAmount)resp.tokenCount * req.feePerToken;

        out.push_back({resp.requestId, resp.minerAddress, totalPayment});
    }
    return out;
}

void ProcessVerifiableResponsePayments(const std::vector<CTransaction>& vtx, const Consensus::Params& params)
{
    for (const auto& p : GetVerifiablePaymentsForBlock(vtx, params))
        g_opoiCache.MarkResponsePaid(p.requestId);
}

// ── ProcessAuditorVerifications ────────────────────────────────────────────────
// F14-C: called from ConnectBlock/RebuildOPoICache after ProcessOPoITransaction
// has applied this block's own AUDITOR_VERIFY txs. Event-driven (unlike the
// window-based ProcessExpiredChallenges): resolves a requestId's verification
// the moment it first reaches nOPoIMinAuditors quorum, same shape as shard
// majority resolution (F15-D/F16) rather than a fixed-block timeout — there is
// no real sandbox execution time to bound yet (F14-E).
//
// On resolution: Auditors matching the majority get their collateral unlocked
// immediately; Auditors in the minority stay locked forever (burned), same
// treatment as an unanswered CHALLENGE (ProcessExpiredChallenges) — no separate
// reward is minted for correct votes or paid out from the slashed collateral
// (see plan rationale: "treasury" elsewhere in this file never moves real
// funds either, it just means nothing is paid).
//
// Known v1 limitation: if quorum is never reached, Auditors who already voted
// stay locked indefinitely and the underlying RESPONSE payment never resolves
// — same "never resolves = never pays" behavior the rest of OPoI already has.
// A quorum-degradation policy mirroring F15-F (GetEffectiveShardMinSubmissions)
// would be a reasonable follow-up, not implemented here.

void ProcessAuditorVerifications(uint32_t blockHeight, const Consensus::Params& params)
{
    LOCK(g_opoiCache.cs);
    for (auto& kv : g_opoiCache.mapAuditorVerifications) {
        const std::string& requestId = kv.first;
        if (g_opoiCache.IsAuditorResolved(requestId)) continue;

        int majority = g_opoiCache.GetAuditorMajorityResult(requestId, params.nOPoIMinAuditors);
        if (majority < 0) continue; // no quorum yet

        for (auto& fv : kv.second) {
            if ((int)fv.result == majority) {
                g_opoiCache.UnlockUTXO(fv.auditorCollateral);
                fv.status = OPOI_AUDITOR_STATUS_COMPLETE;
            } else {
                // Collateral stays locked permanently (burned) — same as an
                // unanswered CHALLENGE (ProcessExpiredChallenges).
                fv.status = OPOI_AUDITOR_STATUS_SLASHED;
                LogPrintf("OPoI: SLASH auditor %s — verdict %d disagreed with majority %d for "
                          "request %s at height %u — collateral %s:%u permanently locked\n",
                          fv.auditorAddress, (int)fv.result, majority, requestId, blockHeight,
                          fv.auditorCollateral.hash.GetHex(), fv.auditorCollateral.n);
            }
        }
        g_opoiCache.MarkAuditorResolved(requestId);
    }
}

// ── GetChallengerRewardsAtHeight ──────────────────────────────────────────────
//
// F10-A/F8-C (2026-07-05): rewritten around proof, not a bare timeout. A
// challenger is rewarded once their challenge is actually PROVEN (REVEAL
// verified + Auditor majority FAIL for VERIFIABLE — never for OPEN, which has
// no fraud oracle). Mirrors GetVerifiablePaymentsForBlock's combine-cache-
// with-this-block's-own-txs pattern: a REVEAL that itself completes the
// resolution (Auditor majority already decided pre-block) must be visible to
// the pre-apply callers (CreateNewBlock/CheckOPoIChallengerRewards), not just
// to ProcessOPoITransaction's own immediate-resolution path — same bug class
// already fixed once for F14-C's verifiable-response payment gate.
// The challenger's share is nOPoIChallengerRewardPct % of the miner's staked
// amount; F12-A (2026-07) adds a second share, nOPoITreasuryRewardPct %, paid
// to GetOPoITreasuryAddress() for the same proven CHALLENGE — together they
// account for the full stakedAmount instead of leaving the challenger's half
// as the only payout.

std::vector<OPoIChallengerReward> GetChallengerRewardsAtHeight(
    const std::vector<CTransaction>& vtx, uint32_t blockHeight, const Consensus::Params& params)
{
    std::vector<OPoIChallengerReward> rewards;
    if (params.nOPoIChallengerRewardPct <= 0 && params.nOPoITreasuryRewardPct <= 0) return rewards;

    LOCK(g_opoiCache.cs);

    auto tryReward = [&](const std::string& requestId, const std::string& challengerAddress) {
        if (g_opoiCache.IsChallengerRewardPaid(requestId)) return;
        auto respIt = g_opoiCache.mapResponses.find(requestId);
        if (respIt == g_opoiCache.mapResponses.end()) return;
        auto stakeIt = g_opoiCache.mapStakes.find(respIt->second.minerAddress);
        if (stakeIt == g_opoiCache.mapStakes.end()) return;

        CAmount stakedAmount = stakeIt->second.amount;
        CAmount reward = (stakedAmount * params.nOPoIChallengerRewardPct) / 100;
        CAmount treasuryReward = (stakedAmount * params.nOPoITreasuryRewardPct) / 100;
        if (reward <= 0 && treasuryReward <= 0) return;

        rewards.push_back({challengerAddress, reward, requestId, treasuryReward});
        LogPrint("opoi", "GetChallengerRewardsAtHeight: height=%u challenger=%s reward=%s treasury=%s\n",
                 blockHeight, challengerAddress, FormatMoney(reward), FormatMoney(treasuryReward));
    };

    // Case 1: already resolved SLASHED in an earlier block (deferred VERIFIABLE
    // resolution via ProcessExpiredChallenges catching up once Auditor decides).
    for (const auto& kv : g_opoiCache.mapChallenges) {
        const OPoIChallenge& ch = kv.second;
        if (ch.challengeStatus == OPOI_CHALLENGE_SLASHED)
            tryReward(ch.requestId, ch.challengerAddress);
    }

    // Case 2: this block's own REVEAL txs that resolve SLASHED right now,
    // because the Auditor majority was already FAIL before this block.
    for (size_t i = 1; i < vtx.size(); ++i) {
        const CTransaction& tx = vtx[i];
        if (tx.nVersion != OPOI_TX_VERSION || tx.nType != OPOI_CHALLENGE_TX_TYPE) continue;
        if (tx.opoiChallengePhase != 1) continue; // REVEAL only

        OPoIChallenge ch;
        if (!g_opoiCache.GetChallenge(tx.opoiRequestId, ch) || ch.challengeStatus != OPOI_CHALLENGE_OPEN)
            continue; // not a pending COMMIT this REVEAL could resolve

        OPoIRequest req;
        if (!g_opoiCache.GetRequest(tx.opoiRequestId, req) || !req.IsVerifiable()) continue;
        if (g_opoiCache.GetAuditorMajorityResult(tx.opoiRequestId, params.nOPoIMinAuditors) != AUDITOR_VERIFY_FAIL)
            continue;

        tryReward(tx.opoiRequestId, tx.opoiRequester);
    }

    return rewards;
}

// Marks each reward returned by GetChallengerRewardsAtHeight as paid, once the
// block that actually includes the coinbase payout is connected for real.
// Called after ProcessExpiredChallenges so any deferred (REVEALED_PENDING →
// SLASHED) resolution from this same block is already visible.
void ProcessChallengerRewardPayments(const std::vector<CTransaction>& vtx, uint32_t blockHeight,
                                      const Consensus::Params& params)
{
    for (const auto& r : GetChallengerRewardsAtHeight(vtx, blockHeight, params))
        g_opoiCache.MarkChallengerRewardPaid(r.requestId);
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

    auto rewards = GetChallengerRewardsAtHeight(vtx, blockHeight, params);
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

    // F12-A: treasury gets the other half of each slashed miner's stake —
    // aggregated into a single expected output (CreateNewBlock mirrors this,
    // see miner.cpp) rather than checking one output per requestId.
    CAmount totalTreasuryReward = 0;
    for (const auto& reward : rewards)
        totalTreasuryReward += reward.treasuryAmount;

    if (totalTreasuryReward > 0) {
        if (checkedTotal + totalTreasuryReward > totalCoinbaseValue) {
            LogPrint("opoi", "CheckOPoIChallengerRewards: treasury reward %s exceeds coinbase, skipping\n",
                     FormatMoney(totalTreasuryReward));
        } else {
            CTxDestination treasuryDest = DecodeDestination(Params().GetOPoITreasuryAddress());
            if (!IsValidDestination(treasuryDest))
                return state.DoS(100, error("CheckOPoIChallengerRewards(): invalid treasury address %s",
                                            Params().GetOPoITreasuryAddress()),
                                 REJECT_INVALID, "bad-cb-opoi-invalid-treasury-addr");

            CScript expectedTreasuryScript = GetScriptForDestination(treasuryDest);
            bool foundTreasury = false;
            for (const CTxOut& out : coinbase.vout) {
                if (out.scriptPubKey == expectedTreasuryScript && out.nValue == totalTreasuryReward) {
                    foundTreasury = true;
                    break;
                }
            }
            if (!foundTreasury)
                return state.DoS(100, error("CheckOPoIChallengerRewards(): coinbase missing treasury reward"
                                            " of %s", FormatMoney(totalTreasuryReward)),
                                 REJECT_INVALID, "bad-cb-opoi-missing-treasury-reward");
        }
    }

    return true;
}
