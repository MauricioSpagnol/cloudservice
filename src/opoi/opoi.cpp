// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "opoi.h"
#include "primitives/transaction.h"
#include "main.h"
#include "util.h"

OPoICache g_opoiCache;

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

        } else if (tx.nType == OPOI_UNSTAKE_TX_TYPE) {
            // Revert unstake: restore to ACTIVE
            auto it = g_opoiCache.mapStakes.find(tx.opoiMinerAddress);
            if (it != g_opoiCache.mapStakes.end()) {
                it->second.stakeStatus  = OPOI_STAKE_ACTIVE;
                it->second.unstakeHeight = 0;
            }

        } else if (tx.nType == OPOI_CHALLENGE_TX_TYPE) {
            g_opoiCache.mapChallenges.erase(tx.opoiRequestId);
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
        req.blockHeight = blockHeight;
        req.sigTime     = tx.opoiSigTime;
        req.txHash      = tx.GetHash();
        req.status      = OPOI_STATUS_PENDING;
        g_opoiCache.AddRequest(req);
        LogPrintf("OPoI: REQUEST %s (model=%s) at height %u\n",
                  tx.opoiRequestId, tx.opoiModel, blockHeight);

    } else if (tx.nType == OPOI_RESPONSE_TX_TYPE) {
        OPoIResponse resp;
        resp.requestId    = tx.opoiRequestId;
        resp.minerAddress = tx.opoiMinerAddress;
        resp.responseHash = tx.opoiResponseHash;
        resp.blockHeight  = blockHeight;
        resp.sigTime      = tx.opoiSigTime;
        resp.txHash       = tx.GetHash();
        g_opoiCache.AddResponse(resp);
        LogPrintf("OPoI: RESPONSE for %s by %s at height %u\n",
                  tx.opoiRequestId, tx.opoiMinerAddress, blockHeight);

    } else if (tx.nType == OPOI_STAKE_TX_TYPE) {
        OPoIStake stake;
        stake.minerAddress  = tx.opoiMinerAddress;
        stake.collateralIn  = tx.opoiCollateralIn;
        stake.amount        = tx.opoiPayment;
        stake.blockHeight   = blockHeight;
        stake.sigTime       = tx.opoiSigTime;
        stake.txHash        = tx.GetHash();
        stake.stakeStatus   = OPOI_STAKE_ACTIVE;
        stake.unstakeHeight = 0;
        g_opoiCache.AddStake(stake);
        LogPrintf("OPoI: STAKE by %s (%.4f CS) at height %u\n",
                  tx.opoiMinerAddress, (double)tx.opoiPayment / COIN, blockHeight);

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
    }

    return true;
}

// ── RebuildOPoICache ──────────────────────────────────────────────────────────

void RebuildOPoICache()
{
    LogPrintf("OPoI: rebuilding cache from chain...\n");
    g_opoiCache.SetNull();

    CBlockIndex* pindex = chainActive.Genesis();
    while (pindex) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
            for (const CTransaction& tx : block.vtx) {
                if (tx.nVersion == OPOI_TX_VERSION)
                    ProcessOPoITransaction(tx, (uint32_t)pindex->nHeight);
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
                LogPrintf("OPoI: SLASH miner %s — unanswered challenge for request %s at height %u\n",
                          minerAddr, ch.requestId, blockHeight);
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
            LogPrintf("OPoI: stake released for %s at height %u\n",
                      stake.minerAddress, blockHeight);
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

    case OPOI_REQUEST_TX_TYPE:
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
        break;

    case OPOI_RESPONSE_TX_TYPE:
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-no-request-id");
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing minerAddress"),
                             REJECT_INVALID, "bad-txns-opoi-no-miner");
        if (tx.opoiResponseHash.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing responseHash"),
                             REJECT_INVALID, "bad-txns-opoi-no-response-hash");
        // Phase 3: miner must be an active staker
        if (!g_opoiCache.IsActiveStaker(tx.opoiMinerAddress))
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE from non-staked miner %s",
                                       tx.opoiMinerAddress),
                             REJECT_INVALID, "bad-txns-opoi-miner-not-staked");
        break;

    case OPOI_STAKE_TX_TYPE:
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): STAKE missing minerAddress"),
                             REJECT_INVALID, "bad-txns-opoi-stake-no-miner");
        if (tx.opoiCollateralIn.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): STAKE missing collateralIn"),
                             REJECT_INVALID, "bad-txns-opoi-stake-no-collateral");
        if (tx.opoiPayment <= 0)
            return state.DoS(10, error("CheckOPoITransaction(): STAKE payment must be positive"),
                             REJECT_INVALID, "bad-txns-opoi-stake-zero-amount");
        break;

    case OPOI_UNSTAKE_TX_TYPE:
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): UNSTAKE missing minerAddress"),
                             REJECT_INVALID, "bad-txns-opoi-unstake-no-miner");
        if (!g_opoiCache.IsActiveStaker(tx.opoiMinerAddress))
            return state.DoS(10, error("CheckOPoITransaction(): UNSTAKE from non-active staker %s",
                                       tx.opoiMinerAddress),
                             REJECT_INVALID, "bad-txns-opoi-unstake-not-staked");
        break;

    case OPOI_CHALLENGE_TX_TYPE:
        if (tx.opoiRequestId.empty())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing requestId"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-request-id");
        if (tx.opoiRequester.empty())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing challenger"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-challenger");
        if (tx.opoiResponseHash.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE missing claimedResponseHash"),
                             REJECT_INVALID, "bad-txns-opoi-challenge-no-hash");
        {
            // Response must exist to be challenged
            OPoIResponse resp;
            if (!g_opoiCache.GetResponse(tx.opoiRequestId, resp))
                return state.DoS(10, error("CheckOPoITransaction(): CHALLENGE for unknown response %s",
                                           tx.opoiRequestId),
                                 REJECT_INVALID, "bad-txns-opoi-challenge-unknown-response");
        }
        break;

    default:
        return state.DoS(10, error("CheckOPoITransaction(): invalid nType %d", tx.nType),
                         REJECT_INVALID, "bad-txns-opoi-invalid-type");
    }

    return true;
}
