// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "opoi.h"
#include "primitives/transaction.h"
#include "main.h"
#include "util.h"

OPoICache g_opoiCache;

bool ProcessOPoITransaction(const CTransaction& tx, uint32_t blockHeight, bool fUndo)
{
    if (tx.nVersion != OPOI_TX_VERSION)
        return false;

    if (fUndo) {
        LOCK(g_opoiCache.cs);
        if (tx.nType == OPOI_REQUEST_TX_TYPE) {
            g_opoiCache.mapRequests.erase(tx.opoiRequestId);
        } else if (tx.nType == OPOI_RESPONSE_TX_TYPE) {
            g_opoiCache.mapResponses.erase(tx.opoiRequestId);
            // Restore request to PENDING on undo
            auto it = g_opoiCache.mapRequests.find(tx.opoiRequestId);
            if (it != g_opoiCache.mapRequests.end())
                it->second.status = OPOI_STATUS_PENDING;
        }
        return true;
    }

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
        LogPrintf("OPoI: request %s (model=%s) at height %u\n",
                  tx.opoiRequestId, tx.opoiModel, blockHeight);

    } else if (tx.nType == OPOI_RESPONSE_TX_TYPE) {
        OPoIResponse resp;
        resp.requestId     = tx.opoiRequestId;
        resp.minerAddress  = tx.opoiMinerAddress;
        resp.responseHash  = tx.opoiResponseHash;
        resp.blockHeight   = blockHeight;
        resp.sigTime       = tx.opoiSigTime;
        resp.txHash        = tx.GetHash();
        g_opoiCache.AddResponse(resp);
        LogPrintf("OPoI: response for %s by %s at height %u\n",
                  tx.opoiRequestId, tx.opoiMinerAddress, blockHeight);
    }

    return true;
}

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
    LogPrintf("OPoI: cache rebuilt — %zu request(s), %zu response(s)\n",
              g_opoiCache.RequestCount(), g_opoiCache.ResponseCount());
}

bool CheckOPoITransaction(const CTransaction& tx, CValidationState& state)
{
    if (tx.nVersion != OPOI_TX_VERSION)
        return true; // not an OPoI tx, nothing to check

    if (!tx.vin.empty() || !tx.vout.empty() || !tx.vJoinSplit.empty())
        return state.DoS(10, error("CheckOPoITransaction(): OPoI tx has non-empty vectors"),
                         REJECT_INVALID, "bad-txns-opoi-not-empty");

    if (tx.opoiRequestId.empty())
        return state.DoS(10, error("CheckOPoITransaction(): missing requestId"),
                         REJECT_INVALID, "bad-txns-opoi-no-request-id");

    if (tx.nType == OPOI_REQUEST_TX_TYPE) {
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
    } else if (tx.nType == OPOI_RESPONSE_TX_TYPE) {
        if (tx.opoiMinerAddress.empty())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing minerAddress"),
                             REJECT_INVALID, "bad-txns-opoi-no-miner");
        if (tx.opoiResponseHash.IsNull())
            return state.DoS(10, error("CheckOPoITransaction(): RESPONSE missing responseHash"),
                             REJECT_INVALID, "bad-txns-opoi-no-response-hash");
    } else {
        return state.DoS(10, error("CheckOPoITransaction(): invalid nType %d", tx.nType),
                         REJECT_INVALID, "bad-txns-opoi-invalid-type");
    }

    return true;
}
