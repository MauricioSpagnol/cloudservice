// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "csapp.h"
#include "primitives/transaction.h"
#include "util.h"
#include "main.h"

CSAppCache g_csappCache;

bool ProcessCSAppTransaction(const CTransaction& tx, uint32_t blockHeight, bool fUndo)
{
    if (tx.nVersion != CSAPP_TX_VERSION)
        return false;

    if (fUndo) {
        // On block disconnect: reverse the effect of this tx
        if (tx.nType == CSAPP_REGISTER_TX_TYPE) {
            LOCK(g_csappCache.cs);
            g_csappCache.mapApps.erase(tx.csappDeploymentId);
        } else if (tx.nType == CSAPP_UPDATE_TX_TYPE || tx.nType == CSAPP_STOP_TX_TYPE) {
            // Revert to running — a full reindex would restore the previous state.
            // For simplicity, mark as running on undo.
            LOCK(g_csappCache.cs);
            auto it = g_csappCache.mapApps.find(tx.csappDeploymentId);
            if (it != g_csappCache.mapApps.end())
                it->second.status = CSAPP_STATUS_RUNNING;
        }
        return true;
    }

    if (tx.nType == CSAPP_REGISTER_TX_TYPE) {
        CSAppData data;
        data.deploymentId = tx.csappDeploymentId;
        data.owner        = tx.csappOwner;
        data.specJson     = tx.csappSpecJson;
        data.ip           = tx.csappIp;
        data.registeredAt = blockHeight;
        data.updatedAt    = blockHeight;
        data.status       = CSAPP_STATUS_RUNNING;
        data.lockedCscoin = tx.csappLockedAmount;
        data.txHash       = tx.GetHash();
        data.lastTxHash   = tx.GetHash();
        g_csappCache.AddApp(data);
        LogPrintf("CSApp: registered %s at height %u\n", tx.csappDeploymentId, blockHeight);

    } else if (tx.nType == CSAPP_UPDATE_TX_TYPE) {
        g_csappCache.UpdateApp(tx.csappDeploymentId, tx.csappSpecJson,
                               blockHeight, tx.GetHash());
        LogPrintf("CSApp: updated %s at height %u\n", tx.csappDeploymentId, blockHeight);

    } else if (tx.nType == CSAPP_STOP_TX_TYPE) {
        g_csappCache.StopApp(tx.csappDeploymentId, blockHeight, tx.GetHash(), /*expired=*/false);
        LogPrintf("CSApp: stopped %s at height %u\n", tx.csappDeploymentId, blockHeight);
    }

    return true;
}

void RebuildCSAppCache()
{
    LogPrintf("CSApp: rebuilding app cache from chain...\n");
    g_csappCache.SetNull();

    CBlockIndex* pindex = chainActive.Genesis();
    while (pindex) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
            for (const CTransaction& tx : block.vtx) {
                if (tx.nVersion == CSAPP_TX_VERSION)
                    ProcessCSAppTransaction(tx, (uint32_t)pindex->nHeight);
            }
        }
        pindex = chainActive.Next(pindex);
    }
    LogPrintf("CSApp: cache rebuilt — %zu app(s) found\n", g_csappCache.Size());
}
