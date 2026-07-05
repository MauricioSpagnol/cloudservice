// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"

#include <boost/optional.hpp>

namespace Consensus {

/**
 * Index into Params.vUpgrades and NetworkUpgradeInfo
 *
 * Being array indices, these MUST be numbered consecutively.
 *
 * The order of these indices MUST match the order of the upgrades on-chain, as
 * several functions depend on the enum being sorted.
 */
enum UpgradeIndex {
    // BASE_SPROUT must be first
    BASE_SPROUT,
    UPGRADE_TESTDUMMY,
    // LWMA algo starts at this block 
    UPGRADE_LWMA,
    UPGRADE_EQUI144_5,	
    UPGRADE_ACADIA,
    UPGRADE_KAMIOOKA,
    UPGRADE_KAMATA,
    UPGRADE_FLUX,
    UPGRADE_HALVING,
    UPGRADE_P2SHNODES,
    UPGRADE_OPOI,          // Optimistic Proof of Inference (tx version 8)
    // NOTE: Also add new upgrades to NetworkUpgradeInfo in upgrades.cpp
    MAX_NETWORK_UPGRADES
};

struct NetworkUpgrade {
    /**
     * The first protocol version which will understand the new consensus rules
     */
    int nProtocolVersion;

    /**
     * Height of the first block for which the new consensus rules will be active
     */
    int nActivationHeight;

    /**
     * Special value for nActivationHeight indicating that the upgrade is always active.
     * This is useful for testing, as it means tests don't need to deal with the activation
     * process (namely, faking a chain of somewhat-arbitrary length).
     *
     * New blockchains that want to enable upgrade rules from the beginning can also use
     * this value. However, additional care must be taken to ensure the genesis block
     * satisfies the enabled rules.
     */
    static constexpr int ALWAYS_ACTIVE = 0;

    /**
     * Special value for nActivationHeight indicating that the upgrade will never activate.
     * This is useful when adding upgrade code that has a testnet activation height, but
     * should remain disabled on mainnet.
     */
    static constexpr int NO_ACTIVATION_HEIGHT = -1;

    /**
     * The hash of the block at height nActivationHeight, if known. This is set manually
     * after a network upgrade activates.
     *
     * We use this in IsInitialBlockDownload to detect whether we are potentially being
     * fed a fake alternate chain. We use NU activation blocks for this purpose instead of
     * the checkpoint blocks, because network upgrades (should) have significantly more
     * scrutiny than regular releases. nMinimumChainWork MUST be set to at least the chain
     * work of this block, otherwise this detection will have false positives.
     */
    boost::optional<uint256> hashActivationBlock;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;

    bool fCoinbaseMustBeProtected;

    /** Needs to evenly divide MAX_SUBSIDY to avoid rounding errors. */
    int nSubsidySlowStartInterval;
    /**
     * Shift based on a linear ramp for slow start:
     *
     * MAX_SUBSIDY*(t_s/2 + t_r) = MAX_SUBSIDY*t_h  Coin balance
     *              t_s   + t_r  = t_h + t_c        Block balance
     *
     * t_s = nSubsidySlowStartInterval
     * t_r = number of blocks between end of slow start and first halving
     * t_h = nSubsidyHalvingInterval
     * t_c = SubsidySlowStartShift()
     */
    int SubsidySlowStartShift() const { return nSubsidySlowStartInterval / 2; }
    int nSubsidyHalvingInterval;
    int GetLastFoundersRewardBlockHeight() const {
        return -1;
    }


    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    NetworkUpgrade vUpgrades[MAX_NETWORK_UPGRADES];
    /** Proof of work parameters */
    uint256 powLimit;

    boost::optional<uint32_t> nPowAllowMinDifficultyBlocksAfterHeight;	
    int64_t nDigishieldAveragingWindow;
    int64_t nDigishieldMaxAdjustDown;
    int64_t nDigishieldMaxAdjustUp;
    int64_t nPowTargetSpacing;
    int64_t DigishieldAveragingWindowTimespan() const { return nDigishieldAveragingWindow * nPowTargetSpacing; }
    int64_t DigishieldMinActualTimespan() const { return (DigishieldAveragingWindowTimespan() * (100 - nDigishieldMaxAdjustUp  )) / 100; }
    int64_t DigishieldMaxActualTimespan() const { return (DigishieldAveragingWindowTimespan() * (100 + nDigishieldMaxAdjustDown)) / 100; }

    uint256 nMinimumChainWork;	
	
    /** Parameters for LWMA difficulty adjustment **/
    int64_t nZawyLWMAAveragingWindow;  // N

    /** Parameters for Equihash epoche fade **/
    unsigned long eh_epoch_fade_length = 0;

    /** OPoI Phase 3 — escrow parameters **/
    int64_t nOPoIMinStake              = 0;   // minimum collateral (zatoshis); set in chainparams
    int     nOPoIChallengeWindowBlocks = 144; // blocks after RESPONSE during which CHALLENGE is valid
    int     nOPoIUnstakeCooldownBlocks = 1440;// blocks after UNSTAKE before collateral is released

    /** OPoI Phase 5 — challenger reward **/
    int     nOPoIChallengerRewardPct   = 10;  // % of staked amount paid to challenger on successful slash

    /** OPoI Phase 6 — request expiry **/
    int     nOPoIRequestExpiryBlocks   = 2016;// blocks a PENDING request stays valid (mainnet ~2 weeks)

    /** OPoI subsidy allocation — dedicated inference budget **/
    double  nOPoISubsidyPct            = 0.10;// 10% of block subsidy reserved for OPoI miners (cap per block)

    /** OPoI v3 — fee per token (F11-A) **/
    // Default baseFee = payment in REQUEST; totalPayment = baseFee + tokenCount * feePerToken
    // feePerToken is specified per-request; this is the network default cap (0 = no default)
    int64_t nOPoIDefaultFeePerToken    = 0;   // zatoshis per token (regtest/testnet may set > 0)

    /** OPoI v3 — Auditors (F14-C): verify VERIFIABLE-task responses against a test suite **/
    // Minimum number of Auditors for VERIFIABLE tasks — must be odd ≥ 3
    int     nOPoIMinAuditors           = 3;
    // Minimum collateral an Auditor must lock to submit a verification (zatoshis); set in chainparams
    int64_t nOPoIAuditorMinCollateral  = 0;

    /** OPoI v3 — ECVRF threshold (F10-D) **/
    // Fixed VRF threshold: eligible = VRF_output < threshold
    // Value = 2^256 * 3 / 1000 ≈ selects ~3 miners per request (assumes ~1000 active miners)
    // Stored as hex string for arith_uint256 comparison in CheckOPoITransaction
    std::string nOPoIVrfThreshold      = "004C4B40000000000000000000000000000000000000000000000000000000000";

    /** F15-A2 — Model Manifest governance (register new dense/MoE/hybrid models via stake vote) **/
    int     nOPoIModelVoteWindowBlocks      = 200;  // how long a proposed model stays open to voting
    int     nOPoIModelApprovalPct           = 66;   // % of total ACTIVE stake needed to approve
    int     nOPoIModelActivationDelayBlocks = 100;  // grace period after approval before minable

    /** F15-C — Shard coordinator VRF self-claim (same mechanism as nOPoIVrfThreshold,
     *  different domain-separated seed: SHA256(prevBlockHash || requestId || "COORD")).
     *  Calibrated so ~3 coordinators self-select per request on average. **/
    std::string nOPoICoordinatorThreshold   = "004C4B40000000000000000000000000000000000000000000000000000000000";

    /** F15-D — shard boundary result: how many independent submissions before a
     *  shard's majority output is considered resolved. Same VRF-eligibility
     *  mechanism (domain-separated "SHARD"+shardIndex) governs who may submit. **/
    std::string nOPoIShardThreshold         = "004C4B40000000000000000000000000000000000000000000000000000000000";
    int         nOPoIShardMinSubmissions    = 3;    // R in the design doc — miners per shard

    /** F15-G — latency budget: max sequential DenseShards a task_class=INTERACTIVE
     *  request's model may have. Deeper models must be requested as BATCH. **/
    int         nOPoIMaxPipelineDepth       = 6;

};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
