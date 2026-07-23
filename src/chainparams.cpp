// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Copyright (c) 2024-2025 The CS Coin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"
#include "streams.h"
#include "arith_uint256.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <stdio.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#include <mutex>
#include "metrics.h"

// Mine a new genesis block when pszTimestamp changes.
// Prints nNonce, nSolution, Hash, MerkleRoot and exits so the user can update chainparams.cpp.
static void MineGenesisBlock(CBlock& genesis)
{
    // ZelHash = Equihash(125, 4)
    const unsigned int n = 125;
    const unsigned int k = 4;

    printf("\n=== MINING GENESIS BLOCK (ZelHash 125/4) ===\n");
    printf("pszTimestamp changed — finding new nNonce + nSolution...\n");
    printf("This may take a few minutes.\n\n");

    arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
    arith_uint256 nNonce = UintToArith256(genesis.nNonce);
    bool found = false;

    while (!found) {
        genesis.nNonce = ArithToUint256(nNonce);
        genesis.nSolution.clear();

        // Build the initial Blake2b state
        crypto_generichash_blake2b_state state;
        EhInitialiseState(n, k, state);

        CEquihashInput I{genesis};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << I;
        crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

        crypto_generichash_blake2b_state curr_state = state;
        crypto_generichash_blake2b_update(&curr_state, genesis.nNonce.begin(), genesis.nNonce.size());

        std::function<bool(std::vector<unsigned char>)> validBlock =
            [&genesis, &hashTarget, &found](std::vector<unsigned char> soln) {
                genesis.nSolution = soln;
                if (UintToArith256(genesis.GetHash()) > hashTarget)
                    return false;
                found = true;
                return true;
            };
        std::function<bool(EhSolverCancelCheck)> cancelled =
            [&found](EhSolverCancelCheck) { return found; };

        EhOptimisedSolve(n, k, curr_state, validBlock, cancelled);

        if (!found)
            nNonce++;
    }

    printf("=== GENESIS FOUND — update chainparams.cpp with these values ===\n");
    printf("nNonce:      uint256S(\"0x%s\")\n", genesis.nNonce.GetHex().c_str());
    printf("nSolution:   ParseHex(\"%s\")\n", HexStr(genesis.nSolution.begin(), genesis.nSolution.end()).c_str());
    printf("Hash:        uint256S(\"0x%s\")\n", genesis.GetHash().GetHex().c_str());
    printf("MerkleRoot:  uint256S(\"0x%s\")\n", genesis.hashMerkleRoot.GetHex().c_str());
    printf("================================================================\n\n");
    exit(0);
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // *** ALTERADO PARA CS COIN ***
    const char* pszTimestamp = "01/May/2026 94% of Global Cloud Controlled by Big Tech as Computing Demand Soars - Now It Belongs to Everyone";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "CS"; // *** ALTERADO: Nome da moeda ***
        bip44CoinType = 19999;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nSubsidyHalvingInterval = 655350; 
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; 
        consensus.nDigishieldMaxAdjustUp = 16; 
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.nPowTargetSpacing = 2 * 60; // 2 minutos por bloco

        // Upgrades: BASE_SPROUT ativo desde genesis (obrigatorio).
        
        // Os demais ativam no bloco 1 para que o genesis (bloco 0) passe
        // a validacao com transacao v1 (nao-overwintered).
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        // ZelHash (GPU mining) ativo desde o genesis:
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nProtocolVersion = 170016;
        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_FLUX].nProtocolVersion = 170017;
        consensus.vUpgrades[Consensus::UPGRADE_FLUX].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_HALVING].nProtocolVersion = 170018;
        consensus.vUpgrades[Consensus::UPGRADE_HALVING].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_P2SHNODES].nProtocolVersion = 170019;
        consensus.vUpgrades[Consensus::UPGRADE_P2SHNODES].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_OPOI].nProtocolVersion = 170020;
        consensus.vUpgrades[Consensus::UPGRADE_OPOI].nActivationHeight = 100000;

        // OPoI Phase 3 escrow
        consensus.nOPoIMinStake              = 100 * COIN;  // 100 CS minimum stake
        consensus.nOPoIChallengeWindowBlocks = 144;         // ~1 hour at 25s/block
        consensus.nOPoIUnstakeCooldownBlocks = 1440;        // ~10 hours cooldown
        consensus.nOPoIRequestExpiryBlocks   = 2016;        // ~14 days PENDING before expiry

        // F10-A/F8-C — challenger collateral + commit-reveal
        consensus.nOPoIChallengerStakePct          = 10;
        consensus.nOPoIChallengeCommitRevealBlocks = 144;   // ~1 hour to REVEAL after COMMIT

        // F10-B — RESPONSE commit-reveal window (anti-copy)
        consensus.nOPoIResponseCommitWindowBlocks  = 144;   // ~1 hour to COMMIT before REVEAL opens

        // F9-E — periodic stake renewal (liveness proof, no slash on expiry)
        consensus.nOPoIStakeRenewalBlocks   = 20160;        // ~6 days at 25s/block

        // F11-A — REQUEST budget floor scaled by declared prompt size
        consensus.nOPoIFeeBase              = 100000;       // 0.001 CS
        consensus.nOPoIFeePerToken          = 10000;        // 0.0001 CS per estimated prompt token

        // F14-C — Auditors (verify VERIFIABLE-task responses against a test suite)
        consensus.nOPoIMinAuditors           = 3;           // odd ≥ 3, majority always decisive
        consensus.nOPoIAuditorMinCollateral  = 50 * COIN;   // 50 CS minimum collateral

        // F15-A2 — Model Manifest governance
        consensus.nOPoIModelVoteWindowBlocks      = 4032;   // ~4 weeks voting window
        consensus.nOPoIModelApprovalPct           = 66;     // 66% of active stake to approve
        consensus.nOPoIModelActivationDelayBlocks = 2016;   // ~2 weeks to download weights via FOTON

        consensus.nZawyLWMAAveragingWindow = 60;
        consensus.eh_epoch_fade_length = 11;

        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;

        // *** ALTERADO: TRABALHO MINIMO ZERO (Para moeda nova) ***
        consensus.nMinimumChainWork = uint256S("0x00");

        /**
         * The message start string should be awesome!
         * *** ALTERADO: MAGIC BYTES NOVOS DA CS COIN ***
         */
        pchMessageStart[0] = 0xc5; // C
        pchMessageStart[1] = 0x53; // S
        pchMessageStart[2] = 0x01;
        pchMessageStart[3] = 0x01;
        
        vAlertPubKey = ParseHex("04da977b8d1078e4777f0bff3a51b9a3540da14c8a810259c994c053b87e2dfbb428eea457ce0d7fb2a566109e547b0f4044890555874ff2db0f2e4470ce820fb3");
        
        nDefaultPort = 26125; // Porta nova
        nPruneAfterHeight = 100000;

        // Criacao do Bloco Genesis
        genesis = CreateGenesisBlock(
            1746316800,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000005"),
            ParseHex("444aac956cad85cef69321b78d4544dc358c6bf465e81187d7295f9a092b72314993b82edac01768ace6ff0326a79df16a084434"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();

        if (consensus.hashGenesisBlock != uint256S("0x069c0f4ff0427ee02edb625106bdf0e7fd4e28845dee020a493e9d8fd47c09c3")) {
            MineGenesisBlock(genesis);
        }
        assert(consensus.hashGenesisBlock == uint256S("0x069c0f4ff0427ee02edb625106bdf0e7fd4e28845dee020a493e9d8fd47c09c3"));
        assert(genesis.hashMerkleRoot == uint256S("0xef816fa706057f2414c71580dab285289fdabcbe143e8004486107378c7cb1e0"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("seed.cscloudservice.com", "seed.cscloudservice.com"));
        vSeeds.push_back(CDNSSeedData("seed2.cscloudservice.com", "seed2.cscloudservice.com"));

        // Prefixos (pode manter os originais por enquanto para compatibilidade)
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        base58Prefixes[SECRET_KEY]         = {0x80};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "csa";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "csviewa";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "csivka";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        networkID = CBaseChainParams::Network::MAIN;

        nStartFluxnodePaymentsHeight = 500; 

        // CS Coin benchmark signing key (generated by csbench-keygen, stored in ~/.csbenchmark/benchmark.key)
        vecBenchmarkingPublicKeys.resize(1);
        vecBenchmarkingPublicKeys[0] = std::make_pair("04bd9a8274ec53bd87782a3cf30d5c96e1d6c1f8aa98fedfc3364754766b7c5e2e0b83d2f75048fe7181d8cae9ea7fef573a6602f1a118ad4f4e5a3e48be28930a", 0);

        assert(vecBenchmarkingPublicKeys.size() > 0);

        // *** CHECKPOINTS LIMPOS PARA REDE NOVA ***
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,     
            0,             
            0            
        };

        // CS Coin funding addresses (mainnet)
        strExchangeFundingAddress = "t1KQjFkfwF2iJMBNd4EQ6cdGaLG9jVgVabR";
        nExchangeFundingHeight = 100000;
        nExchangeFundingAmount = 100000000 * COIN;  // 100M CS

        strFoundationFundingAddress = "t1PWoWfPBpQN36K2AuKbzeWwbcVCqkNwvu1";
        nFoundationFundingHeight = 101000;
        nFoundationFundingAmount = 10000000 * COIN;  // 10M CS

        strSwapPoolAddress = "t1QvfKYr3ozt36s5XKrK7LoQT1tsJYEpk3A";
        nSwapPoolStartHeight = 102000;
        nSwapPoolAmount = 20000000 * COIN;  // 20M CS x 10 = 200M total
        nSwapPoolInterval = 21600;
        nSwapPoolMaxTimes = 10;

        // Dev Fund: 5M CS x 100 installments = 500M CS total (~8.3 years)
        strDevFundAddress = "t1Lz6NHYByyDVWhRFn32hwd42nUtDdBpLc1";
        nDevFundStartHeight = 150000;
        nDevFundAmount = 5000000 * COIN;
        nDevFundInterval = 21600;
        nDevFundMaxTimes = 100;

        // Marketing Fund: 5M CS x 100 installments = 500M CS total (~8.3 years)
        strMarketingFundAddress = "t1WSeYrRUHzXNKKfzbAcsVWt25MVkZcSBUZ";
        nMarketingFundStartHeight = 150001;
        nMarketingFundAmount = 5000000 * COIN;
        nMarketingFundInterval = 21600;
        nMarketingFundMaxTimes = 100;

        vecP2SHPublicKeys.resize(1);
        vecP2SHPublicKeys[0] = std::make_pair("048c79f91e8b6a80da4f9d10e5b45ab81befa8f57ae869ad9fa0cca49f1c58b6ce3095bf2ffc87b83febbd3d58a3a03e3afe3c5bb5aebbb3b2d24da71a02e2946b", 0);
        assert(vecP2SHPublicKeys.size() > 0);
    }
};
static CMainParams mainParams;

/**
 * testnet-kamata
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TESTCS";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 1;
        consensus.nSubsidyHalvingInterval = 655350;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("0effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32;
        consensus.nDigishieldMaxAdjustUp = 16;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.nPowTargetSpacing = 60;
        consensus.nMinimumChainWork = uint256S("0x00");

        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nProtocolVersion = 170016;
        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_FLUX].nProtocolVersion = 170017;
        consensus.vUpgrades[Consensus::UPGRADE_FLUX].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_HALVING].nProtocolVersion = 170018;
        consensus.vUpgrades[Consensus::UPGRADE_HALVING].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_P2SHNODES].nProtocolVersion = 170019;
        consensus.vUpgrades[Consensus::UPGRADE_P2SHNODES].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_OPOI].nProtocolVersion = 170020;
        consensus.vUpgrades[Consensus::UPGRADE_OPOI].nActivationHeight = 5000;

        // OPoI Phase 3 escrow (testnet — lower values for easier testing)
        consensus.nOPoIMinStake              = 10 * COIN;   // 10 CS on testnet
        consensus.nOPoIChallengeWindowBlocks = 20;          // ~8 minutes on testnet
        consensus.nOPoIUnstakeCooldownBlocks = 60;          // ~25 minutes on testnet
        consensus.nOPoIRequestExpiryBlocks   = 200;         // ~83 minutes PENDING before expiry

        // F10-A/F8-C — challenger collateral + commit-reveal
        consensus.nOPoIChallengerStakePct          = 10;
        consensus.nOPoIChallengeCommitRevealBlocks = 20;    // ~8 minutes on testnet

        // F10-B — RESPONSE commit-reveal window (anti-copy)
        consensus.nOPoIResponseCommitWindowBlocks  = 20;    // ~8 minutes on testnet

        // F9-E — periodic stake renewal (liveness proof, no slash on expiry)
        consensus.nOPoIStakeRenewalBlocks   = 200;          // ~83 minutes on testnet

        // F11-A — REQUEST budget floor scaled by declared prompt size
        consensus.nOPoIFeeBase              = 100000;       // 0.001 CS
        consensus.nOPoIFeePerToken          = 10000;        // 0.0001 CS per estimated prompt token

        // F14-C — Auditors (testnet — lower collateral for easier testing)
        consensus.nOPoIMinAuditors           = 3;
        consensus.nOPoIAuditorMinCollateral  = 5 * COIN;

        // F15-A2 — Model Manifest governance (testnet — faster cycle)
        consensus.nOPoIModelVoteWindowBlocks      = 200;
        consensus.nOPoIModelApprovalPct           = 66;
        consensus.nOPoIModelActivationDelayBlocks = 100;

        consensus.nZawyLWMAAveragingWindow = 60;
        consensus.eh_epoch_fade_length = 10;

        eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_3 = zelHash;

        pchMessageStart[0] = 0xc5;
        pchMessageStart[1] = 0x53;
        pchMessageStart[2] = 0x74; 
        pchMessageStart[3] = 0x74;
        vAlertPubKey = ParseHex("044b5cb8fd1db34e2d89a93e7becf3fb35dd08a81bb3080484365e567136403fd4a6682a43d8819522ae35394704afa83de1ef069a3104763fd0ebdbdd505a1386"); 

        nDefaultPort = 26128; // 26127 is reserved for cs-cloud node-agent (slot 1)
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1582228940, 
            uint256S("0x000000000000000000000000000000000000000000000000000000000000021c"),
            ParseHex("00069ae382cf568d3f3ba00d15f9d09c8977cd37d90d2c4d612e053e4cdfd4d226db220e51495bfb00d1019180b34c25091fbee2a08e4f08c974a4356760690b00d8da0c8baa3b6902130202e60391a16a5fa1ea08d6d0b63a60ec91dd0790cb432261483fe7fbe9d80d6a07af5599cc6d0b717780184fc0523e5ada8c07134262b9676c0269709501d4403c621cb9a15f55602b400e3fc093034f84ec583f25e6f16a111372ab4f031d6d12270259d7066520f71e63893e8dcedd8db2255272add167e4cd4a0045a6815a16818f9efb075106090b8e47d089dd7d50c838ea4b22caca1fdb866e485f0248c763faada47f8555b8cdb1222e45f2f0a10e3f3dffcb9733090bf2e58eb8f11399ffd7fc58302db98d5d978dac49b88f849ad4af4972b37d3cf2ca1797c28af99b3addc356c460ba6eb161d3304eeef863237c61006b486df070bb29026895172ae79bd9f3018637fe01dbc18d3829a2ed211a7218fcd8f4def308c3a8bd60cb999565f253435f1af115d1d473750c0233fda7aaeff783b8265083a9c0369852a459fe2c093dec6929cfc31cea57a3579fed30add42cfc02260700796ea2d3054dc04020a50c5a8079863b15f68c0e0354bb0aa8f1dd48fec84923d02f1a300d3ec598071a9f0584d918e36ec892450abdfe7d41acfe870624de69f988db06f7790897459c7d9899f290b60f2102a1df05bca84a7f54e746d274625f3322ae5a3eaa02b4565a125c948cf8682396e72494995793bf9379196014fec46c4c3769861808ed6b3fd2b4e57cadb92a7c81fc7fd630c4bae2549aa6efdc02df0f5e1ff20a834d35372301334b214229e872f8ac9415d57d1a325ac539a4a62eb1c685c6478867cf3ea0f999768a0d66fc9e36a35a2f1f768481613da1a99a17739fab0dd2ffe73f58f95ef1a6c2495167b485207dabe48001a200b4a371cf1df817f0b1fb6208d0d77b38d5cf170d83a6b7633a4fb605f44665a314ab5de8dc0ace1091611148705b3fe81e945857291daeb3657c98602cda23a350ed209ba19b6312fdefe765f3de7a16031580eba06145f64bfdf284dca4713335e9735031c71cf36da5f1145c8ed6e69352a7d763be253bd5fc7e1e45660e8d4f2beb98377268bc6303f5de2dd6ce1a35652b7090a8be51d43ef5c779376de1cbabf4758b064259d545524781801e18d005dd2a1ea4d27e1eaf27578c6a5acdf4a27d226293ae7c49d645c07adc8b0dfb0c35e519a6d95e9bb3f4a8bbbc72551e5ab9191d552104620b954523376637077c2e32aa42dec58b07ad0d91e4b93651d74b220070d22171e1b116dda1428082cb54122c27276f283260e1249ed483f97d053a0ad3abc6a032d7b8a5672ad7ec2232010655136e6e1507cbd9fa4a27ec674724a8cf4bdae91e3e34080291899bbb53c209bb3936a9c2d9194de89179396803cdf6bcb5cf9bbaf95b56c613d161c21ff1defe0f056f27e953891fd310aa6760d6f5a5edef8011d8780de5c681261331aed69ee2eccd3bb413cdf55f2e500686b231cbaf451fecdc1327e14bde0973fb4cbd8835b7c31a1a1aaf47eecbb57849ad3eb960cdbd5cdb0e4c53a8d7f10459cbc572faab1ffbd8ca9d0919e0113099339910e897e21fd390f450c3b13b5d198d7306927f258a0297c50daa10a4f29aed6a184df29c0a32a666744bef2c358401350cfb54797a02a35afeba0bfefa865890dded2694d88ad86a5b327662bd7b932c6ce97a7f300bfd8b544316696a4f2e6c197ddf9d0e9b008e3f85427fd6b661970e4177c947fbb6d43324a4f47c26983b55ea90d3bffcbc87c15cab5ba2751314819e7eb21a29b9b915cce6f7cf01ff05936317161b9dae29637d89cb88b55ac74348878b017e7942"),
            0x2007ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        
        // vFixedSeeds.clear();
        vSeeds.clear();
        // vSeeds.push_back(CDNSSeedData("...", "..."));

        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "cstesta";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "csviewta";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "csivkta";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        networkID = CBaseChainParams::Network::TESTNET;

        nStartFluxnodePaymentsHeight = 350;

        vecBenchmarkingPublicKeys.resize(2);
        vecBenchmarkingPublicKeys[0] = std::make_pair("04d422e01f5acff68504b92df96a9004cf61be432a20efe83fe8a94c1aa730fe7dece5d2e8298f2d5672d4e569c55d9f0a73268ef7b92990d8c014e828a7cc48dd", 0);
        vecBenchmarkingPublicKeys[1] = std::make_pair("042023568fbcc4715c34d8596feaabf0683b3dfa7280b2f4df0436311a31086a73fdf507d63c3ec89455037ba738375d17b309c2cd226f173a5ef7841400cd09ec", 1617508800); 

        assert(vecBenchmarkingPublicKeys.size() > 0);

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,           
            0,           
            0          
        };

        strExchangeFundingAddress = "tmRucHD85zgSigtA4sJJBDbPkMUJDcw5XDE";
        nExchangeFundingHeight = 4100;
        nExchangeFundingAmount = 7500000 * COIN; 

        strFoundationFundingAddress = "tmRucHD85zgSigtA4sJJBDbPkMUJDcw5XDE";
        nFoundationFundingHeight = 4200;
        nFoundationFundingAmount = 2500000 * COIN;

        strSwapPoolAddress = "tmRucHD85zgSigtA4sJJBDbPkMUJDcw5XDE";
        nSwapPoolStartHeight = 4300;
        nSwapPoolAmount = 2200000 * COIN;
        nSwapPoolInterval = 100;
        nSwapPoolMaxTimes = 10;

        strDevFundAddress = "tmRucHD85zgSigtA4sJJBDbPkMUJDcw5XDE";
        nDevFundStartHeight = 5000;
        nDevFundAmount = 500000 * COIN;
        nDevFundInterval = 100;
        nDevFundMaxTimes = 100;

        strMarketingFundAddress = "tmRucHD85zgSigtA4sJJBDbPkMUJDcw5XDE";
        nMarketingFundStartHeight = 5001;
        nMarketingFundAmount = 500000 * COIN;
        nMarketingFundInterval = 100;
        nMarketingFundMaxTimes = 100;

        vecP2SHPublicKeys.resize(1);
        vecP2SHPublicKeys[0] = std::make_pair("04276f105ff36a670a56e75c2462cff05a4a7864756e6e1af01022e32752d6fe57b1e13cab4f2dbe3a6a51b4e0de83a5c4627345f5232151867850018c9a3c3a1d", 0);
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 0; 
        consensus.nDigishieldMaxAdjustUp = 0; 

        consensus.nPowTargetSpacing = 2 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;

        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        // TEST-ONLY: activate KAMIOOKA from genesis so regtest validates the
        // mainnet ZelHash (Equihash 125,4 / 52-byte) solutions — lets cs-miner's
        // real 125,4 shares be accepted as blocks at trivial regtest difficulty.
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nProtocolVersion = 170016;
        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_FLUX].nProtocolVersion = 170017;
        consensus.vUpgrades[Consensus::UPGRADE_FLUX].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_HALVING].nProtocolVersion = 170018;
        consensus.vUpgrades[Consensus::UPGRADE_HALVING].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_P2SHNODES].nProtocolVersion = 170019;
        consensus.vUpgrades[Consensus::UPGRADE_P2SHNODES].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_OPOI].nProtocolVersion = 170020;
        consensus.vUpgrades[Consensus::UPGRADE_OPOI].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        // OPoI Phase 3 escrow (regtest — minimal values for unit testing)
        consensus.nOPoIMinStake              = 1 * COIN;
        consensus.nOPoIChallengeWindowBlocks = 5;
        consensus.nOPoIUnstakeCooldownBlocks = 10;
        consensus.nOPoIRequestExpiryBlocks   = 20;           // 20 blocks PENDING before expiry in regtest

        // F10-A/F8-C — challenger collateral + commit-reveal (regtest — fast)
        consensus.nOPoIChallengerStakePct          = 10;
        consensus.nOPoIChallengeCommitRevealBlocks = 3;

        // F10-B — RESPONSE commit-reveal window (regtest — fast)
        consensus.nOPoIResponseCommitWindowBlocks  = 3;

        // F9-E — periodic stake renewal (regtest — fast, easy to cross with `generate`)
        consensus.nOPoIStakeRenewalBlocks   = 10;

        // F11-A — REQUEST budget floor scaled by declared prompt size (regtest — cheap)
        consensus.nOPoIFeeBase              = 10000;
        consensus.nOPoIFeePerToken          = 1000;

        // F14-C — Auditors (regtest — quorum of 1 so a single-node test can resolve it)
        consensus.nOPoIMinAuditors           = 1;
        consensus.nOPoIAuditorMinCollateral  = 1 * COIN;

        // F15-A2 — Model Manifest governance (regtest — minimal, for fast unit testing)
        consensus.nOPoIModelVoteWindowBlocks      = 5;
        consensus.nOPoIModelApprovalPct           = 66;
        consensus.nOPoIModelActivationDelayBlocks = 2;

        // F10-D — VRF eligibility threshold (regtest: ~87% of outputs eligible, so a
        // single test staker doesn't need dozens of retries to find an eligible request).
        // Mainnet/testnet keep the calibrated default in consensus/params.h.
        consensus.nOPoIVrfThreshold = "e000000000000000000000000000000000000000000000000000000000000000";
        // F15-C — same permissive override, coordinator self-claim domain.
        consensus.nOPoICoordinatorThreshold = "e000000000000000000000000000000000000000000000000000000000000000";
        // F15-D — same permissive override, shard result submission domain.
        consensus.nOPoIShardThreshold = "e000000000000000000000000000000000000000000000000000000000000000";
        consensus.nOPoIShardMinSubmissions = 2; // regtest: 2 miners enough to test majority
        // F15-G — small depth so toy models can actually exercise the rejection path
        consensus.nOPoIMaxPipelineDepth = 3;

        // F11-B/C — low caps so a manual test can actually hit and exercise the
        // rejection path without mining dozens of throwaway REQUEST/RESPONSE txs.
        consensus.nOPoIMaxRequestsPerBlock  = 3;
        consensus.nOPoIMaxResponsesPerBlock = 5;

        consensus.nMinimumChainWork = uint256S("0x00");

        consensus.nZawyLWMAAveragingWindow = 60;
        consensus.eh_epoch_fade_length = 11;

        eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_3 = zelHash;   // TEST-ONLY: 125,4 (52-byte) — see KAMIOOKA above

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 26126;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1296688602,
            uint256S("0000000000000000000000000000000000000000000000000000000000000016"),
            ParseHex("02853a9dd062e2356909a0d2b9f0e4873dbf092edd3f00eea317e21222d1f2c414b926ee"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear(); 
        vSeeds.clear();      

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        networkID = CBaseChainParams::Network::REGTEST;
        vecBenchmarkingPublicKeys.resize(2);
        vecBenchmarkingPublicKeys[0] = std::make_pair("04cf3c34f01486bbb34c1a7ca11c2ddb1b3d98698c3f37d54452ff91a8cd5e92a6910ce5fc2cc7ad63547454a965df53ff5be740d4ef4ac89848c2bafd1e40e6b7", 0);
        vecBenchmarkingPublicKeys[1] = std::make_pair("045d54130187b4c4bba25004bf615881c2d79b16950a59114df27dc9858d8e531fda4f3a27aa95ceb2bcc87ddd734be40a6808422655e5350fa9417874556b7342", 1617508800); 

        assert(vecBenchmarkingPublicKeys.size() > 0);

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "csrega";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "csviewra";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "csivkra";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        strExchangeFundingAddress = "tmRucHD85zgSigtA4sJJBDbPkMUJDcw5XDE";
        nExchangeFundingHeight = 10;
        nExchangeFundingAmount = 3000000 * COIN;

        strFoundationFundingAddress = "t2DFGpj2tciojsGKKrGVwQ92hUwAxWQQgJ9";
        nFoundationFundingHeight = 10;
        nFoundationFundingAmount = 2500000 * COIN;

        strSwapPoolAddress = "t2Dsexh4v5g2dpL2LLCsR1p9TshMm63jSBM";
        nSwapPoolStartHeight = 10;
        nSwapPoolAmount = 2100000 * COIN;
        nSwapPoolInterval = 10;
        nSwapPoolMaxTimes = 5;

        strDevFundAddress = "t2Dsexh4v5g2dpL2LLCsR1p9TshMm63jSBM";
        nDevFundStartHeight = 50;
        nDevFundAmount = 500000 * COIN;
        nDevFundInterval = 10;
        nDevFundMaxTimes = 100;

        strMarketingFundAddress = "t2Dsexh4v5g2dpL2LLCsR1p9TshMm63jSBM";
        nMarketingFundStartHeight = 51;
        nMarketingFundAmount = 500000 * COIN;
        nMarketingFundInterval = 10;
        nMarketingFundMaxTimes = 100;

        vecP2SHPublicKeys.resize(1);
        vecP2SHPublicKeys[0] = std::make_pair("04276f105ff36a670a56e75c2462cff05a4a7864756e6e1af01022e32752d6fe57b1e13cab4f2dbe3a6a51b4e0de83a5c4627345f5232151867850018c9a3c3a1d", 0);

    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}


// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}
std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    int current_height = (int)blockheight;
    if (current_height < 0)
        current_height = 0;

    int modified_height = (int)(current_height - params.GetConsensus().eh_epoch_fade_length);
    if (modified_height < 0)
        modified_height = 0;

    // AQUI GARANTE QUE USA ZELHASH SE O UPGRADE KAMIOOKA ESTIVER ATIVO
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        return 1;
    }

    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        ehparams[1]=params.eh_epoch_2_params();
        return 2;
    }

    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }

    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        ehparams[1]=params.eh_epoch_1_params();
        return 2;
    }

    ehparams[0]=params.eh_epoch_1_params();
    return 1;
}