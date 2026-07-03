// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "librustzcash.h"

JSDescription::JSDescription(
    ZCJoinSplit& params,
    const uint256& joinSplitPubKey,
    const uint256& anchor,
    const std::array<libflux::JSInput, ZC_NUM_JS_INPUTS>& inputs,
    const std::array<libflux::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
    CAmount vpub_old,
    CAmount vpub_new,
    bool computeProof,
    uint256 *esk // payment disclosure
) : vpub_old(vpub_old), vpub_new(vpub_new), anchor(anchor)
{
    std::array<libflux::SproutNote, ZC_NUM_JS_OUTPUTS> notes;

    proof = params.prove(
        inputs,
        outputs,
        notes,
        ciphertexts,
        ephemeralKey,
        joinSplitPubKey,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        anchor,
        computeProof,
        esk // payment disclosure
    );
}

JSDescription JSDescription::Randomized(
    ZCJoinSplit& params,
    const uint256& joinSplitPubKey,
    const uint256& anchor,
    std::array<libflux::JSInput, ZC_NUM_JS_INPUTS>& inputs,
    std::array<libflux::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
    std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
    std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
    CAmount vpub_old,
    CAmount vpub_new,
    bool computeProof,
    uint256 *esk, // payment disclosure
    std::function<int(int)> gen
)
{
    // Randomize the order of the inputs and outputs
    inputMap = {0, 1};
    outputMap = {0, 1};

    assert(gen);

    MappedShuffle(inputs.begin(), inputMap.begin(), ZC_NUM_JS_INPUTS, gen);
    MappedShuffle(outputs.begin(), outputMap.begin(), ZC_NUM_JS_OUTPUTS, gen);

    return JSDescription(
        params, joinSplitPubKey, anchor, inputs, outputs,
        vpub_old, vpub_new, computeProof,
        esk // payment disclosure
    );
}

class SproutProofVerifier : public boost::static_visitor<bool>
{
    ZCJoinSplit& params;
    libflux::ProofVerifier& verifier;
    const uint256& joinSplitPubKey;
    const JSDescription& jsdesc;

public:
    SproutProofVerifier(
        ZCJoinSplit& params,
        libflux::ProofVerifier& verifier,
        const uint256& joinSplitPubKey,
        const JSDescription& jsdesc
        ) : params(params), jsdesc(jsdesc), verifier(verifier), joinSplitPubKey(joinSplitPubKey) {}

    bool operator()(const libflux::PHGRProof& proof) const
    {
        // We checkpoint after Sapling activation, so we can skip verification
        // for all Sprout proofs.
        return true;
    }

    bool operator()(const libflux::GrothProof& proof) const
    {
        uint256 h_sig = params.h_sig(jsdesc.randomSeed, jsdesc.nullifiers, joinSplitPubKey);

        return librustzcash_sprout_verify(
            proof.begin(),
            jsdesc.anchor.begin(),
            h_sig.begin(),
            jsdesc.macs[0].begin(),
            jsdesc.macs[1].begin(),
            jsdesc.nullifiers[0].begin(),
            jsdesc.nullifiers[1].begin(),
            jsdesc.commitments[0].begin(),
            jsdesc.commitments[1].begin(),
            jsdesc.vpub_old,
            jsdesc.vpub_new
        );
    }
};

bool JSDescription::Verify(
    ZCJoinSplit& params,
    libflux::ProofVerifier& verifier,
    const uint256& joinSplitPubKey
) const {
    auto pv = SproutProofVerifier(params, verifier, joinSplitPubKey, *this);
    return boost::apply_visitor(pv, proof);
}

uint256 JSDescription::h_sig(ZCJoinSplit& params, const uint256& joinSplitPubKey) const
{
    return params.h_sig(randomSeed, nullifiers, joinSplitPubKey);
}

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

std::string COutPoint::ToFullString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString(), n);
}

std::string COutPoint::GetTxHash() const
{
    return strprintf("%s", hash.ToString());
}

std::string COutPoint::GetTxIndex() const
{
    return strprintf("%u", n);
}


std::string SaplingOutPoint::ToString() const
{
    return strprintf("SaplingOutPoint(%s, %u)", hash.ToString().substr(0, 10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != std::numeric_limits<unsigned int>::max())
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::SPROUT_MIN_CURRENT_VERSION), fOverwintered(false), nVersionGroupId(0), nExpiryHeight(0), nLockTime(0), valueBalance(0), csappLockedAmount(0), opoiMaxTokens(0), opoiTokenCount(0), opoiTaskType(0), opoiPayment(0), opoiFeePerToken(0), opoiSigTime(0), opoiCollateralIn(), opoiChallengePhase(0), opoiChallengerCollateralIn(), opoiResponsePhase(0), opoiTier(0), opoiPromptTokenCount(0), opoiIsCanary(0), opoiFotonVerifyResult(0), opoiFotonCollateralIn() {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nExpiryHeight(tx.nExpiryHeight),
                                                                   vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime),
                                                                   valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput),
                                                                   vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig),
                                                                   bindingSig(tx.bindingSig), nType(tx.nType), collateralIn(tx.collateralIn), collateralPubkey(tx.collateralPubkey),
                                                                   pubKey(tx.pubKey), sigTime(tx.sigTime), ip(tx.ip), sig(tx.sig), benchmarkTier(tx.benchmarkTier),
                                                                   benchmarkSig(tx.benchmarkSig), benchmarkSigTime(tx.benchmarkSigTime), nUpdateType(tx.nUpdateType),
                                                                   nFluxTxVersion(tx.nFluxTxVersion), P2SHRedeemScript(tx.P2SHRedeemScript),
                                                                   csappDeploymentId(tx.csappDeploymentId), csappOwner(tx.csappOwner),
                                                                   csappSpecJson(tx.csappSpecJson), csappIp(tx.csappIp),
                                                                   csappLockedAmount(tx.csappLockedAmount), csappSig(tx.csappSig),
                                                                   opoiRequestId(tx.opoiRequestId), opoiRequester(tx.opoiRequester),
                                                                   opoiMinerAddress(tx.opoiMinerAddress), opoiModel(tx.opoiModel),
                                                                   opoiPromptHash(tx.opoiPromptHash), opoiResponseHash(tx.opoiResponseHash),
                                                                   opoiCommitment(tx.opoiCommitment),
                                                                   opoiMaxTokens(tx.opoiMaxTokens), opoiTokenCount(tx.opoiTokenCount),
                                                                   opoiTaskType(tx.opoiTaskType),
                                                                   opoiTaskClass(tx.opoiTaskClass),
                                                                   opoiPayment(tx.opoiPayment), opoiFeePerToken(tx.opoiFeePerToken),
                                                                   opoiSigTime(tx.opoiSigTime), opoiSig(tx.opoiSig),
                                                                   opoiVrfProof(tx.opoiVrfProof),
                                                                   opoiCollateralIn(tx.opoiCollateralIn),
                                                                   opoiChallengePhase(tx.opoiChallengePhase),
                                                                   opoiCommitHash(tx.opoiCommitHash),
                                                                   opoiProofData(tx.opoiProofData),
                                                                   opoiChallengeNonce(tx.opoiChallengeNonce),
                                                                   opoiChallengerCollateralIn(tx.opoiChallengerCollateralIn),
                                                                   opoiResponsePhase(tx.opoiResponsePhase),
                                                                   opoiResponseCommitHash(tx.opoiResponseCommitHash),
                                                                   opoiResponseNonce(tx.opoiResponseNonce),
                                                                   opoiVrfOutput(tx.opoiVrfOutput),
                                                                   opoiModelId(tx.opoiModelId),
                                                                   opoiTier(tx.opoiTier),
                                                                   opoiPomRoot(tx.opoiPomRoot),
                                                                   opoiHostedExpertIds(tx.opoiHostedExpertIds),
                                                                   opoiPromptTokenCount(tx.opoiPromptTokenCount),
                                                                   opoiIsCanary(tx.opoiIsCanary),
                                                                   opoiTestSuite(tx.opoiTestSuite),
                                                                   opoiFotonAddress(tx.opoiFotonAddress),
                                                                   opoiFotonVerifyResult(tx.opoiFotonVerifyResult),
                                                                   opoiFotonCollateralIn(tx.opoiFotonCollateralIn),
                                                                   opoiModelArchType(tx.opoiModelArchType),
                                                                   opoiModelTotalParams(tx.opoiModelTotalParams),
                                                                   opoiModelActiveParamsPerToken(tx.opoiModelActiveParamsPerToken),
                                                                   opoiModelNumLayers(tx.opoiModelNumLayers),
                                                                   opoiModelNumDenseShards(tx.opoiModelNumDenseShards),
                                                                   opoiModelNumExperts(tx.opoiModelNumExperts),
                                                                   opoiModelTopKExperts(tx.opoiModelTopKExperts),
                                                                   opoiModelExpertPomRoots(tx.opoiModelExpertPomRoots),
                                                                   opoiModelMinRewardPerToken(tx.opoiModelMinRewardPerToken),
                                                                   opoiModelVoteApprove(tx.opoiModelVoteApprove),
                                                                   opoiShardIndex(tx.opoiShardIndex)
{
}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this);
}

std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CMutableTransaction(ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
                     nVersion,
                     vin.size(),
                     vout.size(),
                     nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}


void CTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

CTransaction::CTransaction() : nVersion(CTransaction::SPROUT_MIN_CURRENT_VERSION), fOverwintered(false), nVersionGroupId(0), nExpiryHeight(0), vin(), vout(), nLockTime(0),
                               valueBalance(0), vShieldedSpend(), vShieldedOutput(), vJoinSplit(), joinSplitPubKey(), joinSplitSig(), bindingSig(), nType(FLUXNODE_NO_TYPE),
                               collateralIn(), collateralPubkey(), pubKey(), sigTime(0), ip(), sig(), benchmarkTier(0), benchmarkSig(), benchmarkSigTime(0), nUpdateType(0),
                               nFluxTxVersion(0), P2SHRedeemScript(), csappDeploymentId(), csappOwner(), csappSpecJson(), csappIp(), csappLockedAmount(0), csappSig(),
                               opoiRequestId(), opoiRequester(), opoiMinerAddress(), opoiModel(),
                               opoiPromptHash(), opoiResponseHash(), opoiCommitment(),
                               opoiMaxTokens(0), opoiTokenCount(0), opoiTaskType(0), opoiTaskClass(0),
                               opoiPayment(0), opoiFeePerToken(0), opoiSigTime(0), opoiSig(), opoiVrfProof(),
                               opoiCollateralIn(), opoiChallengePhase(0), opoiCommitHash(), opoiProofData(),
                               opoiChallengeNonce(), opoiChallengerCollateralIn(), opoiResponsePhase(0),
                               opoiResponseCommitHash(), opoiResponseNonce(), opoiVrfOutput(), opoiModelId(),
                               opoiTier(0), opoiPomRoot(), opoiHostedExpertIds(), opoiPromptTokenCount(0), opoiIsCanary(0),
                               opoiTestSuite(), opoiFotonAddress(), opoiFotonVerifyResult(0),
                               opoiFotonCollateralIn(),
                               opoiModelArchType(0), opoiModelTotalParams(0), opoiModelActiveParamsPerToken(0),
                               opoiModelNumLayers(0), opoiModelNumDenseShards(0), opoiModelNumExperts(0), opoiModelTopKExperts(0),
                               opoiModelExpertPomRoots(), opoiModelMinRewardPerToken(0), opoiModelVoteApprove(0),
                               opoiShardIndex(0)  { }

CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nExpiryHeight(tx.nExpiryHeight),
                                                            vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime),
                                                            valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput),
                                                            vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig),
                                                            bindingSig(tx.bindingSig), nType(tx.nType), collateralIn(tx.collateralIn), collateralPubkey(tx.collateralPubkey),
                                                            pubKey(tx.pubKey), sigTime(tx.sigTime), ip(tx.ip), sig(tx.sig), benchmarkTier(tx.benchmarkTier),
                                                            benchmarkSig(tx.benchmarkSig), benchmarkSigTime(tx.benchmarkSigTime), nUpdateType(tx.nUpdateType),
                                                            nFluxTxVersion(tx.nFluxTxVersion), P2SHRedeemScript(tx.P2SHRedeemScript),
                                                            csappDeploymentId(tx.csappDeploymentId), csappOwner(tx.csappOwner),
                                                            csappSpecJson(tx.csappSpecJson), csappIp(tx.csappIp),
                                                            csappLockedAmount(tx.csappLockedAmount), csappSig(tx.csappSig),
                                                            opoiRequestId(tx.opoiRequestId), opoiRequester(tx.opoiRequester),
                                                            opoiMinerAddress(tx.opoiMinerAddress), opoiModel(tx.opoiModel),
                                                            opoiPromptHash(tx.opoiPromptHash), opoiResponseHash(tx.opoiResponseHash),
                                                            opoiCommitment(tx.opoiCommitment),
                                                            opoiMaxTokens(tx.opoiMaxTokens), opoiTokenCount(tx.opoiTokenCount),
                                                            opoiTaskType(tx.opoiTaskType),
                                                            opoiTaskClass(tx.opoiTaskClass),
                                                            opoiPayment(tx.opoiPayment), opoiFeePerToken(tx.opoiFeePerToken),
                                                            opoiSigTime(tx.opoiSigTime), opoiSig(tx.opoiSig),
                                                            opoiVrfProof(tx.opoiVrfProof),
                                                            opoiCollateralIn(tx.opoiCollateralIn),
                                                            opoiChallengePhase(tx.opoiChallengePhase),
                                                            opoiCommitHash(tx.opoiCommitHash),
                                                            opoiProofData(tx.opoiProofData),
                                                            opoiChallengeNonce(tx.opoiChallengeNonce),
                                                            opoiChallengerCollateralIn(tx.opoiChallengerCollateralIn),
                                                            opoiResponsePhase(tx.opoiResponsePhase),
                                                            opoiResponseCommitHash(tx.opoiResponseCommitHash),
                                                            opoiResponseNonce(tx.opoiResponseNonce),
                                                            opoiVrfOutput(tx.opoiVrfOutput),
                                                            opoiModelId(tx.opoiModelId),
                                                            opoiTier(tx.opoiTier),
                                                            opoiPomRoot(tx.opoiPomRoot),
                                                            opoiHostedExpertIds(tx.opoiHostedExpertIds),
                                                            opoiPromptTokenCount(tx.opoiPromptTokenCount),
                                                            opoiIsCanary(tx.opoiIsCanary),
                                                            opoiTestSuite(tx.opoiTestSuite),
                                                            opoiFotonAddress(tx.opoiFotonAddress),
                                                            opoiFotonVerifyResult(tx.opoiFotonVerifyResult),
                                                            opoiFotonCollateralIn(tx.opoiFotonCollateralIn),
                                                            opoiModelArchType(tx.opoiModelArchType),
                                                            opoiModelTotalParams(tx.opoiModelTotalParams),
                                                            opoiModelActiveParamsPerToken(tx.opoiModelActiveParamsPerToken),
                                                            opoiModelNumLayers(tx.opoiModelNumLayers),
                                                            opoiModelNumDenseShards(tx.opoiModelNumDenseShards),
                                                            opoiModelNumExperts(tx.opoiModelNumExperts),
                                                            opoiModelTopKExperts(tx.opoiModelTopKExperts),
                                                            opoiModelExpertPomRoots(tx.opoiModelExpertPomRoots),
                                                            opoiModelMinRewardPerToken(tx.opoiModelMinRewardPerToken),
                                                            opoiModelVoteApprove(tx.opoiModelVoteApprove),
                                                            opoiShardIndex(tx.opoiShardIndex)
{
    UpdateHash();
}

// Protected constructor which only derived classes can call.
// For developer testing only.
CTransaction::CTransaction(
    const CMutableTransaction &tx,
    bool evilDeveloperFlag) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nExpiryHeight(tx.nExpiryHeight),
                              vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime),
                              valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput),
                              vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig),
                              bindingSig(tx.bindingSig), nType(tx.nType), collateralIn(tx.collateralIn),
                              collateralPubkey(tx.collateralPubkey), pubKey(tx.pubKey), sigTime(tx.sigTime),
                              ip(tx.ip), sig(tx.sig), benchmarkTier(tx.benchmarkTier),
                              benchmarkSig(tx.benchmarkSig), benchmarkSigTime(tx.benchmarkSigTime),
                              nUpdateType(tx.nUpdateType), nFluxTxVersion(tx.nFluxTxVersion),
                              P2SHRedeemScript(tx.P2SHRedeemScript),
                              csappDeploymentId(tx.csappDeploymentId), csappOwner(tx.csappOwner),
                              csappSpecJson(tx.csappSpecJson), csappIp(tx.csappIp),
                              csappLockedAmount(tx.csappLockedAmount), csappSig(tx.csappSig),
                              opoiRequestId(tx.opoiRequestId), opoiRequester(tx.opoiRequester),
                              opoiMinerAddress(tx.opoiMinerAddress), opoiModel(tx.opoiModel),
                              opoiPromptHash(tx.opoiPromptHash), opoiResponseHash(tx.opoiResponseHash),
                              opoiCommitment(tx.opoiCommitment),
                              opoiMaxTokens(tx.opoiMaxTokens), opoiTokenCount(tx.opoiTokenCount),
                              opoiTaskType(tx.opoiTaskType),
                              opoiTaskClass(tx.opoiTaskClass),
                              opoiPayment(tx.opoiPayment), opoiFeePerToken(tx.opoiFeePerToken),
                              opoiSigTime(tx.opoiSigTime), opoiSig(tx.opoiSig),
                              opoiVrfProof(tx.opoiVrfProof),
                              opoiCollateralIn(tx.opoiCollateralIn),
                              opoiChallengePhase(tx.opoiChallengePhase),
                              opoiCommitHash(tx.opoiCommitHash),
                              opoiProofData(tx.opoiProofData),
                              opoiChallengeNonce(tx.opoiChallengeNonce),
                              opoiChallengerCollateralIn(tx.opoiChallengerCollateralIn),
                              opoiResponsePhase(tx.opoiResponsePhase),
                              opoiResponseCommitHash(tx.opoiResponseCommitHash),
                              opoiResponseNonce(tx.opoiResponseNonce),
                              opoiVrfOutput(tx.opoiVrfOutput),
                              opoiModelId(tx.opoiModelId),
                              opoiTier(tx.opoiTier),
                              opoiPomRoot(tx.opoiPomRoot),
                              opoiHostedExpertIds(tx.opoiHostedExpertIds),
                              opoiPromptTokenCount(tx.opoiPromptTokenCount),
                              opoiIsCanary(tx.opoiIsCanary),
                              opoiTestSuite(tx.opoiTestSuite),
                              opoiFotonAddress(tx.opoiFotonAddress),
                              opoiFotonVerifyResult(tx.opoiFotonVerifyResult),
                              opoiFotonCollateralIn(tx.opoiFotonCollateralIn),
                              opoiModelArchType(tx.opoiModelArchType),
                              opoiModelTotalParams(tx.opoiModelTotalParams),
                              opoiModelActiveParamsPerToken(tx.opoiModelActiveParamsPerToken),
                              opoiModelNumLayers(tx.opoiModelNumLayers),
                              opoiModelNumDenseShards(tx.opoiModelNumDenseShards),
                              opoiModelNumExperts(tx.opoiModelNumExperts),
                              opoiModelTopKExperts(tx.opoiModelTopKExperts),
                              opoiModelExpertPomRoots(tx.opoiModelExpertPomRoots),
                              opoiModelMinRewardPerToken(tx.opoiModelMinRewardPerToken),
                              opoiModelVoteApprove(tx.opoiModelVoteApprove),
                              opoiShardIndex(tx.opoiShardIndex)
{
    assert(evilDeveloperFlag);
}

CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId),
                                                       vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), nExpiryHeight(tx.nExpiryHeight),
                                                       valueBalance(tx.valueBalance),
                                                       vShieldedSpend(std::move(tx.vShieldedSpend)), vShieldedOutput(std::move(tx.vShieldedOutput)),
                                                       vJoinSplit(std::move(tx.vJoinSplit)),
                                                       joinSplitPubKey(std::move(tx.joinSplitPubKey)), joinSplitSig(std::move(tx.joinSplitSig)),
                                                       nType(tx.nType), collateralIn(tx.collateralIn), collateralPubkey(tx.collateralPubkey),
                                                       pubKey(tx.pubKey), sigTime(tx.sigTime), ip(tx.ip),
                                                       sig(tx.sig), benchmarkTier(tx.benchmarkTier), benchmarkSig(tx.benchmarkSig),
                                                       benchmarkSigTime(tx.benchmarkSigTime), nUpdateType(tx.nUpdateType), nFluxTxVersion(tx.nFluxTxVersion),
                                                       P2SHRedeemScript(tx.P2SHRedeemScript),
                                                       csappDeploymentId(tx.csappDeploymentId), csappOwner(tx.csappOwner),
                                                       csappSpecJson(tx.csappSpecJson), csappIp(tx.csappIp),
                                                       csappLockedAmount(tx.csappLockedAmount), csappSig(std::move(tx.csappSig)),
                                                       opoiRequestId(std::move(tx.opoiRequestId)), opoiRequester(std::move(tx.opoiRequester)),
                                                       opoiMinerAddress(std::move(tx.opoiMinerAddress)), opoiModel(std::move(tx.opoiModel)),
                                                       opoiPromptHash(tx.opoiPromptHash), opoiResponseHash(tx.opoiResponseHash),
                                                       opoiCommitment(tx.opoiCommitment),
                                                       opoiMaxTokens(tx.opoiMaxTokens), opoiTokenCount(tx.opoiTokenCount),
                                                       opoiTaskType(tx.opoiTaskType),
                                                       opoiTaskClass(tx.opoiTaskClass),
                                                       opoiPayment(tx.opoiPayment), opoiFeePerToken(tx.opoiFeePerToken),
                                                       opoiSigTime(tx.opoiSigTime), opoiSig(std::move(tx.opoiSig)),
                                                       opoiVrfProof(std::move(tx.opoiVrfProof)),
                                                       opoiCollateralIn(tx.opoiCollateralIn),
                                                       opoiChallengePhase(tx.opoiChallengePhase),
                                                       opoiCommitHash(std::move(tx.opoiCommitHash)),
                                                       opoiProofData(std::move(tx.opoiProofData)),
                                                       opoiChallengeNonce(std::move(tx.opoiChallengeNonce)),
                                                       opoiChallengerCollateralIn(tx.opoiChallengerCollateralIn),
                                                       opoiResponsePhase(tx.opoiResponsePhase),
                                                       opoiResponseCommitHash(std::move(tx.opoiResponseCommitHash)),
                                                       opoiResponseNonce(std::move(tx.opoiResponseNonce)),
                                                       opoiVrfOutput(std::move(tx.opoiVrfOutput)),
                                                       opoiModelId(std::move(tx.opoiModelId)),
                                                       opoiTier(tx.opoiTier),
                                                       opoiPomRoot(tx.opoiPomRoot),
                                                       opoiHostedExpertIds(std::move(tx.opoiHostedExpertIds)),
                                                       opoiPromptTokenCount(tx.opoiPromptTokenCount),
                                                       opoiIsCanary(tx.opoiIsCanary),
                                                       opoiTestSuite(tx.opoiTestSuite),
                                                       opoiFotonAddress(std::move(tx.opoiFotonAddress)),
                                                       opoiFotonVerifyResult(tx.opoiFotonVerifyResult),
                                                       opoiFotonCollateralIn(tx.opoiFotonCollateralIn),
                                                       opoiModelArchType(tx.opoiModelArchType),
                                                       opoiModelTotalParams(tx.opoiModelTotalParams),
                                                       opoiModelActiveParamsPerToken(tx.opoiModelActiveParamsPerToken),
                                                       opoiModelNumLayers(tx.opoiModelNumLayers),
                                                       opoiModelNumDenseShards(tx.opoiModelNumDenseShards),
                                                       opoiModelNumExperts(tx.opoiModelNumExperts),
                                                       opoiModelTopKExperts(tx.opoiModelTopKExperts),
                                                       opoiModelExpertPomRoots(std::move(tx.opoiModelExpertPomRoots)),
                                                       opoiModelMinRewardPerToken(tx.opoiModelMinRewardPerToken),
                                                       opoiModelVoteApprove(tx.opoiModelVoteApprove),
                                                       opoiShardIndex(tx.opoiShardIndex)
{
    UpdateHash();
}

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<bool*>(&fOverwintered) = tx.fOverwintered;
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<uint32_t*>(&nVersionGroupId) = tx.nVersionGroupId;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint32_t*>(&nExpiryHeight) = tx.nExpiryHeight;
    *const_cast<CAmount*>(&valueBalance) = tx.valueBalance;
    *const_cast<std::vector<SpendDescription>*>(&vShieldedSpend) = tx.vShieldedSpend;
    *const_cast<std::vector<OutputDescription>*>(&vShieldedOutput) = tx.vShieldedOutput;
    *const_cast<std::vector<JSDescription>*>(&vJoinSplit) = tx.vJoinSplit;
    *const_cast<uint256*>(&joinSplitPubKey) = tx.joinSplitPubKey;
    *const_cast<joinsplit_sig_t*>(&joinSplitSig) = tx.joinSplitSig;
    *const_cast<binding_sig_t*>(&bindingSig) = tx.bindingSig;
    *const_cast<uint256*>(&hash) = tx.hash;

    // Fluxnode tx data
    *const_cast<int8_t*>(&nType) = tx.nType;
    *const_cast<COutPoint*>(&collateralIn) = tx.collateralIn;
    *const_cast<CPubKey*>(&collateralPubkey) = tx.collateralPubkey;
    *const_cast<CPubKey*>(&pubKey) = tx.pubKey;
    *const_cast<uint32_t*>(&sigTime) = tx.sigTime;
    *const_cast<std::string*>(&ip) = tx.ip;
    *const_cast<std::vector<unsigned char>*>(&sig) = tx.sig;
    *const_cast<int8_t*>(&benchmarkTier) = tx.benchmarkTier;
    *const_cast<std::vector<unsigned char>*>(&benchmarkSig) = tx.benchmarkSig;
    *const_cast<uint32_t*>(&benchmarkSigTime) = tx.benchmarkSigTime;
    *const_cast<int8_t*>(&nUpdateType) = tx.nUpdateType;

    // P2SH Nodes
    *const_cast<int32_t*>(&nFluxTxVersion) = tx.nFluxTxVersion;
    *const_cast<CScript*>(&P2SHRedeemScript) = tx.P2SHRedeemScript;

    // CSApp tx data
    *const_cast<std::string*>(&csappDeploymentId) = tx.csappDeploymentId;
    *const_cast<std::string*>(&csappOwner) = tx.csappOwner;
    *const_cast<std::string*>(&csappSpecJson) = tx.csappSpecJson;
    *const_cast<std::string*>(&csappIp) = tx.csappIp;
    *const_cast<CAmount*>(&csappLockedAmount) = tx.csappLockedAmount;
    *const_cast<std::vector<unsigned char>*>(&csappSig) = tx.csappSig;

    // OPoI tx data
    *const_cast<std::string*>(&opoiRequestId) = tx.opoiRequestId;
    *const_cast<std::string*>(&opoiRequester) = tx.opoiRequester;
    *const_cast<std::string*>(&opoiMinerAddress) = tx.opoiMinerAddress;
    *const_cast<std::string*>(&opoiModel) = tx.opoiModel;
    *const_cast<uint256*>(&opoiPromptHash) = tx.opoiPromptHash;
    *const_cast<uint256*>(&opoiResponseHash) = tx.opoiResponseHash;
    *const_cast<uint256*>(&opoiCommitment) = tx.opoiCommitment;
    *const_cast<uint32_t*>(&opoiMaxTokens) = tx.opoiMaxTokens;
    *const_cast<uint32_t*>(&opoiTokenCount) = tx.opoiTokenCount;
    *const_cast<int8_t*>(&opoiTaskType) = tx.opoiTaskType;
    *const_cast<uint8_t*>(&opoiTaskClass) = tx.opoiTaskClass;
    *const_cast<CAmount*>(&opoiPayment) = tx.opoiPayment;
    *const_cast<CAmount*>(&opoiFeePerToken) = tx.opoiFeePerToken;
    *const_cast<uint32_t*>(&opoiSigTime) = tx.opoiSigTime;
    *const_cast<std::vector<unsigned char>*>(&opoiSig) = tx.opoiSig;
    *const_cast<std::vector<unsigned char>*>(&opoiVrfProof) = tx.opoiVrfProof;
    *const_cast<COutPoint*>(&opoiCollateralIn) = tx.opoiCollateralIn;
    *const_cast<uint8_t*>(&opoiChallengePhase) = tx.opoiChallengePhase;
    *const_cast<std::vector<uint8_t>*>(&opoiCommitHash) = tx.opoiCommitHash;
    *const_cast<std::vector<uint8_t>*>(&opoiProofData) = tx.opoiProofData;
    *const_cast<std::vector<uint8_t>*>(&opoiChallengeNonce) = tx.opoiChallengeNonce;
    *const_cast<COutPoint*>(&opoiChallengerCollateralIn) = tx.opoiChallengerCollateralIn;
    *const_cast<uint8_t*>(&opoiResponsePhase) = tx.opoiResponsePhase;
    *const_cast<std::vector<uint8_t>*>(&opoiResponseCommitHash) = tx.opoiResponseCommitHash;
    *const_cast<std::vector<uint8_t>*>(&opoiResponseNonce) = tx.opoiResponseNonce;
    *const_cast<std::vector<uint8_t>*>(&opoiVrfOutput) = tx.opoiVrfOutput;
    *const_cast<std::string*>(&opoiModelId) = tx.opoiModelId;
    *const_cast<uint8_t*>(&opoiTier) = tx.opoiTier;
    *const_cast<uint256*>(&opoiPomRoot) = tx.opoiPomRoot;
    *const_cast<std::vector<uint32_t>*>(&opoiHostedExpertIds) = tx.opoiHostedExpertIds;
    *const_cast<uint32_t*>(&opoiPromptTokenCount) = tx.opoiPromptTokenCount;
    *const_cast<uint8_t*>(&opoiIsCanary) = tx.opoiIsCanary;
    *const_cast<uint256*>(&opoiTestSuite) = tx.opoiTestSuite;
    *const_cast<std::string*>(&opoiFotonAddress) = tx.opoiFotonAddress;
    *const_cast<uint8_t*>(&opoiFotonVerifyResult) = tx.opoiFotonVerifyResult;
    *const_cast<COutPoint*>(&opoiFotonCollateralIn) = tx.opoiFotonCollateralIn;
    *const_cast<uint8_t*>(&opoiModelArchType) = tx.opoiModelArchType;
    *const_cast<uint64_t*>(&opoiModelTotalParams) = tx.opoiModelTotalParams;
    *const_cast<uint64_t*>(&opoiModelActiveParamsPerToken) = tx.opoiModelActiveParamsPerToken;
    *const_cast<uint32_t*>(&opoiModelNumLayers) = tx.opoiModelNumLayers;
    *const_cast<uint32_t*>(&opoiModelNumDenseShards) = tx.opoiModelNumDenseShards;
    *const_cast<uint32_t*>(&opoiModelNumExperts) = tx.opoiModelNumExperts;
    *const_cast<uint32_t*>(&opoiModelTopKExperts) = tx.opoiModelTopKExperts;
    *const_cast<std::vector<uint256>*>(&opoiModelExpertPomRoots) = tx.opoiModelExpertPomRoots;
    *const_cast<CAmount*>(&opoiModelMinRewardPerToken) = tx.opoiModelMinRewardPerToken;
    *const_cast<uint8_t*>(&opoiModelVoteApprove) = tx.opoiModelVoteApprove;
    *const_cast<uint32_t*>(&opoiShardIndex) = tx.opoiShardIndex;

    return *this;
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }

    if (valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -valueBalance;

        if (!MoneyRange(-valueBalance) || !MoneyRange(nValueOut)) {
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
        }
    }

    for (std::vector<JSDescription>::const_iterator it(vJoinSplit.begin()); it != vJoinSplit.end(); ++it)
    {
        // NB: vpub_old "takes" money from the transparent value pool just as outputs do
        nValueOut += it->vpub_old;

        if (!MoneyRange(it->vpub_old) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
    return nValueOut;
}

CAmount CTransaction::GetShieldedValueIn() const
{
    CAmount nValue = 0;

    if (valueBalance >= 0) {
        // NB: positive valueBalance "gives" money to the transparent value pool just as inputs do
        nValue += valueBalance;

        if (!MoneyRange(valueBalance) || !MoneyRange(nValue)) {
            throw std::runtime_error("CTransaction::GetShieldedValueIn(): value out of range");
        }
    }

    for (std::vector<JSDescription>::const_iterator it(vJoinSplit.begin()); it != vJoinSplit.end(); ++it)
    {
        // NB: vpub_new "gives" money to the transparent value pool just as inputs do
        nValue += it->vpub_new;

        if (!MoneyRange(it->vpub_new) || !MoneyRange(nValue))
            throw std::runtime_error("CTransaction::GetShieldedValueIn(): value out of range");
    }

    return nValue;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

std::string CTransaction::ToString() const
{
    if (nVersion == FLUXNODE_TX_VERSION) {
        return strprintf("CTransaction(hash=%s, ver=%d, type=%d)\n",
                         GetHash().ToString().substr(0,10),
                         nVersion,
                         nType);
    }

    std::string str;
    if (!fOverwintered) {
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
    } else if (nVersion >= SAPLING_MIN_TX_VERSION) {
        str += strprintf("CTransaction(hash=%s, ver=%d, fOverwintered=%d, nVersionGroupId=%08x, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u, valueBalance=%u, vShieldedSpend.size=%u, vShieldedOutput.size=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            fOverwintered,
            nVersionGroupId,
            vin.size(),
            vout.size(),
            nLockTime,
            nExpiryHeight,
            valueBalance,
            vShieldedSpend.size(),
            vShieldedOutput.size());
    } else if (nVersion >= 3) {
        str += strprintf("CTransaction(hash=%s, ver=%d, fOverwintered=%d, nVersionGroupId=%08x, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            fOverwintered,
            nVersionGroupId,
            vin.size(),
            vout.size(),
            nLockTime,
            nExpiryHeight);
    }
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}
