// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "primitives/block.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "key.h"
#include "poc.h"
#include "base58.h"
#include "chainparamsseeds.h"

#include <stdio.h>
#include <assert.h>
#include <boost/assign/list_of.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

CDynamicChainParams dynParams;
string strChainName;

#define SHOW_GENESIS_HASHES 0

#if SHOW_GENESIS_HASHES
#define PRINT_HASHES \
    printf("%s parameters\n" \
            "block hash   : %s\n" \
            "merkle root  : %s\n" \
            "payload hash : %s\n\n", \
            strNetworkID.c_str(), \
            consensus.hashGenesisBlock.ToString().c_str(), \
            genesis.hashMerkleRoot.ToString().c_str(), \
            genesis.hashPayload.ToString().c_str())
#endif

#define CHECK_PARAM(a,b,c) \
    param = c[a]; \
    if (param.isNull()) { \
        fprintf(stderr, "\"" a "\" was not found in the definition file.\n"); \
        return false; \
    } \
    if (param.getType() != b) { \
        fprintf(stderr, "\"" a "\" is of wrong type.\n"); \
        return false; \
    }

#define GENESIS_BLOCK_TIMESTAMP 1500364800
const char* genesisMessage = "FairCoin - the currency for a fair economy.";

CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nCreatorId, const CDynamicChainParams& dynamicChainParams)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << OP_0 << CScriptNum(GENESIS_NODE_ID) << OP_0; // Serialised block height + genesis node ID + zero
    txNew.vout[0].nValue = 0;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>((uint8_t*)genesisMessage, (uint8_t*)genesisMessage + strlen(genesisMessage));

    CBlock genesis;
    genesis.nVersion   = CBlock::CURRENT_VERSION | CBlock::TX_PAYLOAD | CBlock::CVN_PAYLOAD | CBlock::CHAIN_PARAMETERS_PAYLOAD | CBlock::CHAIN_ADMINS_PAYLOAD;
    genesis.nTime      = nTime;
    genesis.nCreatorId = nCreatorId;
    genesis.hashPrevBlock.SetNull();
    genesis.vtx.push_back(txNew);
    genesis.dynamicChainParams = dynamicChainParams;
    return genesis;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        vAlertPubKey = ParseHex("04b06af4982ca3edc2c040cc2cde05fa5b33264af4a98712ceb29d196e7390b4753eb7264dc5f383f29a44d63e70dbbd8d9e46a0a60f80ef62fd1911291ec388e4");
        nDefaultPort = 40404;
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 3 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 60;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 0 * CENT; // 0 FAIR per Kb
        dynParams.nDustThreshold               = 0 * CENT; // 0 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 50; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 15; // 15 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("041cbfa5cb7dbe6387c0808264feb7adc9d99a003da4922e839a548955307f3d365f9fe6fa76767e848660ec864c9f3075fdcdf3e3755af9e3c2662004979ff580"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("591039a3b2e2c5ca8cd491e940263c9f2515a43b5085d4451dbdf8c09acb3d1fe7001957ebeda65a3cd26f1d19fb3db3b06baf5dc41cdcd3412728c8b57edaf5");
        genesis.creatorSignature = CSchnorrSigS("ced5d4d4f5967b80ca774324a5d9ab0569ec1f1608dfef6c1e439094dc3467d50b2116fa02f3e89753033e94628668298f61b43df046881c9312f3bccde46a3f");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("beed44fa5e96150d95d56ebd5d2625781825a9407a5215dd7eda723373a0a1d7"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        assert(genesis.hashPayload == uint256S("2b7ab86ef7189614d4bccb2576bffe834b7c0e6d3fd63539ea9fbbca45d26c0e"));
#endif
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-seed1.fair-coin.org")); // Thomas König
        vSeeds.push_back(CDNSSeedData("2.fair-coin.org", "faircoin2-seed2.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,36);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fCreateBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

#if 0
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("49443ff1f4876f972e130e19c0969794aefd7aeb57ec65cdda386eea22a36cb2")),
            1462293889, // * UNIX timestamp of last checkpoint block
            0,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0     // * estimated number of transactions per day after checkpoint
        };
#endif
    }
};
static CMainParams mainParams;

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        pchMessageStart[0] = 0x0c;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x0a;
        pchMessageStart[3] = 0x08;
        vAlertPubKey = ParseHex("045894f38e9dd72b6f210c261d40003eb087030c42b102d3b238b396256d02f5a380ff3b7444d306d9e118fa1fc7b2b7594875f4eb64bbeaa31577391d85eb5a8a");
        nDefaultPort = 41404;
        nPruneAfterHeight = 1000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 2 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 45;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 50; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 15; // 15 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 1, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("041cbfa5cb7dbe6387c0808264feb7adc9d99a003da4922e839a548955307f3d365f9fe6fa76767e848660ec864c9f3075fdcdf3e3755af9e3c2662004979ff580"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("0c9cce30058d3a2e8e154d6bf9ab6ae94098a4e2d539bf27f0236e26dee86d1e9a37df700bdd4b991310046b069b0b84ce62371f6c8ab8949e19831d4b071231");
        genesis.creatorSignature = CSchnorrSigS("377599b4021c3e35a40667466734d2d1a3a1ef94cf52e1f5a6863af180ed7258982869d956ff34251ef4e13d7fd341a68c3e47007b5cbc0c67860a8956df9e71");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("42327d5edf3cbb75bb139ec78bd62e517f14d7cbad451e4778741b6b4c1dfbc6"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        assert(genesis.hashPayload == uint256S("1c4ed40a950abbd27f4cd57e1ccb6613a956ce9edb16210cd5acb12f708389f3"));
#endif
        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-testnet-seed1.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fCreateBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

#if 0
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("fac71114e0630bb4c8722144ea843fcc8b465ac77820e86251d37141bd3da26e")),
            1461766275,
            1488,
            300
        };
#endif
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

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 42404;
        nPruneAfterHeight = 1000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 1 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 30;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 20; // 20 sec.
        dynParams.nRetryNewSigSetInterval      = 7; // 7 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 2, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("041cbfa5cb7dbe6387c0808264feb7adc9d99a003da4922e839a548955307f3d365f9fe6fa76767e848660ec864c9f3075fdcdf3e3755af9e3c2662004979ff580"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("3ac684b4ea4df55e3c5b23af67494489a01f7b5263d293952313bad3debf8b4d936c86556ad92b1e0c5189141d5c6b9cc172a6e2775781b840e5d03418e7f8aa");
        genesis.creatorSignature = CSchnorrSigS("2475495c2135e34acf104bb060abebd78c3948ca5048dbb1ff4dde0c1970a729d78667da56fc776a09edd5185b9153e1e6821111c08f62784308aeda4c91a1a3");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("335a7133066fe45cc6b1b7d48a5b589153bec2df38c069caf6c05a96f2ec0b76"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        assert(genesis.hashPayload == uint256S("10f08b71d33acab5031e62f2d6987398567e04988ed5810a893f12a72f3f5193"));
#endif
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fCreateBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

#if 0
        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("fac71114e0630bb4c8722144ea843fcc8b465ac77820e86251d37141bd3da26e")),
            1461766275,
            0,
            0
        };
#endif
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }
};
static CRegTestParams regTestParams;


class CCustomParams : public CChainParams {
public:
    CCustomParams() {
        strNetworkID = "custom";
    }

    bool isInitialised()
    {
        return fInitialised;
    }

    void init(const string &chainName)
    {
        strChainName = chainName;
        fInitialised = true;
    }

private:
    bool fInitialised = false;
    string strChainName;
};
static CCustomParams customParams;

static uint32_t str2Uint32(const UniValue& param)
{
    uint32_t nValue;
    stringstream ss;
    ss << hex << param.getValStr();
    ss >> nValue;

    return nValue;
}

static bool ParseDynamicChainParameters(CDynamicChainParams& dp, const UniValue& valNetDef)
{
    UniValue param;

    CHECK_PARAM("blockSpacing", UniValue::VNUM, valNetDef);
    dp.nBlockSpacing = param.get_int();

    CHECK_PARAM("blockSpacingGracePeriod", UniValue::VNUM, valNetDef);
    dp.nBlockSpacingGracePeriod = param.get_int();

    CHECK_PARAM("maxAdminSigs", UniValue::VNUM, valNetDef);
    dp.nMaxAdminSigs = param.get_int();

    CHECK_PARAM("minAdminSigs", UniValue::VNUM, valNetDef);
    dp.nMinAdminSigs = param.get_int();

    CHECK_PARAM("transactionFee", UniValue::VNUM, valNetDef);
    dp.nTransactionFee = param.get_int64();

    CHECK_PARAM("dustThreshold", UniValue::VNUM, valNetDef);
    dp.nDustThreshold = param.get_int64();

    CHECK_PARAM("minSuccessiveSignatures", UniValue::VNUM, valNetDef);
    dp.nMinSuccessiveSignatures = param.get_int();

    CHECK_PARAM("blocksToConsiderForSigCheck", UniValue::VNUM, valNetDef);
    dp.nBlocksToConsiderForSigCheck = param.get_int();

    CHECK_PARAM("percentageOfSignaturesMean", UniValue::VNUM, valNetDef);
    dp.nPercentageOfSignaturesMean = param.get_int();

    CHECK_PARAM("maxBlockSize", UniValue::VNUM, valNetDef);
    dp.nMaxBlockSize = param.get_int();

    CHECK_PARAM("blockPropagationWaitTime", UniValue::VNUM, valNetDef);
    dp.nBlockPropagationWaitTime = param.get_int();

    CHECK_PARAM("retryNewSigSetInterval", UniValue::VNUM, valNetDef);
    dp.nRetryNewSigSetInterval = param.get_int();

    CHECK_PARAM("coinbaseMaturity", UniValue::VNUM, valNetDef);
    dp.nCoinbaseMaturity = param.get_int();

    CHECK_PARAM("description", UniValue::VSTR, valNetDef);
    dp.strDescription = param.getValStr();

    return true;
}

static bool CreateGenesisBlock(CCustomParams& p, const UniValue& valNetDef)
{
    UniValue param;
    CHECK_PARAM("jsonVersion", UniValue::VNUM, valNetDef);
    if (param.get_int() != 1) {
        fprintf(stderr, "invalid json version: %d\n", param.get_int());
        return false;
    }

    CHECK_PARAM("chainName", UniValue::VSTR, valNetDef);
    strChainName = param.getValStr();
    if (strChainName.empty() || strChainName.size() > 64) {
        fprintf(stderr, "chainName is empty or too long\n");
        return false;
    }
    p.SetNetworkIDString("custom");

    CHECK_PARAM("networkMagic", UniValue::VSTR, valNetDef);
    p.SetMessageStart(str2Uint32(param));

    CHECK_PARAM("alertPubKey", UniValue::VSTR, valNetDef);
    vector<unsigned char> vAlertPubKey = ParseHex(param.getValStr());
    if (vAlertPubKey.size() != 65) {
        fprintf(stderr, "invalid alertPubKey length\n");
        return false;
    }
    p.SetAlertKey(vAlertPubKey);

    CHECK_PARAM("defaultPort", UniValue::VNUM, valNetDef);
    int nPort = param.get_int();
    if (nPort < 1 || nPort > 0xffff /* || nPort == mainParams.GetDefaultPort()*/ || nPort == testNetParams.GetDefaultPort()) {
        fprintf(stderr, "invalid default port: %d\n", nPort);
        return false;
    }
    p.SetDefaultPort(nPort);

    CHECK_PARAM("seedNodes", UniValue::VARR, valNetDef);
    const UniValue& nodes = param.get_array();
    std::vector<CDNSSeedData> vSeeds;
    for (unsigned int idx = 0; idx < nodes.size(); idx++) {
        const UniValue& node = nodes[idx];
        if (node.isNull() || node.getType() != UniValue::VSTR) {
            fprintf(stderr, "invalid entry in \"seedNodes\"\n");
            return false;
        }
        vSeeds.push_back(CDNSSeedData((idx + 1) + ".custom.fair-coin.org", node.getValStr()));
    }
    p.SetDNSSeeds(vSeeds);

    CHECK_PARAM("fixedSeeds", UniValue::VARR, valNetDef);
    const UniValue& fixedSeeds = param.get_array();
    std::vector<SeedSpec6> vFixedSeeds;
    for (unsigned int idx = 0; idx < fixedSeeds.size(); idx++) {
        const UniValue& node = nodes[idx];
        if (node.isNull() || node.getType() != UniValue::VOBJ) {
            fprintf(stderr, "invalid entry in \"fixedSeeds\"\n");
            return false;
        }

        CHECK_PARAM("ipAddress", UniValue::VSTR, node);
        const string& ipAddr = param.getValStr();
        if (ipAddr.size() != 32) {
            fprintf(stderr, "invalid ip address %s in \"fixedSeeds\"\n", ipAddr.c_str());
            return false;
        }
        vector<unsigned char> vIpAddr = ParseHex(param.getValStr());

        SeedSpec6 entry;
        memcpy(entry.addr, &vIpAddr[0], 16);

        CHECK_PARAM("port", UniValue::VNUM, node);
        entry.port = param.get_int();

        vFixedSeeds.push_back(entry);
    }
    p.SetFixedSeeds(vFixedSeeds);

    CHECK_PARAM("pubKeyAddrVersion", UniValue::VNUM, valNetDef);
    int nAddrVer = param.get_int();
    if (nAddrVer < 1 || nAddrVer > 255) {
        fprintf(stderr, "\"pubKeyAddrVersion\" out of range\n");
        return false;
    }
    std::vector<unsigned char> addrVer(1,nAddrVer);
    p.SetBase58Prefix(addrVer, CChainParams::PUBKEY_ADDRESS);

    CHECK_PARAM("scriptAddrVersion", UniValue::VNUM, valNetDef);
    nAddrVer = param.get_int();
    if (nAddrVer < 1 || nAddrVer > 255) {
        fprintf(stderr, "\"scriptAddrVersion\" out of range\n");
        return false;
    }
    std::vector<unsigned char> scriptVer(1,nAddrVer);
    p.SetBase58Prefix(scriptVer, CChainParams::SCRIPT_ADDRESS);

    CHECK_PARAM("secretKeyVersion", UniValue::VNUM, valNetDef);
    nAddrVer = param.get_int();
    if (nAddrVer < 1 || nAddrVer > 255) {
        fprintf(stderr, "\"scriptAddrVersion\" out of range\n");
        return false;
    }
    std::vector<unsigned char> secretVer(1,nAddrVer);
    p.SetBase58Prefix(secretVer, CChainParams::SECRET_KEY);

    CHECK_PARAM("extPubKeyPrefix", UniValue::VSTR, valNetDef);
    uint32_t nExtPK = str2Uint32(param);

    std::vector<unsigned char> extPub = boost::assign::list_of
            ((nExtPK >>  0) & 0xff)
            ((nExtPK >>  8) & 0xff)
            ((nExtPK >> 16) & 0xff)
            ((nExtPK >> 24) & 0xff).convert_to_container<std::vector<unsigned char> >();
    p.SetBase58Prefix(extPub, CChainParams::EXT_PUBLIC_KEY);

    CHECK_PARAM("extSecretPrefix", UniValue::VSTR, valNetDef);
    uint32_t nExtSK = str2Uint32(param);

    std::vector<unsigned char> extSec = boost::assign::list_of
            ((nExtSK >>  0) & 0xff)
            ((nExtSK >>  8) & 0xff)
            ((nExtSK >> 16) & 0xff)
            ((nExtSK >> 24) & 0xff).convert_to_container<std::vector<unsigned char> >();
    p.SetBase58Prefix(extSec, CChainParams::EXT_SECRET_KEY);

    CHECK_PARAM("requireStandardTx", UniValue::VBOOL, valNetDef);
    p.SetRequireStandard(param.getBool());

    CHECK_PARAM("dynamicChainParams", UniValue::VOBJ, valNetDef);
    CDynamicChainParams dynParams;
    if (!ParseDynamicChainParameters(dynParams, param) || !CheckDynamicChainParameters(dynParams)) {
        return false;
    }

    CHECK_PARAM("blockchainStartTime", UniValue::VNUM, valNetDef);
    uint32_t nTimeStamp = param.get_int();

    CHECK_PARAM("genesisCvnID", UniValue::VSTR, valNetDef);
    uint32_t nGenesisCvnID = str2Uint32(param);
    CHECK_PARAM("genesisAdminID", UniValue::VSTR, valNetDef);
    uint32_t nGenesisAdminID = str2Uint32(param);

    CBlock genesis = CreateGenesisBlock(nTimeStamp, nGenesisCvnID, dynParams);

    CHECK_PARAM("genesisCvnPubKey", UniValue::VSTR, valNetDef);
    genesis.vCvns.resize(1);
    genesis.vCvns[0] = CCvnInfo(nGenesisCvnID, 0, CSchnorrPubKeyS(param.getValStr()));

    CHECK_PARAM("genesisAdminPubKey", UniValue::VSTR, valNetDef);
    genesis.vChainAdmins.resize(1);
    genesis.vChainAdmins[0] = CChainAdmin(nGenesisAdminID, 0, CSchnorrPubKeyS(param.getValStr()));

    CHECK_PARAM("chainMultiSig", UniValue::VSTR, valNetDef);
    genesis.chainMultiSig = CSchnorrSigS(param.getValStr());
    genesis.vAdminIds.push_back(nGenesisAdminID);

    CHECK_PARAM("adminMultiSig", UniValue::VSTR, valNetDef);
    genesis.adminMultiSig = CSchnorrSigS(param.getValStr());

    CHECK_PARAM("creatorSignature", UniValue::VSTR, valNetDef);
    genesis.creatorSignature = CSchnorrSigS(param.getValStr());

    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashPayload    = genesis.GetPayloadHash();

    p.SetGenesisBlock(genesis);
    const uint256 genesisHash = genesis.GetHash();

    p.SetConsensusGenesisHash(genesisHash);

    CHECK_PARAM("blockHash", UniValue::VSTR, valNetDef);
    const string strBlockHash = param.getValStr();
    if (genesisHash != uint256S(strBlockHash)) {
        fprintf(stderr, "could not verify \"blockHash\"\n");
        return false;
    }

    CHECK_PARAM("merkleRoot", UniValue::VSTR, valNetDef);
    const string strMerkleRoot = param.getValStr();
    if (genesis.hashMerkleRoot != uint256S(strMerkleRoot)) {
        fprintf(stderr, "could not verify \"merkleRoot\"\n");
        return false;
    }

    CHECK_PARAM("payloadHash", UniValue::VSTR, valNetDef);
    const string strPayloadHash = param.getValStr();
    if (genesis.hashPayload != uint256S(strPayloadHash)) {
        fprintf(stderr, "could not verify \"payloadHash\"\n");
        return false;
    }

    return true;
}

static std::vector<CSchnorrPubKey> officialChainParamPubKeys = boost::assign::list_of
   (CSchnorrPubKeyDER("04a2bb310b665a2479666b0b4e591cce3ddede393a26954bf1b0ebd37a1b666cb2acb4396bcdeeec15d9aabaae3477122aa7a0286049e338ca5237f33b0f9ad31e"))
   (CSchnorrPubKeyDER("04d7175ec64a05994dd85e95127ecdaffc2f2135b2b72255bca9c0c002b23e0607b947629d59712bfa66d1c8b499333ca1625da054ad281f1767e7e5e42c565f54"))
;

bool fOfficialFairChain = false;

static bool ReadCustomParams(UniValue &valNetDef)
{
    const std::string strNetName = GetArg("-netname", "");
    if (strNetName.empty())
        throw std::runtime_error(strprintf("%s: internal error, chain name unavailable.", __func__));

    const std::string strFileName = strNetName + ".json";

    fprintf(stdout, "Reading custom chain parameters from file: %s\n", (GetDataDir(false) / strFileName).c_str());

    boost::filesystem::ifstream streamNetDef(GetDataDir(false) / strFileName);
    if (!streamNetDef.good()) {
        fprintf(stderr, "ERROR: could not find file %s\n", strFileName.c_str());
        return false;
    }

    std::string str((std::istreambuf_iterator<char>(streamNetDef)), std::istreambuf_iterator<char>());
    if (!valNetDef.read(str)) {
        fprintf(stderr, "ERROR: could not parse file %s\n", strFileName.c_str());
        return false;
    }

    return true;
}

bool InitialiseCustomParams(const UniValue &valNetDef, const char *pFileName, const bool fUnsignedPenalty)
{
    UniValue param;
    CHECK_PARAM("data", UniValue::VOBJ, valNetDef);
    const UniValue valData = param;

    CHashWriter hasher(SER_GETHASH, 0);
    hasher << std::string("Official FairChains parameter file");
    hasher << param.write(0, 0);

    const uint256 hashData = hasher.GetHash();

    CHECK_PARAM("sign", UniValue::VOBJ, valNetDef);
    const UniValue valSign = param;

    CHECK_PARAM("hash", UniValue::VSTR, valNetDef);
    const uint256 hashCheck = uint256S(param.getValStr());

    if (hashData != hashCheck) {
        fprintf(stderr, "ERROR: file %s most probably corrupted. Hash check failed.\n", pFileName);
        return false;
    }

    CHECK_PARAM("signature", UniValue::VSTR, valSign);
    const std::string strSignature = param.getValStr();

    if (strSignature.empty()) {
        if (fUnsignedPenalty) {
            fprintf(stderr, "WARNING: file %s does not contain a signature and can not be verified.\nThis is NOT an official FairChain.\n", pFileName);
            MilliSleep(5000);
        }
    } else {
        CHashWriter hasherSig(SER_GETHASH, 0);
        hasherSig << hashData;

        CHECK_PARAM("comment", UniValue::VSTR, valSign);
        hasherSig << param.getValStr();

        uint256 hashSig = hasherSig.GetHash();

        if (strSignature.size() != 2 * 64) {
            reverse(hashSig.begin(), hashSig.end()); // reverse it so hashSig.ToString() displays it correctly
            fprintf(stderr, "ERROR: invalid signature in file %s for hash %s.\n", pFileName, hashSig.ToString().c_str());
            return false;
        }

        const CSchnorrSig sigData = CSchnorrSigS(strSignature);

        // secp256k1 context does exists yet. Create a temporary context for signature verification
        ECCVerifyHandle *ptrHandle = new ECCVerifyHandle();
        bool fGoodSignature = false;

        BOOST_FOREACH(const CSchnorrPubKey &pubKey, officialChainParamPubKeys) {
            fGoodSignature = CPubKey::VerifySchnorr(hashSig, sigData, pubKey);
            if (fGoodSignature) {
                fprintf(stderr, "Successfully verified signature of file %s. This is an official FairChain.\n", pFileName);
                fOfficialFairChain = true;
                break;
            }
        }

        delete ptrHandle;

        if (!fGoodSignature) {
            fprintf(stderr, "ERROR: could not verify signature in file %s.\n", pFileName);
            return false;
        }
    }

    if (!CreateGenesisBlock(customParams, valData)) {
        return false;
    }

    return true;
}

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else if (chain == CBaseChainParams::CUSTOM) {
        if (!customParams.isInitialised()) {
            UniValue valNetDef(UniValue::VOBJ); // network definition information in JSON format

            if (!ReadCustomParams(valNetDef)) {
                throw std::runtime_error(strprintf("%s: error could not read custom parameters file", __func__));
            }

            const string strJsonFileName = GetArg("-netname", "") + ".json";

            if (!InitialiseCustomParams(valNetDef, strJsonFileName.c_str())) {
                throw std::runtime_error(strprintf("%s: error could not initialise custom parameters", __func__));
            }

            customParams.init(valNetDef["chainName"].getValStr());
        }
        return customParams;
    }
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool CheckDynamicChainParameters(const CDynamicChainParams& params)
{
    if (params.nBlockSpacing > MAX_BLOCK_SPACING || params.nBlockSpacing < MIN_BLOCK_SPACING) {
        LogPrintf("%s : block spacing %u exceeds limit\n",__func__ , params.nBlockSpacing);
        return false;
    }

    if (params.nTransactionFee > MAX_TX_FEE_THRESHOLD || params.nTransactionFee < MIN_TX_FEE_THRESHOLD) {
        LogPrintf("%s : tx fee threshold %u exceeds limit\n",__func__ , params.nTransactionFee);
        return false;
    }

    if (params.nDustThreshold > MAX_DUST_THRESHOLD || params.nDustThreshold < MIN_DUST_THRESHOLD) {
        LogPrintf("%s : dust threshold %u exceeds limit\n",__func__ , params.nDustThreshold);
        return false;
    }

    if (!params.nMinAdminSigs || params.nMinAdminSigs > params.nMaxAdminSigs) {
        LogPrintf("%s : number of CVN signers %u/%u exceeds limit\n",__func__ , params.nMinAdminSigs, params.nMaxAdminSigs);
        return false;
    }

    if (params.nBlocksToConsiderForSigCheck < MIN_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK || params.nBlocksToConsiderForSigCheck > MAX_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK) {
        LogPrintf("%s : %u blocksToConsiderForSigCheck is out of bounds\n",__func__ , params.nBlocksToConsiderForSigCheck);
        return false;
    }

    if (params.nPercentageOfSignaturesMean < MIN_PERCENTAGE_OF_SIGNATURES_MEAN || params.nPercentageOfSignaturesMean > MAX_PERCENTAGE_OF_SIGNATURES_MEAN) {
        LogPrintf("%s : %u nPercentageOfSignatureMean is out of bounds\n",__func__ , params.nPercentageOfSignaturesMean);
        return false;
    }

    if (params.nMaxBlockSize < MIN_SIZE_OF_BLOCK || params.nMaxBlockSize > MAX_SIZE_OF_BLOCK) {
        LogPrintf("%s : %u nMaxBlockSize is out of bounds\n",__func__ , params.nMaxBlockSize);
        return false;
    }

    if (params.nBlockPropagationWaitTime < MIN_BLOCK_PROPAGATION_WAIT_TIME || params.nBlockPropagationWaitTime > MAX_BLOCK_PROPAGATION_WAIT_TIME ||
            params.nBlockPropagationWaitTime >= params.nBlockSpacing) {
        LogPrintf("%s : %u nBlockPropagationWaitTime is out of bounds\n",__func__ , params.nBlockPropagationWaitTime);
        return false;
    }

    if (params.nRetryNewSigSetInterval < MIN_RETRY_NEW_SIG_SET_INTERVAL || params.nRetryNewSigSetInterval > MAX_RETRY_NEW_SIG_SET_INTERVAL) {
        LogPrintf("%s : %u nRetryNewSigSetInterval is out of bounds\n",__func__ , params.nRetryNewSigSetInterval);
        return false;
    }

    if (params.nCoinbaseMaturity < MIN_COINBASE_MATURITY || params.nCoinbaseMaturity > MAX_COINBASE_MATURITY) {
        LogPrintf("%s : %u nCoinbaseMaturity is out of bounds\n",__func__ , params.nCoinbaseMaturity);
        return false;
    }

    if (params.strDescription.length() <= MIN_CHAIN_DATA_DESCRIPTION_LEN) {
        LogPrintf("%s : chain data description is too short: %s\n",__func__ , params.strDescription);
        return false;
    }

    return true;
}
