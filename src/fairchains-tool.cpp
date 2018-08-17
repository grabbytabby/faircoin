// Copyright (c) 2016-2018 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <univalue.h>
#include "chainparams.h"
#include "clientversion.h"
#include "util.h"
#include "utilstrencodings.h"
#include "key.h"
#include "poc.h"
#include "fairchains-tool-input.h"
#include "fairchains-tool-key.h"
#include "consensus/merkle.h"

#include <fstream>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;

class Secp256k1Init
{
    ECCVerifyHandle globalVerifyHandle;

public:
    Secp256k1Init() {
        ECC_Start();
    }
    ~Secp256k1Init() {
        ECC_Stop();
    }
};

string requestPassword()
{
    string strPassword;
    cout << "Supply a good password (at least 10 characters) to secure the certificates." << endl;

    string strPassword1;
    bool fPassGood = false;
    do {
        fPassGood = false;
        do {
            promptForPassword("Password: ", strPassword);
            if (strPassword.length() < 10) {
                cout << "--> password too short." << endl;
            } else {
                fPassGood = true;
            }
        } while (!fPassGood);

        promptForPassword("Repeat password: ", strPassword1);
        if (strPassword != strPassword1)  {
            cout << "--> passwords do not match." << endl;
            fPassGood = false;
        }
    } while (!fPassGood);

    return strPassword;
}

int SignJSONFile(const string &strFileName, const string &strKeyFile)
{
    fprintf(stdout, "Reading custom chain parameters from file: %s\n", strFileName.c_str());

    boost::filesystem::ifstream streamNetDef(strFileName);
    if (!streamNetDef.good() || !boost::filesystem::exists(strFileName) || !boost::filesystem::is_regular(strFileName)) {
        fprintf(stderr, "ERROR: could not find file %s\n", strFileName.c_str());
        return 1;
    }

    std::string str((std::istreambuf_iterator<char>(streamNetDef)), std::istreambuf_iterator<char>());
    UniValue valNetDef(UniValue::VOBJ);
    if (!valNetDef.read(str)) {
        fprintf(stderr, "ERROR: could not parse file %s\n", strFileName.c_str());
        return 1;
    }

    if (!InitialiseCustomParams(valNetDef, strFileName.c_str(), false)) {
        fprintf(stderr, "ERROR: file %s is invalid\n", strFileName.c_str());
        return 1;
    }

    if (fOfficialFairChain) {
        fprintf(stderr, "This file is already signed! Nothing to do.\n");
        return 2;
    }

    string strFullName;
    const uint256 hashData = uint256S(valNetDef["hash"].getValStr());
    CHashWriter hasherSig(SER_GETHASH, 0);
    hasherSig << hashData;

    cout << "Enter your full name: ";
    flush(cout);
    getline(cin, strFullName);

    time_t now = time(0);
    tm *gmtm = gmtime(&now);
    char cTime[32];
    asctime_r(gmtm, cTime);
    cTime[strlen(cTime) - 1] = 0; // strip the "\n"

    const string strComment("signed by " + strFullName + " on " + string(cTime) + " UTC");

    const UniValue& valSign = valNetDef["sign"];
    UniValue& valComment = (UniValue &) valSign["comment"];
    UniValue& valSignedHash = (UniValue &) valSign["signedhash"];
    UniValue& valSignature = (UniValue &) valSign["signature"];

    valComment.setStr(strComment);
    hasherSig << strComment;

    uint256 hashSig = hasherSig.GetHash();
    valSignedHash.setStr(hashSig.ToString());

    BIO *bioKey = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bioKey, strKeyFile.c_str())) {
        fprintf(stderr, "ERROR: key file not found: %s\n", strKeyFile.c_str());
        return 1;
    }

    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!PEM_read_bio_ECPrivateKey(bioKey, &ecKey, NULL, NULL)) {
        fprintf(stderr, "ERROR: could not read private key from file %s.\n", strKeyFile.c_str());
        return 1;
    }

    const BIGNUM *bnPrivKey = EC_KEY_get0_private_key(ecKey);
    uint8_t buf[256];
    size_t sKeyLen = BN_bn2bin(bnPrivKey, buf);
    const vector<uint8_t> data(buf, buf + sKeyLen);

    CKey key;
    key.Set(data.begin(), data.end(), false);

    CSchnorrSig signature;
    if (!key.SchnorrSign(hashSig, signature)) {
        fprintf(stderr, "ERROR: could not create signature");
        return 1;
    }

    valSignature.setStr(signature.ToString());

    ofstream out(strFileName);

    if (!out) {
        cerr << "\nERROR: could not save file " << strFileName << ": " << strerror(errno) << endl;
    } else {
        out << valNetDef.write(4, 0) << endl;
        out.close();

        cout << "\nChain data file " << strFileName << " successfully signed." << endl;
    }

    EC_KEY_free(ecKey);
    BIO_free_all(bioKey);

    return 0;
}

static const string strInstructions =
"  #################################################\n"
"  ##                                             ##\n"
"  ##       Welcome to the FairChains tool!       ##\n"
"  ##  %-41s  ##\n"
"  ##          (c) 2018  by Thomas König          ##\n"
"  ##                                             ##\n"
"  ##                                             ##\n"
"  ##  This tool  is used to create  a JSON file  ##\n"
"  ##  which  contains all  required information  ##\n"
"  ##  to run a public/private  blockchain based  ##\n"
"  ##  on  the   FairChains   wallet   software.  ##\n"
"  ##  Certificates  for  the  genesis  CVN  and  ##\n"
"  ##  Admin are created in  the current working  ##\n"
"  ##  directory as well.                         ##\n"
"  ##                                             ##\n"
"  ##  For  more information about the  required  ##\n"
"  ##  input parameters visit:                    ##\n"
"  ##  https://fairchains.org/doc                 ##\n"
"  ##                                             ##\n"
"  #################################################\n"
;

int main(int argc, char* argv[])
{
    OpenSSL_add_all_algorithms();

    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    boost::scoped_ptr<Secp256k1Init> ecc;

    SetupEnvironment();
    fPrintToConsole = true;

    ecc.reset(new Secp256k1Init());

    if (argc == 5 && !strcmp("-sign", argv[1]) && !strcmp("-key", argv[3])) {
        return SignJSONFile(string(argv[2]), string(argv[4]));
    } else if (argc > 1) {
        fprintf(stderr, "ERROR: invalid arguments.\n");
        return -1;
    }

    CChainParams p = Params("main");

    UniValue data(UniValue::VOBJ);
    data.push_back(Pair("jsonVersion", 1));

    const string strFullVersion = FormatFullVersion();
    const string strPaddedFullVersion = strprintf("%*s%*s", 20 + strFullVersion.length() / 2, strFullVersion, 20 - strFullVersion.length() / 2, "");
    cout << endl << strprintf(strInstructions, strPaddedFullVersion) << endl;

    string strPassword = requestPassword();

    prompt4String(data, "chainName", "Chain name", "mychain", 24);
    const string strChainName = data["chainName"].getValStr();

    prompt4String(data, "currencyName", "Currency name", "FairCoin", 24);
    prompt4String(data, "currencySymbol", "Currency symbol", "FAIR", 8, ensureUpperCase);

    prompt4Double(data, "maxMoney", "Maximum amount of coins (money supply) in the blockchain", 1000000);

    prompt4Hex(data, "networkMagic", "Network magic bytes", "0xfabfb5fa");

    CKey keyAlert;
    if (!createKeyFile("alert-" + strChainName + ".pem", "FairChains network", "Alert signer", "alert", strPassword, keyAlert)) {
        fprintf(stderr, "ERROR: could not create CVN certificate\n");
        exit(0);
    }

    data.push_back(Pair("alertPubKey", HexStr(keyAlert.GetPubKey())));

    int nPort = prompt4Integer(data, "defaultPort", "Network TCP port", 49404, checkForValidPorts);
    prompt4StringArray(data, "seedNodes", "Seed nodes (One per line. End input by entering '.' + enter)");
    prompt4FixedSeeds(data, "fixedSeeds", "IPv4 and/or IPv6 addresses of fixed seed nodes (One per line. End input by entering '.' + enter)", nPort);
    prompt4Integer(data, "pubKeyAddrVersion", "Public key address version", p.Base58Prefix(CChainParams::PUBKEY_ADDRESS)[0], checkByteSize);
    prompt4Integer(data, "scriptAddrVersion", "Script address version", p.Base58Prefix(CChainParams::SCRIPT_ADDRESS)[0], checkByteSize);
    prompt4Integer(data, "secretKeyVersion", "Secret key version", p.Base58Prefix(CChainParams::SECRET_KEY)[0], checkByteSize);
    prompt4Hex(data, "extPubKeyPrefix", "Extended public key prefix", "0x0488b21e");
    prompt4Hex(data, "extSecretPrefix", "Extended secret key prefix", "0x0488ade4");
    prompt4Bool(data, "requireStandardTx", "Require standard transactions", true);
    uint32_t nStartTime = prompt4Integer(data, "blockchainStartTime", "Blockchain start unix timestamp", (int) time(NULL));
    prompt4Hex(data, "genesisCvnID", "Id of the genesis CVN", "0xc0ff0001");
    prompt4Hex(data, "genesisAdminID", "Id of the genesis chain admin", "0xadff0001");

    string strId = data["genesisCvnID"].getValStr();
    uint32_t nCnvId;
    stringstream ss;
    ss << hex << strId;
    ss >> nCnvId;
    CKey keyCVN;
    if (!createKeyFile(strId + ".pem", "CVN node operator", "Block creator", strId, strPassword, keyCVN)) {
        fprintf(stderr, "ERROR: could not create CVN certificate\n");
        exit(0);
    }

    data.push_back(Pair("genesisCvnPubKey", keyCVN.GetRawPubKey().ToString()));

    strId = data["genesisAdminID"].getValStr();
    uint32_t nAdminId;
    ss.clear();
    ss << hex << strId;
    ss >> nAdminId;
    CKey keyADMIN;
    if (!createKeyFile(strId + ".pem", "CVN chain admin", "Chain data signer", strId, strPassword, keyADMIN)) {
        fprintf(stderr, "ERROR: could not create ADMIN certificate\n");
        exit(0);
    }

    data.push_back(Pair("genesisAdminPubKey", keyADMIN.GetRawPubKey().ToString()));

    UniValue dynParams(UniValue::VOBJ);
    CDynamicChainParams dcp;

    dcp.nMinAdminSigs                = 1;        dynParams.push_back(Pair("minAdminSigs", 1));
    dcp.nMaxAdminSigs                = 1;        dynParams.push_back(Pair("maxAdminSigs", 1));
    dcp.nBlockSpacing                = prompt4Integer(dynParams, "blockSpacing", "Block spacing time - in seconds", 180);
    dcp.nBlockSpacingGracePeriod     = prompt4Integer(dynParams, "blockSpacingGracePeriod", "Block spacing grace period time - in seconds", 60);
    dcp.nTransactionFee              = prompt4Integer(dynParams, "transactionFee", "Transaction fee in Satoshis", 0);
    dcp.nDustThreshold               = prompt4Integer(dynParams, "dustThreshold", "Dust threshold in Satoshis", 0);
    dcp.nMinSuccessiveSignatures     = 1;        dynParams.push_back(Pair("minSuccessiveSignatures", 1));
    dcp.nBlocksToConsiderForSigCheck = 1;        dynParams.push_back(Pair("blocksToConsiderForSigCheck", 1));
    dcp.nPercentageOfSignaturesMean  = 70;       dynParams.push_back(Pair("percentageOfSignaturesMean", 70));
    dcp.nMaxBlockSize                = prompt4Integer(dynParams, "maxBlockSize", "Maximum block size", 1500000);
    dcp.nBlockPropagationWaitTime    = prompt4Integer(dynParams, "blockPropagationWaitTime", "Block propagation wait time", 50);
    dcp.nRetryNewSigSetInterval      = prompt4Integer(dynParams, "retryNewSigSetInterval", "Retry new signature set interval", 15);
    dcp.nCoinbaseMaturity            = prompt4Integer(dynParams, "coinbaseMaturity", "Coinbase maturity - in blocks", 10);
    prompt4String(dynParams, "description", "Description", "#00001 no-URI The genesis dynamic chain parameters", MIN_CHAIN_DATA_DESCRIPTION_LEN);
    dcp.strDescription               = dynParams["description"].getValStr();

    if (!CheckDynamicChainParameters(dcp)) {
        fprintf(stderr, "dynamic chain parameter check failed.\n");
        exit(0);
    }

    data.push_back(Pair("dynamicChainParams", dynParams));

    CBlock genesis = CreateGenesisBlock(nStartTime, nCnvId, dcp);
    genesis.vCvns.resize(1);
    genesis.vCvns[0] = CCvnInfo(nCnvId, 0, CSchnorrPubKeyS(data["genesisCvnPubKey"].getValStr()));

    genesis.vChainAdmins.resize(1);
    genesis.vChainAdmins[0] = CChainAdmin(nAdminId, 0, CSchnorrPubKeyS(data["genesisAdminPubKey"].getValStr()));

    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    data.push_back(Pair("merkleRoot", genesis.hashMerkleRoot.ToString()));

    CHashWriter hasher(SER_GETHASH, 0);
    hasher << genesis.hashPrevBlock << nCnvId;

    CSchnorrSig chainSig;
    if (!keyCVN.SchnorrSign(hasher.GetHash(), chainSig)) {
        fprintf(stderr, "ERROR: could create chain signature\n");
        exit(0);
    }

    genesis.chainMultiSig = chainSig;
    data.push_back(Pair("chainMultiSig", chainSig.ToString()));
    genesis.vAdminIds.push_back(nAdminId);

    const uint256 hashPayload = genesis.GetPayloadHash(true);
    CSchnorrSig adminMultiSig;
    if (!keyADMIN.SchnorrSign(hashPayload, adminMultiSig)) {
        fprintf(stderr, "ERROR: could sign ADMIN data\n");
        exit(0);
    }

    genesis.adminMultiSig = adminMultiSig;
    data.push_back(Pair("adminMultiSig", adminMultiSig.ToString()));

    genesis.hashPayload = genesis.GetPayloadHash();
    data.push_back(Pair("payloadHash", genesis.hashPayload.ToString()));


    const uint256 hashBlock = genesis.GetHash();
    CSchnorrSig creatorSig;
    if (!keyCVN.SchnorrSign(hashBlock, creatorSig)) {
        fprintf(stderr, "ERROR: could sign block data\n");
        exit(0);
    }

    data.push_back(Pair("blockHash", hashBlock.ToString()));

    genesis.creatorSignature = creatorSig;
    data.push_back(Pair("creatorSignature", creatorSig.ToString()));

    p.SetGenesisBlock(genesis);

    UniValue root(UniValue::VOBJ);
    root.push_back(Pair("data", data));

    hasher = CHashWriter(SER_GETHASH, 0);
    hasher << std::string("Official FairChains parameter file");
    hasher << data.write(0, 0);

    root.push_back(Pair("hash", hasher.GetHash().ToString()));
    UniValue sign(UniValue::VOBJ);

    sign.push_back(Pair("comment", "to be signed"));
    sign.push_back(Pair("signature", ""));
    sign.push_back(Pair("signedhash", ""));

    root.push_back(Pair("sign", sign));

    InitialiseCustomParams(root, (strChainName + ".json").c_str(), false);

    ofstream out(strChainName + ".json");
    if (!out) {
        cerr << "\ncould not save file " + strChainName + ".json" << ": " << strerror(errno) << endl;
    } else {
        out << root.write(4, 0) << endl;
        out.close();

        cout << "\n\nChain data file " << strChainName << ".json " << "successfully generated." << endl;
    }

    strPassword.clear();
    memset((void *)&keyAlert.begin()[0], 0, 32);
    memset((void *)&keyCVN.begin()[0], 0, 32);
    memset((void *)&keyADMIN.begin()[0], 0, 32);

    return 0;
}

// dummy
uint32_t GetNumChainSigs(const CBlock *pblock)
{
    return 1;
}
