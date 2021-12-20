// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "server.h"

#include "base58.h"
#include "init.h"
#include "random.h"
#include "sync.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"

#include <univalue.h>

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_upper()

using namespace RPCServer;
using namespace std;

static bool fRPCRunning = false;
static bool fRPCInWarmup = true;
static std::string rpcWarmupStatus("RPC server started");
static CCriticalSection cs_rpcWarmup;
/* Timer-creating functions */
static std::vector<RPCTimerInterface*> timerInterfaces;
/* Map of name to timer.
 * @note Can be changed to std::unique_ptr when C++11 */
static std::map<std::string, boost::shared_ptr<RPCTimerBase> > deadlineTimers;

static struct CRPCSignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CRPCCommand&)> PreCommand;
    boost::signals2::signal<void (const CRPCCommand&)> PostCommand;
} g_rpcSignals;

void RPCServer::OnStarted(boost::function<void ()> slot)
{
    g_rpcSignals.Started.connect(slot);
}

void RPCServer::OnStopped(boost::function<void ()> slot)
{
    g_rpcSignals.Stopped.connect(slot);
}

void RPCServer::OnPreCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PreCommand.connect(boost::bind(slot, _1));
}

void RPCServer::OnPostCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PostCommand.connect(boost::bind(slot, _1));
}

void RPCTypeCheck(const UniValue& params,
                  const list<UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    BOOST_FOREACH(UniValue::VType t, typesExpected)
    {
        if (params.size() <= i)
            break;

        const UniValue& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.isNull()))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   uvTypeName(t), uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheckObj(const UniValue& o,
                  const map<string, UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    BOOST_FOREACH(const PAIRTYPE(string, UniValue::VType)& t, typesExpected)
    {
        const UniValue& v = find_value(o, t.first);
        if (!fAllowNull && v.isNull())
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first));

        if (!((v.type() == t.second) || (fAllowNull && (v.isNull()))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   uvTypeName(t.second), t.first, uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

CAmount AmountFromValue(const UniValue& value)
{
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

UniValue ValueFromAmount(const CAmount& amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
}

uint256 ParseHashV(const UniValue& v, string strName)
{
    string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const UniValue& o, string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
vector<unsigned char> ParseHexV(const UniValue& v, string strName)
{
    string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
vector<unsigned char> ParseHexO(const UniValue& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

/**
 * Note: This interface may still be subject to change.
 */

std::string CRPCTable::help(const std::string& strCommand) const
{
    string strRet;
    string category;
    set<rpcfn_type> setDone;
    vector<pair<string, const CRPCCommand*> > vCommands;

    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
        vCommands.push_back(make_pair(mi->second->category + mi->first, mi->second));
    sort(vCommands.begin(), vCommands.end());

    BOOST_FOREACH(const PAIRTYPE(string, const CRPCCommand*)& command, vCommands)
    {
        const CRPCCommand *pcmd = command.second;
        string strMethod = pcmd->name;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand)
            continue;
        try
        {
            UniValue params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (const std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
            {
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category)
                {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    string firstLetter = category.substr(0,1);
                    boost::to_upper(firstLetter);
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand);
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

UniValue help(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "help ( \"command\" )\n"
            "\nList all commands, or get help for a specified command.\n"
            "\nArguments:\n"
            "1. \"command\"     (string, optional) The command to get help on\n"
            "\nResult:\n"
            "\"text\"     (string) The help text\n"
        );

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    return tableRPC.help(strCommand);
}


UniValue stop(const UniValue& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "stop\n"
            "\nStop FairCoin server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client.
    StartShutdown();
    return "FairCoin server stopping";
}

/**
 * Call Table
 */
static const CRPCCommand vRPCCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    /* Overall control/query calls */
    { "control",            "getinfo",                &getinfo,                true  }, /* uses wallet if enabled */
    { "control",            "help",                   &help,                   true  },
    { "control",            "stop",                   &stop,                   true  },

    /* P2P networking */
    { "network",            "getnetworkinfo",         &getnetworkinfo,         true  },
    { "network",            "addnode",                &addnode,                true  },
    { "network",            "disconnectnode",         &disconnectnode,         true  },
    { "network",            "getaddednodeinfo",       &getaddednodeinfo,       true  },
    { "network",            "getconnectioncount",     &getconnectioncount,     true  },
    { "network",            "getnettotals",           &getnettotals,           true  },
    { "network",            "getpeerinfo",            &getpeerinfo,            true  },
    { "network",            "ping",                   &ping,                   true  },
    { "network",            "setban",                 &setban,                 true  },
    { "network",            "listbanned",             &listbanned,             true  },
    { "network",            "clearbanned",            &clearbanned,            true  },

    /* Block chain and UTXO */
    { "blockchain",         "getblockchaininfo",      &getblockchaininfo,      true  },
    { "blockchain",         "getbestblockhash",       &getbestblockhash,       true  },
    { "blockchain",         "getblockcount",          &getblockcount,          true  },
    { "blockchain",         "getblock",               &getblock,               true  },
    { "blockchain",         "getblockhash",           &getblockhash,           true  },
    { "blockchain",         "getblockheader",         &getblockheader,         true  },
    { "blockchain",         "getchaintips",           &getchaintips,           true  },
    { "blockchain",         "getmempoolinfo",         &getmempoolinfo,         true  },
    { "blockchain",         "getrawmempool",          &getrawmempool,          true  },
    { "blockchain",         "gettxout",               &gettxout,               true  },
    { "blockchain",         "gettxoutproof",          &gettxoutproof,          true  },
    { "blockchain",         "verifytxoutproof",       &verifytxoutproof,       true  },
    { "blockchain",         "gettxoutsetinfo",        &gettxoutsetinfo,        true  },
    { "blockchain",         "verifychain",            &verifychain,            true  },

    /* CVN functions */
    { "cvn",                "getchainparameters",     &getchainparameters,     true  },
    { "cvn",                "getactivecvns",          &getactivecvns,          true  },
    { "cvn",                "getactiveadmins",        &getactiveadmins,        true  },
    { "cvn",                "estimatefee",            &estimatefee,            true  },
#ifdef USE_CVN
    { "cvn",                "addcvn",                 &addcvn,                 false },
    { "cvn",                "removecvn",              &removecvn,              false },
    { "cvn",                "fasitoschnorr",          &fasitoschnorr,          true  },
    { "cvn",                "fasitoschnorrverify",    &fasitoschnorrverify,    true  },
    { "cvn",                "fasitohash",             &fasitohash,             true  },
    { "cvn",                "getcvninfo",             &getcvninfo,             true  },
    { "cvn",                "fasitologin",            &fasitologin,            true  },
    { "cvn",                "fasitologout",           &fasitologout,           true  },
    { "cvn",                "fasitononce",            &fasitononce,            true  },
    { "cvn",                "fasitosign",             &fasitosign,             true  },
    { "cvn",                "fasitoinitkey",          &fasitoinitkey,          true  },
    { "cvn",                "fasitocmd",              &fasitocmd,              true  },
    { "cvn",                "bancvn",                 &bancvn,                 true  },
    { "cvn",                "setchainparameters",     &setchainparameters,     true  },
    { "cvn",                "relaynoncepool",         &relaynoncepool,         true  },
    { "cvn",                "submitblock",            &submitblock,            true  },
    { "cvn",                "addcoinsupply",          &addcoinsupply,          true  },

    /* Block generation */
    { "generating",         "getgenerate",            &getgenerate,            true  },
    { "generating",         "setgenerate",            &setgenerate,            true  },
#endif // USE_CVN

    /* Raw transactions */
    { "rawtransactions",    "createrawtransaction",   &createrawtransaction,   true  },
    { "rawtransactions",    "decoderawtransaction",   &decoderawtransaction,   true  },
    { "rawtransactions",    "decodescript",           &decodescript,           true  },
    { "rawtransactions",    "getrawtransaction",      &getrawtransaction,      true  },
    { "rawtransactions",    "sendrawtransaction",     &sendrawtransaction,     false },
    { "rawtransactions",    "signrawtransaction",     &signrawtransaction,     false }, /* uses wallet if enabled */
#ifdef ENABLE_WALLET
    { "rawtransactions",    "fundrawtransaction",     &fundrawtransaction,     false },
#endif

    /* Utility functions */
    { "util",               "createmultisig",         &createmultisig,         true  },
    { "util",               "validateaddress",        &validateaddress,        true  }, /* uses wallet if enabled */
    { "util",               "validatepubkey",         &validatepubkey,         true  }, /* uses wallet if enabled */
    { "util",               "verifymessage",          &verifymessage,          true  },

    /* Not shown in help */
    { "hidden",             "invalidateblock",        &invalidateblock,        true  },
    { "hidden",             "reconsiderblock",        &reconsiderblock,        true  },
    { "hidden",             "setmocktime",            &setmocktime,            true  },
#ifdef ENABLE_WALLET
    { "hidden",             "resendwallettransactions", &resendwallettransactions, true},
#endif

#ifdef ENABLE_WALLET
    /* Wallet */
    { "wallet",             "addmultisigaddress",     &addmultisigaddress,     true  },
    { "wallet",             "backupwallet",           &backupwallet,           true  },
    { "wallet",             "dumpprivkey",            &dumpprivkey,            true  },
    { "wallet",             "dumpwallet",             &dumpwallet,             true  },
    { "wallet",             "encryptwallet",          &encryptwallet,          true  },
    { "wallet",             "getaccountaddress",      &getaccountaddress,      true  },
    { "wallet",             "getaccount",             &getaccount,             true  },
    { "wallet",             "getaddressesbyaccount",  &getaddressesbyaccount,  true  },
    { "wallet",             "getbalance",             &getbalance,             false },
    { "wallet",             "getnewaddress",          &getnewaddress,          true  },
    { "wallet",             "getrawchangeaddress",    &getrawchangeaddress,    true  },
    { "wallet",             "getreceivedbyaccount",   &getreceivedbyaccount,   false },
    { "wallet",             "getreceivedbyaddress",   &getreceivedbyaddress,   false },
    { "wallet",             "gettransaction",         &gettransaction,         false },
    { "wallet",             "abandontransaction",     &abandontransaction,     false },
    { "wallet",             "getunconfirmedbalance",  &getunconfirmedbalance,  false },
    { "wallet",             "getwalletinfo",          &getwalletinfo,          false },
    { "wallet",             "importprivkey",          &importprivkey,          true  },
    { "wallet",             "importwallet",           &importwallet,           true  },
    { "wallet",             "importaddress",          &importaddress,          true  },
    { "wallet",             "importpubkey",           &importpubkey,           true  },
    { "wallet",             "keypoolrefill",          &keypoolrefill,          true  },
    { "wallet",             "listaccounts",           &listaccounts,           false },
    { "wallet",             "listaddressgroupings",   &listaddressgroupings,   false },
    { "wallet",             "listlockunspent",        &listlockunspent,        false },
    { "wallet",             "listreceivedbyaccount",  &listreceivedbyaccount,  false },
    { "wallet",             "listreceivedbyaddress",  &listreceivedbyaddress,  false },
    { "wallet",             "listsinceblock",         &listsinceblock,         false },
    { "wallet",             "listtransactions",       &listtransactions,       false },
    { "wallet",             "listunspent",            &listunspent,            false },
    { "wallet",             "lockunspent",            &lockunspent,            true  },
    { "wallet",             "move",                   &movecmd,                false },
    { "wallet",             "sendfrom",               &sendfrom,               false },
    { "wallet",             "sendmany",               &sendmany,               false },
    { "wallet",             "sendtoaddress",          &sendtoaddress,          false },
    { "wallet",             "setaccount",             &setaccount,             true  },
    { "wallet",             "settxfee",               &settxfee,               true  },
    { "wallet",             "signmessage",            &signmessage,            true  },
    { "wallet",             "walletlock",             &walletlock,             true  },
    { "wallet",             "walletpassphrasechange", &walletpassphrasechange, true  },
    { "wallet",             "walletpassphrase",       &walletpassphrase,       true  },
#endif // ENABLE_WALLET
    { "omni layer (data retrieval)", "omni_getinfo",                   &omni_getinfo,                    true  },
    { "omni layer (data retrieval)", "omni_getactivations",            &omni_getactivations,             true  },
    { "omni layer (data retrieval)", "omni_getallbalancesforid",       &omni_getallbalancesforid,        false },
    { "omni layer (data retrieval)", "omni_getbalance",                &omni_getbalance,                 false },
    { "omni layer (data retrieval)", "omni_gettransaction",            &omni_gettransaction,             false },
    { "omni layer (data retrieval)", "omni_getproperty",               &omni_getproperty,                false },
    { "omni layer (data retrieval)", "omni_listproperties",            &omni_listproperties,             false },
    { "omni layer (data retrieval)", "omni_getcrowdsale",              &omni_getcrowdsale,               false },
    { "omni layer (data retrieval)", "omni_getgrants",                 &omni_getgrants,                  false },
    { "omni layer (data retrieval)", "omni_getactivedexsells",         &omni_getactivedexsells,          false },
    { "omni layer (data retrieval)", "omni_getactivecrowdsales",       &omni_getactivecrowdsales,        false },
    { "omni layer (data retrieval)", "omni_getorderbook",              &omni_getorderbook,               false },
    { "omni layer (data retrieval)", "omni_gettrade",                  &omni_gettrade,                   false },
    { "omni layer (data retrieval)", "omni_getsto",                    &omni_getsto,                     false },
    { "omni layer (data retrieval)", "omni_listblocktransactions",     &omni_listblocktransactions,      false },
    { "omni layer (data retrieval)", "omni_listpendingtransactions",   &omni_listpendingtransactions,    false },
    { "omni layer (data retrieval)", "omni_getallbalancesforaddress",  &omni_getallbalancesforaddress,   false },
    { "omni layer (data retrieval)", "omni_gettradehistoryforaddress", &omni_gettradehistoryforaddress,  false },
    { "omni layer (data retrieval)", "omni_gettradehistoryforpair",    &omni_gettradehistoryforpair,     false },
    { "omni layer (data retrieval)", "omni_getcurrentconsensushash",   &omni_getcurrentconsensushash,    false },
    { "omni layer (data retrieval)", "omni_getpayload",                &omni_getpayload,                 false },
    { "omni layer (data retrieval)", "omni_getseedblocks",             &omni_getseedblocks,              false },
    { "omni layer (data retrieval)", "omni_getmetadexhash",            &omni_getmetadexhash,             false },
    { "omni layer (data retrieval)", "omni_getfeecache",               &omni_getfeecache,                false },
    { "omni layer (data retrieval)", "omni_getfeetrigger",             &omni_getfeetrigger,              false },
    { "omni layer (data retrieval)", "omni_getfeedistribution",        &omni_getfeedistribution,         false },
    { "omni layer (data retrieval)", "omni_getfeedistributions",       &omni_getfeedistributions,        false },
    { "omni layer (data retrieval)", "omni_getbalanceshash",           &omni_getbalanceshash,            false },
#ifdef ENABLE_WALLET
    { "omni layer (data retrieval)", "omni_listtransactions",          &omni_listtransactions,           false },
    { "omni layer (data retrieval)", "omni_getfeeshare",               &omni_getfeeshare,                false },
    { "omni layer (configuration)",  "omni_setautocommit",             &omni_setautocommit,              true  },
#endif
    { "hidden",                      "mscrpc",                         &mscrpc,                          true  },

    /* depreciated: */
    { "hidden",                      "getinfo_MP",                     &omni_getinfo,                    true  },
    { "hidden",                      "getbalance_MP",                  &omni_getbalance,                 false },
    { "hidden",                      "getallbalancesforaddress_MP",    &omni_getallbalancesforaddress,   false },
    { "hidden",                      "getallbalancesforid_MP",         &omni_getallbalancesforid,        false },
    { "hidden",                      "getproperty_MP",                 &omni_getproperty,                false },
    { "hidden",                      "listproperties_MP",              &omni_listproperties,             false },
    { "hidden",                      "getcrowdsale_MP",                &omni_getcrowdsale,               false },
    { "hidden",                      "getgrants_MP",                   &omni_getgrants,                  false },
    { "hidden",                      "getactivedexsells_MP",           &omni_getactivedexsells,          false },
    { "hidden",                      "getactivecrowdsales_MP",         &omni_getactivecrowdsales,        false },
    { "hidden",                      "getsto_MP",                      &omni_getsto,                     false },
    { "hidden",                      "getorderbook_MP",                &omni_getorderbook,               false },
    { "hidden",                      "gettrade_MP",                    &omni_gettrade,                   false },
    { "hidden",                      "gettransaction_MP",              &omni_gettransaction,             false },
    { "hidden",                      "listblocktransactions_MP",       &omni_listblocktransactions,      false },
#ifdef ENABLE_WALLET
    { "hidden",                      "listtransactions_MP",            &omni_listtransactions,           false },
#endif
    { "omni layer (payload creation)", "omni_createpayload_simplesend",          &omni_createpayload_simplesend,          true },
    { "omni layer (payload creation)", "omni_createpayload_sendall",             &omni_createpayload_sendall,             true },
    { "omni layer (payload creation)", "omni_createpayload_dexsell",             &omni_createpayload_dexsell,             true },
    { "omni layer (payload creation)", "omni_createpayload_dexaccept",           &omni_createpayload_dexaccept,           true },
    { "omni layer (payload creation)", "omni_createpayload_sto",                 &omni_createpayload_sto,                 true },
    { "omni layer (payload creation)", "omni_createpayload_grant",               &omni_createpayload_grant,               true },
    { "omni layer (payload creation)", "omni_createpayload_revoke",              &omni_createpayload_revoke,              true },
    { "omni layer (payload creation)", "omni_createpayload_changeissuer",        &omni_createpayload_changeissuer,        true },
    { "omni layer (payload creation)", "omni_createpayload_trade",               &omni_createpayload_trade,               true },
    { "omni layer (payload creation)", "omni_createpayload_issuancefixed",       &omni_createpayload_issuancefixed,       true },
    { "omni layer (payload creation)", "omni_createpayload_issuancecrowdsale",   &omni_createpayload_issuancecrowdsale,   true },
    { "omni layer (payload creation)", "omni_createpayload_issuancemanaged",     &omni_createpayload_issuancemanaged,     true },
    { "omni layer (payload creation)", "omni_createpayload_closecrowdsale",      &omni_createpayload_closecrowdsale,      true },
    { "omni layer (payload creation)", "omni_createpayload_canceltradesbyprice", &omni_createpayload_canceltradesbyprice, true },
    { "omni layer (payload creation)", "omni_createpayload_canceltradesbypair",  &omni_createpayload_canceltradesbypair,  true },
    { "omni layer (payload creation)", "omni_createpayload_cancelalltrades",     &omni_createpayload_cancelalltrades,     true },
    { "omni layer (payload creation)", "omni_createpayload_enablefreezing",      &omni_createpayload_enablefreezing,      true },
    { "omni layer (payload creation)", "omni_createpayload_disablefreezing",     &omni_createpayload_disablefreezing,     true },
    { "omni layer (payload creation)", "omni_createpayload_freeze",              &omni_createpayload_freeze,              true },
    { "omni layer (payload creation)", "omni_createpayload_unfreeze",            &omni_createpayload_unfreeze,            true },

    { "omni layer (raw transactions)", "omni_decodetransaction",     &omni_decodetransaction,     true },
    { "omni layer (raw transactions)", "omni_createrawtx_opreturn",  &omni_createrawtx_opreturn,  true },
    { "omni layer (raw transactions)", "omni_createrawtx_multisig",  &omni_createrawtx_multisig,  true },
    { "omni layer (raw transactions)", "omni_createrawtx_input",     &omni_createrawtx_input,     true },
    { "omni layer (raw transactions)", "omni_createrawtx_reference", &omni_createrawtx_reference, true },
    { "omni layer (raw transactions)", "omni_createrawtx_change",    &omni_createrawtx_change,    true },

#ifdef ENABLE_WALLET
    { "omni layer (transaction creation)", "omni_sendrawtx",               &omni_sendrawtx,               false },
    { "omni layer (transaction creation)", "omni_send",                    &omni_send,                    false },
    { "omni layer (transaction creation)", "omni_senddexsell",             &omni_senddexsell,             false },
    { "omni layer (transaction creation)", "omni_senddexaccept",           &omni_senddexaccept,           false },
    { "omni layer (transaction creation)", "omni_sendissuancecrowdsale",   &omni_sendissuancecrowdsale,   false },
    { "omni layer (transaction creation)", "omni_sendissuancefixed",       &omni_sendissuancefixed,       false },
    { "omni layer (transaction creation)", "omni_sendissuancemanaged",     &omni_sendissuancemanaged,     false },
    { "omni layer (transaction creation)", "omni_sendtrade",               &omni_sendtrade,               false },
    { "omni layer (transaction creation)", "omni_sendcanceltradesbyprice", &omni_sendcanceltradesbyprice, false },
    { "omni layer (transaction creation)", "omni_sendcanceltradesbypair",  &omni_sendcanceltradesbypair,  false },
    { "omni layer (transaction creation)", "omni_sendcancelalltrades",     &omni_sendcancelalltrades,     false },
    { "omni layer (transaction creation)", "omni_sendsto",                 &omni_sendsto,                 false },
    { "omni layer (transaction creation)", "omni_sendgrant",               &omni_sendgrant,               false },
    { "omni layer (transaction creation)", "omni_sendrevoke",              &omni_sendrevoke,              false },
    { "omni layer (transaction creation)", "omni_sendclosecrowdsale",      &omni_sendclosecrowdsale,      false },
    { "omni layer (transaction creation)", "omni_sendchangeissuer",        &omni_sendchangeissuer,        false },
    { "omni layer (transaction creation)", "omni_sendall",                 &omni_sendall,                 false },
    { "omni layer (transaction creation)", "omni_sendenablefreezing",      &omni_sendenablefreezing,      false },
    { "omni layer (transaction creation)", "omni_senddisablefreezing",     &omni_senddisablefreezing,     false },
    { "omni layer (transaction creation)", "omni_sendfreeze",              &omni_sendfreeze,              false },
    { "omni layer (transaction creation)", "omni_sendunfreeze",            &omni_sendunfreeze,            false },
    { "hidden",                            "omni_senddeactivation",        &omni_senddeactivation,        true  },
    { "hidden",                            "omni_sendactivation",          &omni_sendactivation,          false },
    { "hidden",                            "omni_sendalert",               &omni_sendalert,               true  },

    /* depreciated: */
    { "hidden",                            "sendrawtx_MP",                 &omni_sendrawtx,               false },
    { "hidden",                            "send_MP",                      &omni_send,                    false },
    { "hidden",                            "sendtoowners_MP",              &omni_sendsto,                 false },
    { "hidden",                            "trade_MP",                     &trade_MP,                     false },
#endif

};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](const std::string &name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

bool StartRPC()
{
    LogPrint("rpc", "Starting RPC\n");
    fRPCRunning = true;
    g_rpcSignals.Started();
    return true;
}

void InterruptRPC()
{
    LogPrint("rpc", "Interrupting RPC\n");
    // Interrupt e.g. running longpolls
    fRPCRunning = false;
}

void StopRPC()
{
    LogPrint("rpc", "Stopping RPC\n");
    deadlineTimers.clear();
    g_rpcSignals.Stopped();
}

bool IsRPCRunning()
{
    return fRPCRunning;
}

void SetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool RPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

void JSONRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    UniValue valMethod = find_value(request, "method");
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getblocktemplate")
        LogPrint("rpc", "ThreadRPCServer method=%s\n", SanitizeString(strMethod));

    // Parse params
    UniValue valParams = find_value(request, "params");
    if (valParams.isArray())
        params = valParams.get_array();
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static UniValue JSONRPCExecOne(const UniValue& req)
{
    UniValue rpc_result(UniValue::VOBJ);

    JSONRequest jreq;
    try {
        jreq.parse(req);

        UniValue result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id);
    }
    catch (const UniValue& objError)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id);
    }
    catch (const std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

std::string JSONRPCExecBatch(const UniValue& vReq)
{
    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return ret.write() + "\n";
}

UniValue CRPCTable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Return immediately if in warmup
    {
        LOCK(cs_rpcWarmup);
        if (fRPCInWarmup)
            throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    }

    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    g_rpcSignals.PreCommand(*pcmd);

    try
    {
        // Execute
        return pcmd->actor(params, false);
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    g_rpcSignals.PostCommand(*pcmd);
}

std::string HelpExampleCli(const std::string& methodname, const std::string& args)
{
    return "> faircoin-cli " + methodname + " " + args + "\n";
}

std::string HelpExampleRpc(const std::string& methodname, const std::string& args)
{
    return "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
        "\"method\": \"" + methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:40405/\n";
}

void RPCRegisterTimerInterface(RPCTimerInterface *iface)
{
    timerInterfaces.push_back(iface);
}

void RPCUnregisterTimerInterface(RPCTimerInterface *iface)
{
    std::vector<RPCTimerInterface*>::iterator i = std::find(timerInterfaces.begin(), timerInterfaces.end(), iface);
    assert(i != timerInterfaces.end());
    timerInterfaces.erase(i);
}

void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds)
{
    if (timerInterfaces.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No timer handler registered for RPC");
    deadlineTimers.erase(name);
    RPCTimerInterface* timerInterface = timerInterfaces.back();
    LogPrint("rpc", "queue run of timer %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());
    deadlineTimers.insert(std::make_pair(name, boost::shared_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds*1000))));
}

const CRPCTable tableRPC;
