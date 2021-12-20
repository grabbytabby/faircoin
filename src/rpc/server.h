// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCSERVER_H
#define BITCOIN_RPCSERVER_H

#include "amount.h"
#include "uint256.h"

#include <list>
#include <map>
#include <stdint.h>
#include <string>

#include <boost/function.hpp>

#include <univalue.h>
#include "protocol.h"

class CRPCCommand;

namespace RPCServer
{
    void OnStarted(boost::function<void ()> slot);
    void OnStopped(boost::function<void ()> slot);
    void OnPreCommand(boost::function<void (const CRPCCommand&)> slot);
    void OnPostCommand(boost::function<void (const CRPCCommand&)> slot);
}

class CBlockIndex;
class CNetAddr;

class JSONRequest
{
public:
    UniValue id;
    std::string strMethod;
    UniValue params;

    JSONRequest() { id = NullUniValue; }
    void parse(const UniValue& valRequest);
};

/** Query whether RPC is running */
bool IsRPCRunning();

/**
 * Set the RPC warmup status.  When this is done, all RPC calls will error out
 * immediately with RPC_IN_WARMUP.
 */
void SetRPCWarmupStatus(const std::string& newStatus);
/* Mark warmup as done.  RPC calls will be processed from now on.  */
void SetRPCWarmupFinished();

/* returns the current warmup state.  */
bool RPCIsInWarmup(std::string *statusOut);

/**
 * Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
 * the right number of arguments are passed, just that any passed are the correct type.
 * Use like:  RPCTypeCheck(params, boost::assign::list_of(str_type)(int_type)(obj_type));
 */
void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected, bool fAllowNull=false);

/*
  Check for expected keys/value types in an Object.
  Use like: RPCTypeCheckObj(object, boost::assign::map_list_of("name", str_type)("value", int_type));
*/
void RPCTypeCheckObj(const UniValue& o,
                  const std::map<std::string, UniValue::VType>& typesExpected, bool fAllowNull=false);

/** Opaque base class for timers returned by NewTimerFunc.
 * This provides no methods at the moment, but makes sure that delete
 * cleans up the whole state.
 */
class RPCTimerBase
{
public:
    virtual ~RPCTimerBase() {}
};

/**
 * RPC timer "driver".
 */
class RPCTimerInterface
{
public:
    virtual ~RPCTimerInterface() {}
    /** Implementation name */
    virtual const char *Name() = 0;
    /** Factory function for timers.
     * RPC will call the function to create a timer that will call func in *millis* milliseconds.
     * @note As the RPC mechanism is backend-neutral, it can use different implementations of timers.
     * This is needed to cope with the case in which there is no HTTP server, but
     * only GUI RPC console, and to break the dependency of pcserver on httprpc.
     */
    virtual RPCTimerBase* NewTimer(boost::function<void(void)>& func, int64_t millis) = 0;
};

/** Register factory function for timers */
void RPCRegisterTimerInterface(RPCTimerInterface *iface);
/** Unregister factory function for timers */
void RPCUnregisterTimerInterface(RPCTimerInterface *iface);

/**
 * Run func nSeconds from now.
 * Overrides previous timer <name> (if any).
 */
void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds);

typedef UniValue(*rpcfn_type)(const UniValue& params, bool fHelp);

class CRPCCommand
{
public:
    std::string category;
    std::string name;
    rpcfn_type actor;
    bool okSafeMode;
};

/**
 * Bitcoin RPC command dispatcher.
 */
class CRPCTable
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands;
public:
    CRPCTable();
    const CRPCCommand* operator[](const std::string& name) const;
    std::string help(const std::string& name) const;

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   UniValue Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */
    UniValue execute(const std::string &method, const UniValue &params) const;
};

extern const CRPCTable tableRPC;

/**
 * Utilities: convert hex-encoded Values
 * (throws error if not hex).
 */
extern uint256 ParseHashV(const UniValue& v, std::string strName);
extern uint256 ParseHashO(const UniValue& o, std::string strKey);
extern std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName);
extern std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey);

extern int64_t nWalletUnlockTime;
extern CAmount AmountFromValue(const UniValue& value);
extern UniValue ValueFromAmount(const CAmount& amount);
extern std::string HelpRequiringPassphrase();
extern std::string HelpExampleCli(const std::string& methodname, const std::string& args);
extern std::string HelpExampleRpc(const std::string& methodname, const std::string& args);

extern void EnsureWalletIsUnlocked();

extern UniValue getconnectioncount(const UniValue& params, bool fHelp); // in rpc/net.cpp
extern UniValue getpeerinfo(const UniValue& params, bool fHelp);
extern UniValue ping(const UniValue& params, bool fHelp);
extern UniValue addnode(const UniValue& params, bool fHelp);
extern UniValue disconnectnode(const UniValue& params, bool fHelp);
extern UniValue getaddednodeinfo(const UniValue& params, bool fHelp);
extern UniValue getnettotals(const UniValue& params, bool fHelp);
extern UniValue setban(const UniValue& params, bool fHelp);
extern UniValue listbanned(const UniValue& params, bool fHelp);
extern UniValue clearbanned(const UniValue& params, bool fHelp);

extern UniValue dumpprivkey(const UniValue& params, bool fHelp); // in rpc/dump.cpp
extern UniValue importprivkey(const UniValue& params, bool fHelp);
extern UniValue importaddress(const UniValue& params, bool fHelp);
extern UniValue importpubkey(const UniValue& params, bool fHelp);
extern UniValue dumpwallet(const UniValue& params, bool fHelp);
extern UniValue importwallet(const UniValue& params, bool fHelp);

extern UniValue getgenerate(const UniValue& params, bool fHelp); // in rpc/cvn.cpp
extern UniValue setgenerate(const UniValue& params, bool fHelp);
extern UniValue fasitologin(const UniValue& params, bool fHelp);
extern UniValue fasitologout(const UniValue& params, bool fHelp);
extern UniValue fasitoinitkey(const UniValue& params, bool fHelp);
extern UniValue fasitononce(const UniValue& params, bool fHelp);
extern UniValue fasitosign(const UniValue& params, bool fHelp);
extern UniValue addcvn(const UniValue& params, bool fHelp);
extern UniValue removecvn(const UniValue& params, bool fHelp);
extern UniValue fasitoschnorr(const UniValue& params, bool fHelp);
extern UniValue fasitoschnorrverify(const UniValue& params, bool fHelp);
extern UniValue fasitohash(const UniValue& params, bool fHelp);
extern UniValue fasitocmd(const UniValue& params, bool fHelp);
extern UniValue getcvninfo(const UniValue& params, bool fHelp);
extern UniValue bancvn(const UniValue& params, bool fHelp);
extern UniValue getchainparameters(const UniValue& params, bool fHelp);
extern UniValue relaynoncepool(const UniValue& params, bool fHelp);
extern UniValue setchainparameters(const UniValue& params, bool fHelp);
extern UniValue getactivecvns(const UniValue& params, bool fHelp);
extern UniValue getactiveadmins(const UniValue& params, bool fHelp);
extern UniValue submitblock(const UniValue& params, bool fHelp);
extern UniValue addcoinsupply(const UniValue& params, bool fHelp);
extern UniValue estimatefee(const UniValue& params, bool fHelp);

extern UniValue getnewaddress(const UniValue& params, bool fHelp); // in rpcwallet.cpp
extern UniValue getaccountaddress(const UniValue& params, bool fHelp);
extern UniValue getrawchangeaddress(const UniValue& params, bool fHelp);
extern UniValue setaccount(const UniValue& params, bool fHelp);
extern UniValue getaccount(const UniValue& params, bool fHelp);
extern UniValue getaddressesbyaccount(const UniValue& params, bool fHelp);
extern UniValue sendtoaddress(const UniValue& params, bool fHelp);
extern UniValue signmessage(const UniValue& params, bool fHelp);
extern UniValue verifymessage(const UniValue& params, bool fHelp);
extern UniValue getreceivedbyaddress(const UniValue& params, bool fHelp);
extern UniValue getreceivedbyaccount(const UniValue& params, bool fHelp);
extern UniValue getbalance(const UniValue& params, bool fHelp);
extern UniValue getunconfirmedbalance(const UniValue& params, bool fHelp);
extern UniValue movecmd(const UniValue& params, bool fHelp);
extern UniValue sendfrom(const UniValue& params, bool fHelp);
extern UniValue sendmany(const UniValue& params, bool fHelp);
extern UniValue addmultisigaddress(const UniValue& params, bool fHelp);
extern UniValue createmultisig(const UniValue& params, bool fHelp);
extern UniValue listreceivedbyaddress(const UniValue& params, bool fHelp);
extern UniValue listreceivedbyaccount(const UniValue& params, bool fHelp);
extern UniValue listtransactions(const UniValue& params, bool fHelp);
extern UniValue listaddressgroupings(const UniValue& params, bool fHelp);
extern UniValue listaccounts(const UniValue& params, bool fHelp);
extern UniValue listsinceblock(const UniValue& params, bool fHelp);
extern UniValue gettransaction(const UniValue& params, bool fHelp);
extern UniValue abandontransaction(const UniValue& params, bool fHelp);
extern UniValue backupwallet(const UniValue& params, bool fHelp);
extern UniValue keypoolrefill(const UniValue& params, bool fHelp);
extern UniValue walletpassphrase(const UniValue& params, bool fHelp);
extern UniValue walletpassphrasechange(const UniValue& params, bool fHelp);
extern UniValue walletlock(const UniValue& params, bool fHelp);
extern UniValue encryptwallet(const UniValue& params, bool fHelp);
extern UniValue validateaddress(const UniValue& params, bool fHelp);
extern UniValue validatepubkey(const UniValue& params, bool fHelp);
extern UniValue getinfo(const UniValue& params, bool fHelp);
extern UniValue getwalletinfo(const UniValue& params, bool fHelp);
extern UniValue getblockchaininfo(const UniValue& params, bool fHelp);
extern UniValue getnetworkinfo(const UniValue& params, bool fHelp);
extern UniValue setmocktime(const UniValue& params, bool fHelp);
extern UniValue resendwallettransactions(const UniValue& params, bool fHelp);

extern UniValue getrawtransaction(const UniValue& params, bool fHelp); // in rcp/rawtransaction.cpp
extern UniValue listunspent(const UniValue& params, bool fHelp);
extern UniValue lockunspent(const UniValue& params, bool fHelp);
extern UniValue listlockunspent(const UniValue& params, bool fHelp);
extern UniValue createrawtransaction(const UniValue& params, bool fHelp);
extern UniValue decoderawtransaction(const UniValue& params, bool fHelp);
extern UniValue decodescript(const UniValue& params, bool fHelp);
extern UniValue fundrawtransaction(const UniValue& params, bool fHelp);
extern UniValue signrawtransaction(const UniValue& params, bool fHelp);
extern UniValue sendrawtransaction(const UniValue& params, bool fHelp);
extern UniValue gettxoutproof(const UniValue& params, bool fHelp);
extern UniValue verifytxoutproof(const UniValue& params, bool fHelp);

extern UniValue getblockcount(const UniValue& params, bool fHelp); // in rpc/blockchain.cpp
extern UniValue getbestblockhash(const UniValue& params, bool fHelp);
extern UniValue settxfee(const UniValue& params, bool fHelp);
extern UniValue getmempoolinfo(const UniValue& params, bool fHelp);
extern UniValue getrawmempool(const UniValue& params, bool fHelp);
extern UniValue getblockhash(const UniValue& params, bool fHelp);
extern UniValue getblockheader(const UniValue& params, bool fHelp);
extern UniValue getblock(const UniValue& params, bool fHelp);
extern UniValue gettxoutsetinfo(const UniValue& params, bool fHelp);
extern UniValue gettxout(const UniValue& params, bool fHelp);
extern UniValue verifychain(const UniValue& params, bool fHelp);
extern UniValue getchaintips(const UniValue& params, bool fHelp);
extern UniValue invalidateblock(const UniValue& params, bool fHelp);
extern UniValue reconsiderblock(const UniValue& params, bool fHelp);

extern UniValue omni_getinfo(const UniValue& params, bool fHelp); // in src/omnicore/rpc.cpp
extern UniValue omni_getactivations(const UniValue& params, bool fHelp);
extern UniValue omni_getallbalancesforid(const UniValue& params, bool fHelp);
extern UniValue omni_getbalance(const UniValue& params, bool fHelp);
extern UniValue omni_gettransaction(const UniValue& params, bool fHelp);
extern UniValue omni_getproperty(const UniValue& params, bool fHelp);
extern UniValue omni_listproperties(const UniValue& params, bool fHelp);
extern UniValue omni_getcrowdsale(const UniValue& params, bool fHelp);
extern UniValue omni_getgrants(const UniValue& params, bool fHelp);
extern UniValue omni_getactivedexsells(const UniValue& params, bool fHelp);
extern UniValue omni_getactivecrowdsales(const UniValue& params, bool fHelp);
extern UniValue omni_getorderbook(const UniValue& params, bool fHelp);
extern UniValue omni_gettrade(const UniValue& params, bool fHelp);
extern UniValue omni_getsto(const UniValue& params, bool fHelp);
extern UniValue omni_listblocktransactions(const UniValue& params, bool fHelp);
extern UniValue omni_listpendingtransactions(const UniValue& params, bool fHelp);
extern UniValue omni_getallbalancesforaddress(const UniValue& params, bool fHelp);
extern UniValue omni_gettradehistoryforaddress(const UniValue& params, bool fHelp);
extern UniValue omni_gettradehistoryforpair(const UniValue& params, bool fHelp);
extern UniValue omni_getcurrentconsensushash(const UniValue& params, bool fHelp);
extern UniValue omni_getpayload(const UniValue& params, bool fHelp);
extern UniValue omni_getseedblocks(const UniValue& params, bool fHelp);
extern UniValue omni_getmetadexhash(const UniValue& params, bool fHelp);
extern UniValue omni_getfeecache(const UniValue& params, bool fHelp);
extern UniValue omni_getfeetrigger(const UniValue& params, bool fHelp);
extern UniValue omni_getfeedistribution(const UniValue& params, bool fHelp);
extern UniValue omni_getfeedistributions(const UniValue& params, bool fHelp);
extern UniValue omni_getbalanceshash(const UniValue& params, bool fHelp);
extern UniValue omni_listtransactions(const UniValue& params, bool fHelp);
extern UniValue omni_getfeeshare(const UniValue& params, bool fHelp);
extern UniValue omni_setautocommit(const UniValue& params, bool fHelp);
extern UniValue mscrpc(const UniValue& params, bool fHelp);
extern UniValue omni_getinfo(const UniValue& params, bool fHelp);
extern UniValue omni_getbalance(const UniValue& params, bool fHelp);
extern UniValue omni_getallbalancesforaddress(const UniValue& params, bool fHelp);
extern UniValue omni_getallbalancesforid(const UniValue& params, bool fHelp);
extern UniValue omni_getproperty(const UniValue& params, bool fHelp);
extern UniValue omni_listproperties(const UniValue& params, bool fHelp);
extern UniValue omni_getcrowdsale(const UniValue& params, bool fHelp);
extern UniValue omni_getgrants(const UniValue& params, bool fHelp);
extern UniValue omni_getactivedexsells(const UniValue& params, bool fHelp);
extern UniValue omni_getactivecrowdsales(const UniValue& params, bool fHelp);
extern UniValue omni_getsto(const UniValue& params, bool fHelp);
extern UniValue omni_getorderbook(const UniValue& params, bool fHelp);
extern UniValue omni_gettrade(const UniValue& params, bool fHelp);
extern UniValue omni_gettransaction(const UniValue& params, bool fHelp);
extern UniValue omni_listblocktransactions(const UniValue& params, bool fHelp);
extern UniValue omni_listtransactions(const UniValue& params, bool fHelp);

extern UniValue omni_createpayload_simplesend(const UniValue& params, bool fHelp); // in src/omnicore/rpcpayload.cpp
extern UniValue omni_createpayload_sendall(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_dexsell(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_dexaccept(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_sto(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_grant(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_revoke(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_changeissuer(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_trade(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_issuancefixed(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_issuancecrowdsale(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_issuancemanaged(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_closecrowdsale(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_canceltradesbyprice(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_canceltradesbypair(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_cancelalltrades(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_enablefreezing(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_disablefreezing(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_freeze(const UniValue& params, bool fHelp);
extern UniValue omni_createpayload_unfreeze(const UniValue& params, bool fHelp);

extern UniValue omni_decodetransaction(const UniValue& params, bool fHelp); // in src/omnicore/rpcrawtx.cpp
extern UniValue omni_createrawtx_opreturn(const UniValue& params, bool fHelp);
extern UniValue omni_createrawtx_multisig(const UniValue& params, bool fHelp);
extern UniValue omni_createrawtx_input(const UniValue& params, bool fHelp);
extern UniValue omni_createrawtx_reference(const UniValue& params, bool fHelp);
extern UniValue omni_createrawtx_change(const UniValue& params, bool fHelp);

extern UniValue omni_sendrawtx(const UniValue& params, bool fHelp); // in src/omnicore/rpctx.cpp
extern UniValue omni_send(const UniValue& params, bool fHelp);
extern UniValue omni_senddexsell(const UniValue& params, bool fHelp);
extern UniValue omni_senddexaccept(const UniValue& params, bool fHelp);
extern UniValue omni_sendissuancecrowdsale(const UniValue& params, bool fHelp);
extern UniValue omni_sendissuancefixed(const UniValue& params, bool fHelp);
extern UniValue omni_sendissuancemanaged(const UniValue& params, bool fHelp);
extern UniValue omni_sendtrade(const UniValue& params, bool fHelp);
extern UniValue omni_sendcanceltradesbyprice(const UniValue& params, bool fHelp);
extern UniValue omni_sendcanceltradesbypair(const UniValue& params, bool fHelp);
extern UniValue omni_sendcancelalltrades(const UniValue& params, bool fHelp);
extern UniValue omni_sendsto(const UniValue& params, bool fHelp);
extern UniValue omni_sendgrant(const UniValue& params, bool fHelp);
extern UniValue omni_sendrevoke(const UniValue& params, bool fHelp);
extern UniValue omni_sendclosecrowdsale(const UniValue& params, bool fHelp);
extern UniValue omni_sendchangeissuer(const UniValue& params, bool fHelp);
extern UniValue omni_sendall(const UniValue& params, bool fHelp);
extern UniValue omni_sendenablefreezing(const UniValue& params, bool fHelp);
extern UniValue omni_senddisablefreezing(const UniValue& params, bool fHelp);
extern UniValue omni_sendfreeze(const UniValue& params, bool fHelp);
extern UniValue omni_sendunfreeze(const UniValue& params, bool fHelp);
extern UniValue omni_senddeactivation(const UniValue& params, bool fHelp);
extern UniValue omni_sendactivation(const UniValue& params, bool fHelp);
extern UniValue omni_sendalert(const UniValue& params, bool fHelp);
extern UniValue omni_sendrawtx(const UniValue& params, bool fHelp);
extern UniValue omni_send(const UniValue& params, bool fHelp);
extern UniValue omni_sendsto(const UniValue& params, bool fHelp);
extern UniValue trade_MP(const UniValue& params, bool fHelp);

bool StartRPC();
void InterruptRPC();
void StopRPC();
std::string JSONRPCExecBatch(const UniValue& vReq);

#endif // BITCOIN_RPCSERVER_H
