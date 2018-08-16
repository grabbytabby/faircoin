// Copyright (c) 2016-2018 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SRC_FAIRCHAINS_TOOL_INPUT_H_
#define SRC_FAIRCHAINS_TOOL_INPUT_H_

#include <univalue.h>
#include <vector>

extern void prompt4String(UniValue &out, const std::string &fieldName, const std::string &prompt, const std::string &defaultValue, const int nMaxLength);
extern void prompt4StringArray(UniValue &out, const std::string &fieldName, const std::string &prompt, const std::vector<std::string> &vDefaultValue = vector<string>());
extern int prompt4Integer(UniValue &out, const std::string &fieldName, const std::string &prompt, const int &defaultValue = -1, bool (*cbCheckValueInt)(const int nVal) = NULL);
extern double prompt4Double(UniValue &out, const string &fieldName, const string &prompt, const double &defaultValue = -1, bool (*cbCheckValueDouble)(const double nVal) = NULL);
extern void prompt4Hex(UniValue &out, const std::string &fieldName, const std::string &prompt, const std::string &defaultValue);
extern void prompt4FixedSeeds(UniValue &out, const std::string &fieldName, const std::string &prompt, const uint16_t nPort, const std::vector<std::string> &vDefaultValue = std::vector<std::string>());
extern void prompt4Bool(UniValue &out, const std::string &fieldName, const std::string &prompt, const bool defaultValue = false);

extern bool checkForValidPorts(const int nVal);
extern bool checkByteSize(const int nVal);

#endif /* SRC_FAIRCHAINS_TOOL_INPUT_H_ */
