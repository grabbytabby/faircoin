// Copyright (c) 2016-2018 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SRC_FAIRCHAINS_TOOL_KEY_H_
#define SRC_FAIRCHAINS_TOOL_KEY_H_

#include <string>
#include "key.h"

bool createKeyFile(const std::string &strFileName, const std::string &strOragnization, const std::string &strOragnizationUnit, const std::string &strId, const std::string &strPrivKeyPassword, CKey &key);

#endif /* SRC_FAIRCHAINS_TOOL_KEY_H_ */
