// Copyright (c) 2016-2018 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utilstrencodings.h"
#include "tinyformat.h"

#include <iostream>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>

#include <univalue.h>

using namespace std;

void prompt4String(UniValue &out, const string &fieldName, const string &prompt, const string &defaultValue = "", const int nMaxLength = -1)
{
    bool fDone = false;
    string strVal;

    do {
        cout << prompt;
        if (defaultValue != "") {
            cout << " (" << defaultValue << ")";
        }
        cout << ": ";
        flush(cout);
        getline(cin, strVal);

        if (strVal == "") {
            if (defaultValue == "") {
                cout << "--> please enter a value." << endl;
                continue;
            }
            strVal = defaultValue;
        } else if (nMaxLength != -1 && strVal.length() > nMaxLength) {
            cout << "--> string too long. Max: " << nMaxLength << endl;
            continue;
        }

        fDone = true;
    } while(!fDone);

    out.push_back(Pair(fieldName, strVal));
}

static string array2Str(const vector<string>& vValues)
{
    string out;

    for (vector<string>::const_iterator strIter = vValues.begin(); strIter != vValues.end(); ++strIter) {
        out += *strIter;
        if (strIter != vValues.end() - 1) {
            out += ',';
        }
    }

    return out;
}

void prompt4StringArray(UniValue &out, const string &fieldName, const string &prompt, const vector<string> &vDefaultValue)
{
    bool fDone = false;
    string strVal;
    vector<string> vValues;
    UniValue array(UniValue::VARR);
    int nIdx = 0;

    do {
        if (!nIdx) {
            cout << prompt;
            if (!vDefaultValue.empty()) {
                cout << " (" << array2Str(vDefaultValue) << ")";
            }
            cout << ":" << endl;
        }
        getline(cin, strVal);

        if (strVal == "") {
            cout << "--> please enter a value." << endl;
            continue;
        }

        if (strVal == ".") {
            if (nIdx == 0) {
                if (vDefaultValue.empty()) {
                    cout << "--> please enter a value." << endl;
                    continue;
                }
                BOOST_FOREACH(const string strLine, vDefaultValue) {
                    vValues.push_back(strLine);
                }
            }

            fDone = true;
        } else {
            vValues.push_back(strVal);
            nIdx++;
        }
    } while(!fDone);

    BOOST_FOREACH(const string strLine, vValues) {
        array.push_back(strLine);
    }

    out.push_back(Pair(fieldName, array));
}

int prompt4Integer(UniValue &out, const string &fieldName, const string &prompt, const int &defaultValue = -1, bool (*cbCheckValueInt)(const int nVal) = NULL)
{
    bool fDone = false;
    int nVal = 0;

    do {
        cout << prompt;
        if (defaultValue != -1) {
            cout << " (" << defaultValue << ")";
        }
        cout << ": ";
        flush(cout);
        string strVal;
        getline(cin, strVal);

        if (strVal == "") {
            if (defaultValue == -1) {
                cout << "--> please enter a value." << endl;
                continue;
            }
            nVal = defaultValue;
        } else {
            try {
                nVal = stoi(strVal, NULL);
            } catch(...) {
                cout << "--> input invalid." << endl;
                continue;
            }
        }

        if (cbCheckValueInt && !cbCheckValueInt(nVal)) {
            continue;
        }

        fDone = true;
    } while(!fDone);

    out.push_back(Pair(fieldName, nVal));
    return nVal;
}

double prompt4Double(UniValue &out, const string &fieldName, const string &prompt, const double &defaultValue = -1, bool (*cbCheckValueDouble)(const double nVal) = NULL)
{
    bool fDone = false;
    double nVal = 0;

    do {
        cout << prompt;
        if (defaultValue != -1) {
            cout << " (" << defaultValue << ")";
        }
        cout << ": ";
        flush(cout);
        string strVal;
        getline(cin, strVal);

        if (strVal == "") {
            if (defaultValue == -1) {
                cout << "--> please enter a value." << endl;
                continue;
            }
            nVal = defaultValue;
        } else {
            try {
                nVal = stod(strVal, NULL);
            } catch(...) {
                cout << "--> input invalid." << endl;
                continue;
            }
        }

        if (cbCheckValueDouble && !cbCheckValueDouble(nVal)) {
            continue;
        }

        fDone = true;
    } while(!fDone);

    out.push_back(Pair(fieldName, nVal));
    return nVal;
}

void prompt4Hex(UniValue &out, const string &fieldName, const string &prompt, const string &defaultValue = "")
{
    bool fDone = false;
    string strVal;

    do {
        cout << prompt;
        if (defaultValue != "") {
            cout << " (" << defaultValue << ")";
        }
        cout << ": ";
        flush(cout);
        getline(cin, strVal);

        if (strVal == "") {
            if (defaultValue == "") {
                cout << "--> please enter a value." << endl;
                continue;
            }
            strVal = defaultValue;
        }

        if (strVal.length() < 10) {
            cout << "--> input number too short." << endl;
            continue;
        }
        if (strVal.length() > 10) {
            cout << "--> input number too long." << endl;
            continue;
        }

        try {
            uint32_t nVal;
            stringstream ss;
            ss << hex << strVal;
            ss >> nVal;

            if (strprintf("0x%08x", nVal) != strVal) {
                cout << "--> input invalid." << endl;
                continue;
            }
        } catch (...) {
            cout << "--> input invalid." << endl;
            continue;
        }

        fDone = true;
    } while(!fDone);

    out.push_back(Pair(fieldName, strVal));
}

static bool convertIPv6Address(const string &strAddrIn, string &out)
{
    const string pad[4] = {"0", "00", "000", "0000"};
    int nIdx = 0;
    string strAddr;
    bool fDoubleColon = false;

    for (string::size_type i = 0; i < strAddrIn.length(); ++i) {
        strAddr += tolower(strAddrIn[i]);
    }

    vector<string> vNibbles;
    boost::split(vNibbles, strAddr, boost::is_any_of(":"));
    BOOST_FOREACH(const string &strN, vNibbles) {
        if (strN.length() < 4) {
            out += pad[3 - strN.length()];
            if (!strN.length()) { // double colon "::"
                if (fDoubleColon) {
                    return false;
                }

                fDoubleColon = true;
                int nToPad = 8 - (vNibbles.size() - 1);
                for (int i = 1 ; i < nToPad ; ++i) {
                    out += pad[3];
                }
            }
        }
        out += strN;
        ++nIdx;
    }

    return true;
}

static bool convertIpAddress2Hex(const string &addr, string &out)
{
    bool isIPv4 = false;

    for (size_t i = 0 ; i < addr.length() ; i++) {
        if (addr[i] == '.') {
            isIPv4 = true;
            break;
        }
    }

    if (isIPv4) {
        vector<string> vNibbles;
        boost::split(vNibbles, addr,boost::is_any_of("."));
        if (vNibbles.size() != 4) {
            cout << "IPv4 address is invalid: " << addr << endl;
            return false;
        }

        int n0 = stoi(vNibbles[0]); int n1 = stoi(vNibbles[1]); int n2 = stoi(vNibbles[2]); int n3 = stoi(vNibbles[3]);

        if (n0 == 127 || (n0 == 169 && n1 == 254) ||
                n0 == 0 || n0 > 223 || n1 == 0 || n1 > 255 ||
                n2 == 0 || n2 > 255 || n3 == 0 || n3 > 255) {
            cout << "IPv4 address is out of range: " << addr << endl;
            return false;
        }

        out = strprintf("00000000000000000000ffff%02x%02x%02x%02x", n0, n1, n2, n3);
    } else {
        if (!convertIPv6Address(addr, out)) {
            cout << "IPv6 address invalid: " << addr << endl;
            return false;
        }
    }

    return true;
}

void prompt4FixedSeeds(UniValue &out, const string &fieldName, const string &prompt, const uint16_t nPort, const vector<string> &vDefaultValue)
{
    bool fDone = false;
    string strVal;
    vector<string> vValues;
    UniValue array(UniValue::VARR);
    int nIdx = 0;

    do {
        if (!nIdx) {
            cout << prompt;
            if (!vDefaultValue.empty()) {
                cout << "(" << array2Str(vDefaultValue) << ")";
            }
            cout << ":" << endl;
        }
        getline(cin, strVal);

        if (strVal == "") {
            cout << "--> please enter a value." << endl;
            continue;
        }

        if (strVal == ".") {
            if (nIdx == 0) {
                if (vDefaultValue.empty()) {
                    cout << "--> please enter a value." << endl;
                    continue;
                }
                BOOST_FOREACH(const string strLine, vDefaultValue) {
                    string addr;
                    convertIpAddress2Hex(strLine, addr);
                    vValues.push_back(addr);
                }
            }

            fDone = true;
        } else {
            string addr;
            if (!convertIpAddress2Hex(strVal, addr)) {
                cout << "--> IP address invalid." << endl;
                continue;
            }
            vValues.push_back(addr);
            nIdx++;
        }
    } while(!fDone);

    BOOST_FOREACH(const string &strLine, vValues) {
        UniValue seed(UniValue::VOBJ);
        seed.push_back(Pair("ipAddress", strLine));
        seed.push_back(Pair("port", nPort));
        array.push_back(seed);
    }

    out.push_back(Pair(fieldName, array));
}

void prompt4Bool(UniValue &out, const string &fieldName, const string &prompt, const bool defaultValue = false)
{
    bool fDone = false;
    string strVal;
    bool fValue = false;

    do {
        cout << prompt;
        cout << " (" << (defaultValue ? "true" : "false") << ")";
        cout << ": ";
        flush(cout);
        getline(cin, strVal);

        if (strVal == "") {
            fValue = defaultValue;
        } else if (strVal[0] == 't') {
            fValue = true;
        } else if (strVal[0] == 'f') {
            fValue = false;
        } else {
            cout << "--> input invalid" << endl;
            continue;
        }

        fDone = true;
    } while(!fDone);

    out.push_back(Pair(fieldName, fValue));
}

bool checkForValidPorts(const int nVal)
{
    if (nVal == 40404 || nVal == 41404) {
        cout << "--> use a different port. This port is used by FairCoin" << endl;
        return false;
    }

    if (nVal == 0 || nVal > 65535) {
        cout << "--> port value out of range." << endl;
        return false;
    }

    return true;
}

bool checkByteSize(const int nVal)
{
    if (nVal < 0 || nVal > 0xff) {
        cout << "--> value " << nVal << " out of range." << endl;
        return false;
    }

    return true;
}
