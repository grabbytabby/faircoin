// Copyright (c) 2016-2018 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utilstrencodings.h"
#include "random.h"
#include "key.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

static bool writeKey(BIO * const bio, EC_KEY *pkey, const std::string &strPassword)
{
#if 0
    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(evp_key, pkey);

    if (!PEM_write_bio_PrivateKey(bio, evp_key, EVP_aes_256_cbc(), (uint8_t *) &strPassword.begin()[0], strPassword.length(), NULL, NULL)) {

        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(evp_key);
        return false;
    }
#else
    if (!PEM_write_bio_ECPrivateKey(bio, pkey, EVP_aes_256_cbc(), (uint8_t *) &strPassword.begin()[0], strPassword.length(), NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        return false;
    }
#endif
    return true;
}

static EC_KEY *createKey(const uint8_t * const vch)
{
    EC_KEY *key;
    BIGNUM *priv;
    BN_CTX *ctx;
    const EC_GROUP *group;
    EC_POINT *pubKey;

    key = EC_KEY_new_by_curve_name(NID_secp256k1);

    priv = BN_new();
    BN_bin2bn(vch, 32, priv);
    EC_KEY_set_private_key(key, priv);

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pubKey = EC_POINT_new(group);
    EC_POINT_mul(group, pubKey, priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pubKey);

    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    EC_POINT_free(pubKey);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(priv);

    return key;
}

typedef PAIRTYPE(int, std:: string) v3EXT_t;
static const std::vector<v3EXT_t> vX509v3Extentions = boost::assign::list_of
    (v3EXT_t(NID_subject_key_identifier, "hash"))
    (v3EXT_t(NID_authority_key_identifier, "keyid:always"))
    (v3EXT_t(NID_basic_constraints, "CA:TRUE"))
;

bool createKeyFile(const std::string &strFileName, const std::string &strOragnization, const std::string &strOragnizationUnit, const std::string &strId, const std::string &strPrivKeyPassword, CKey &key)
{
    bool fRet = false;

    uint8_t vch[32];
    GetStrongRandBytes(vch, sizeof(vch));
    EC_KEY *k = createKey(vch);

    BIO *bio = BIO_new_file(strFileName.c_str(), "w");

    if (!writeKey(bio, k, strPrivKeyPassword)) {
        fprintf(stderr, "ERROR: could not save key\n");
    }

    X509 *cert = X509_new();
    X509_set_version(cert, 2);

    int64_t nSerial = 0;
    // make sure the serial number is positive
    do {
        GetStrongRandBytes((uint8_t *) &nSerial, sizeof(nSerial));
    } while(nSerial < 1);

    ASN1_INTEGER_set(X509_get_serialNumber(cert), nSerial);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 10000); // valid for 10000 days
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (uint8_t *) strOragnization.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (uint8_t *) strOragnizationUnit.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (uint8_t *) strId.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, name);

    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(evp_key, k);
    X509_set_pubkey(cert, evp_key);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, 0, 0, 0);

    BOOST_FOREACH(const v3EXT_t& v3extention, vX509v3Extentions) {
        X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, v3extention.first, (char *) v3extention.second.c_str());
        X509_add_ext(cert, ex, -1);
        X509_EXTENSION_free(ex);
    }

    const BIGNUM *bnPrivKey = EC_KEY_get0_private_key(k);

    unsigned char buf[256];
    size_t sKeyLen = BN_bn2bin(bnPrivKey, buf);
    const vector<unsigned char> data(buf, buf + sKeyLen);
    key.Set(data.begin(), data.end(), false);

    if (!key.IsValid()) {
        fprintf(stderr, "ERROR: created key is invalid.\n");
        return false;
    }

    if (!X509_sign(cert, evp_key, EVP_sha256())) {
        fprintf(stderr, "ERROR: could not sign certificate.\n");
        goto out;
    }

    if (!PEM_write_bio_X509(bio, cert)){
        fprintf(stderr, "ERROR: could not write certificate.\n");
        goto out;
    }

    fRet = true;

out:
    memset(vch, 0, sizeof(vch));
    memset(buf, 0, sizeof(buf));

    if (name)
        X509_NAME_free(name);
    if (evp_key)
        EVP_PKEY_free(evp_key);

    if (k)
        EC_KEY_free(k);
    if (bio)
        BIO_free_all(bio);

    return fRet;
}
