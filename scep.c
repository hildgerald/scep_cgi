#include "scep.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "logger.h"



/**
 * @fn char trim*(char*)
 * @brief
 *
 * @param s
 * @return
 */
static char *trim(char *s)
{
    char *p;
    char *q;

    while (*s && (*s == ' ' || *s == '\t')) {
        ++s;
    }

    for (p = q = s; *q; ++q) {
        if (*q != ' ' && *q != '\t') {
            p = q;
        }
    }

    if (*p) {
        p[1] = '\0';
    }

    return s;
}

/**
 * @fn int scep_oid2nid(const char*)
 * @brief
 *
 * @param oid
 * @return
 */
static int scep_oid2nid(const char *oid)
{
    int nid;

    nid = OBJ_txt2nid(oid);
    if (nid != NID_undef) {
        return nid;
    }

    return OBJ_create(oid, NULL, NULL);
}

/**
 * @fn int scep_get_rsa_key_bits(EVP_PKEY*)
 * @brief
 *
 * @param pkey
 * @return
 */
static int scep_get_rsa_key_bits(EVP_PKEY *pkey)
{
    const BIGNUM *bn;
    const RSA *rsa;
    int bytes;

    rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        LOGD("scep: key is not of type RSA");
        return -1;
    }

    bn = RSA_get0_n(rsa);
    if (!bn) {
        return -1;
    }

    bytes = BN_num_bytes(bn);
    if (bytes < 0) {
        return -1;
    }

    return bytes * 8;
}

/**
 * @fn struct scep scep_new*(const struct scep_configure*)
 * @brief
 *
 * @param configure
 * @return
 */
struct scep *scep_new(const struct scep_configure *configure)
{
    struct scep *scep;

    scep = (struct scep *)malloc(sizeof(*scep));
    if (!scep) {
        return NULL;
    }

    memset(scep, 0, sizeof(*scep));
    if (configure) {
        memcpy(&scep->configure, configure, sizeof(*configure));
    }

    scep->NID_SCEP_messageType    = scep_oid2nid("2.16.840.1.113733.1.9.2");
    scep->NID_SCEP_pkiStatus      = scep_oid2nid("2.16.840.1.113733.1.9.3");
    scep->NID_SCEP_failInfo       = scep_oid2nid("2.16.840.1.113733.1.9.4");
    scep->NID_SCEP_senderNonce    = scep_oid2nid("2.16.840.1.113733.1.9.5");
    scep->NID_SCEP_recipientNonce = scep_oid2nid("2.16.840.1.113733.1.9.6");
    scep->NID_SCEP_transactionID  = scep_oid2nid("2.16.840.1.113733.1.9.7");
    scep->NID_SCEP_extensionReq   = scep_oid2nid("2.16.840.1.113733.1.9.8");

    if (scep->NID_SCEP_messageType    == NID_undef ||
        scep->NID_SCEP_pkiStatus      == NID_undef ||
        scep->NID_SCEP_failInfo       == NID_undef ||
        scep->NID_SCEP_senderNonce    == NID_undef ||
        scep->NID_SCEP_recipientNonce == NID_undef ||
        scep->NID_SCEP_transactionID  == NID_undef ||
        scep->NID_SCEP_extensionReq   == NID_undef ){

        free(scep);
        return NULL;
    }

    return scep;
}

/**
 * @fn int scep_load_subject_extension(struct scep*, char*)
 * @brief
 *
 * @param scep
 * @param buffer
 * @return
 */
static int scep_load_subject_extension(struct scep *scep, char *buffer)
{
    struct scep_extension *e;
    struct scep_extension *p;
    char *value;
    char *copy;
    char *key;
    int nid;

    if (!*buffer || *buffer == '#') {
        return 0;
    }

    value = strchr(buffer, '=');
    if (!value) {
        return -1;
    }

    *value++ = '\0';
    key = trim(buffer);
    value = trim(value);
    if (!*key || !*value) {
        return -1;
    }

    nid = OBJ_txt2nid(key);
    if (nid == NID_undef) {
        return -1;
    }

    copy = strdup(value);
    if (!copy) {
        return -1;
    }

    e = (struct scep_extension *)malloc(sizeof(*e));
    if (!e) {
        free(copy);
        return -1;
    }

    memset(e, 0, sizeof(*e));
    e->value = copy;
    e->nid = nid;

    if (!(p = scep->extensions)) {
        scep->extensions = e;
        return 0;
    }

    while (p->next) {
        p = p->next;
    }

    p->next = e;
    return 0;
}

/**
 * @fn int scep_load_subject_extensions(struct scep*, const char*)
 * @brief
 *
 * @param scep
 * @param filename
 * @return
 */
int scep_load_subject_extensions(struct scep *scep, const char *filename)
{
    char line[256];
    BIO *bp;
    int len;

    bp = BIO_new_file(filename, "r");
    if (!bp) {
        return -1;
    }

    while ((len = BIO_gets(bp, line, sizeof(line))) > 0) {
        if (line[len - 1] == '\n') {
            line[--len] = '\0';
        }

        if (scep_load_subject_extension(scep, line)) {
            len = -1;
            break;
        }
    }

    BIO_free_all(bp);
    return len >= 0 ? 0 : -1;
}

/**
 * @fn void scep_free(struct scep*)
 * @brief
 *
 * @param scep
 */
void scep_free(struct scep *scep)
{
    struct scep_extension *p;
    X509 *cert;
    int num;
    int i;

    if (scep->store) {
        X509_STORE_free(scep->store);
    }

    if (scep->chain) { /* Signing cert is included */
        assert(scep->pkey);
        EVP_PKEY_free(scep->pkey);
        num = sk_X509_num(scep->chain);
        for (i = 0; i < num; ++i) {
            cert = sk_X509_value(scep->chain, i);
            X509_free(cert);
        }

        sk_X509_free(scep->chain);
    }

    while ((p = scep->extensions)) {
        scep->extensions = p->next;
        free(p->value);
        free(p);
    }

    free(scep);
}

/**
 * @fn int scep_check_digest_algo(int)
 * @brief
 *
 * @param nid
 * @return
 */
static int scep_check_digest_algo(int nid)
{
    /* There're many algos, just block some known bad ones */
    switch (nid) {
    case NID_undef:
    case NID_md2:
    case NID_md4:
    case NID_md5:
        return -1;
    }

    return 0;
}

/**
 * @fn int scep_check_signature_algo(int)
 * @brief
 *
 * @param nid
 * @return
 */
static int scep_check_signature_algo(int nid)
{
    const EVP_MD *md;

    /* Explicit allow naked RSA without any hash */
    switch (nid) {
    case NID_rsaEncryption:
        return 0;
    }

    /* Otherwise the algorithm should contain a digest */
    md = EVP_get_digestbynid(nid);
    if (!md) {
        return -1;
    }

    nid = EVP_MD_nid(md);
    return scep_check_digest_algo(nid);
}

/**
 * @fn int scep_PKCS7_SIGNER_INFO_check_algo(PKCS7_SIGNER_INFO*)
 * @brief
 *
 * @param si
 * @return
 */
static int scep_PKCS7_SIGNER_INFO_check_algo(PKCS7_SIGNER_INFO *si)
{
    X509_ALGOR *digest;
    X509_ALGOR *sign;
    int nid;

    PKCS7_SIGNER_INFO_get0_algs(si, NULL, &digest, &sign);
    if (!digest || !sign) {
        return -1;
    }

    nid = OBJ_obj2nid(digest->algorithm);
    if (scep_check_digest_algo(nid)) {
        return -1;
    }

    nid = OBJ_obj2nid(sign->algorithm);
    if (scep_check_signature_algo(nid)) {
        return -1;
    }

    return 0;
}

/**
 * @fn X509 scep_load_certificate_only*(const char*, int, const EVP_MD**)
 * @brief
 *
 * @param certfile
 * @param certpem
 * @param md
 * @return
 */
static X509 *scep_load_certificate_only(
        const char *certfile,
        int certpem,
        const EVP_MD **md)
{
    X509 *cert;
    BIO *bp;
    int nid;

    LOGD("Enter scep_load_certificate_only.");
    bp = BIO_new_file(certfile, "rb");
    if (!bp) {
    	LOGE("Impossible to read certfile (%s).",certfile);
        return NULL;
    }

    if (certpem) {
    	LOGD("Read pem certificate.");
        cert = PEM_read_bio_X509(bp, NULL, NULL, NULL);
    } else {
    	LOGD("Read der certificate.");
        cert = d2i_X509_bio(bp, NULL);
    }

    if (!cert) {
    	LOGE("Certificate is not in the good format (%s)",certfile);
        BIO_free_all(bp);
        return NULL;
    }

    BIO_free_all(bp);
    if (X509_get_version(cert) < 2) { /* X509 V3 */
    	LOGE("Certificate is not in the good version (%d)",X509_get_version(cert));
        X509_free(cert);
        return NULL;
    }

    if (!md) {
    	LOGD("OK, Certificate is returned without other verification");
        return cert;
    }

    nid = X509_get_signature_nid(cert);
    if (scep_check_signature_algo(nid)) {
    	LOGE("Certificate don't has the good signature");
        X509_free(cert);
        return NULL;
    }

    *md = EVP_get_digestbynid(nid);
    if (!*md) {
    	LOGE("Certificate don't has the good digest");
        X509_free(cert);
        return NULL;
    }
    LOGD("OK, Certificate is returned");
    return cert;
}

/**
 * @fn int scep_load_certificate(struct scep*, const char*, int, const char*, int, const char*)
 * @brief
 *
 * @param scep
 * @param certfile
 * @param certpem
 * @param keyfile
 * @param keypem
 * @param keypass
 * @return
 */
int scep_load_certificate(
        struct scep *scep,
        const char *certfile,
        int certpem,
        const char *keyfile,
        int keypem,
        const char *keypass)
{
    STACK_OF(X509) *chain;
    X509_STORE *store;
    const EVP_MD *md;
    EVP_PKEY *pkey;
    X509 *cert;
    BIO *bp;

    LOGD("Enter scep_load_certificate");
    if (!scep || scep->cert) {
    	LOGE("No scep object Error");
        return -1;
    }

    cert = scep_load_certificate_only(certfile, certpem, &md);
    if (!cert) {
    	LOGE("No certificate loaded, error");
        return -1;
    }

    bp = BIO_new_file(keyfile, "rb");
    if (!bp) {
    	LOGE("Impossible to create the BIO for the keyfile :%s of type %d",keyfile,keypem);
        X509_free(cert);
        return -1;
    }

    if (keypem) {
    	LOGD("Load key in pem format");
        pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, (void *)keypass);
    } else {
    	LOGD("Load key in der format");
        pkey = d2i_PrivateKey_bio(bp, NULL);
    }

    if (!pkey) {
    	LOGE("Impossible to read the keyfile :%s of type %d",keyfile,keypem);
        BIO_free_all(bp);
        X509_free(cert);
        return -1;
    }

    BIO_free_all(bp);

    LOGD("Create the chain object");
    chain = sk_X509_new_null();
    if (!chain) {
    	LOGE("Impossible to create the chain object");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    if (sk_X509_push(chain, cert) == 0) {
    	LOGE("Impossible to put certificate in the chain object");
        sk_X509_free(chain);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    store = X509_STORE_new();
    if (!store) {
        sk_X509_free(chain);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    if (X509_STORE_add_cert(store, cert) != 1) {
    	LOGE("Impossible to store certificate");
        X509_STORE_free(store);
        sk_X509_free(chain);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    assert(!scep->store);
    assert(!scep->chain);
    assert(!scep->cert);
    assert(!scep->pkey);
    assert(!scep->md);

    scep->store = store;
    scep->chain = chain;
    scep->cert = cert;
    scep->pkey = pkey;
    scep->md = md;
    LOGD("Quit scep_load_certificate without error");
    return 0;
}

/**
 * @fn int scep_load_certificate(struct scep*, const char*, int, const char*, int, const char*)
 * @brief
 *
 * @param scep
 * @param certfile
 * @param certpem
 * @param keyfile
 * @param keypem
 * @param keypass
 * @return
 */
int scep_load_signer_certificate(
        struct scep *scep,
        const char *certfile,
        int certpem,
        const char *keyfile,
        int keypem,
        const char *keypass)
{
    STACK_OF(X509) *chain;
    X509_STORE *store;
    const EVP_MD *md;
    EVP_PKEY *pkey;
    X509 *cert;
    BIO *bp;

    LOGD("Enter scep_load_signer_certificate");
    if (!scep || scep->signcert) {
    	LOGE("No scep object Error");
        return -1;
    }

    cert = scep_load_certificate_only(certfile, certpem, &md);
    if (!cert) {
    	LOGE("No certificate loaded, error");
        return -1;
    }

    bp = BIO_new_file(keyfile, "rb");
    if (!bp) {
    	LOGE("Impossible to create the BIO for the keyfile :%s of type %d",keyfile,keypem);
        X509_free(cert);
        return -1;
    }

    if (keypem) {
    	LOGD("Load key in pem format");
        pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, (void *)keypass);
    } else {
    	LOGD("Load key in der format");
        pkey = d2i_PrivateKey_bio(bp, NULL);
    }

    if (!pkey) {
    	LOGE("Impossible to read the keyfile :%s of type %d",keyfile,keypem);
        BIO_free_all(bp);
        X509_free(cert);
        return -1;
    }

    BIO_free_all(bp);

    LOGD("Create the chain object");
    chain = sk_X509_new_null();
    if (!chain) {
    	LOGE("Impossible to create the chain object");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    if (sk_X509_push(chain, cert) == 0) {
    	LOGE("Impossible to put certificate in the chain object");
        sk_X509_free(chain);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

#if 0
    store = X509_STORE_new();
    if (!store) {
        sk_X509_free(chain);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    if (X509_STORE_add_cert(store, cert) != 1) {
    	LOGE("Impossible to store certificate");
        X509_STORE_free(store);
        sk_X509_free(chain);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }
#endif
//    assert(!scep->store);
    assert(!scep->signchain);
    assert(!scep->signcert);
    assert(!scep->signpkey);
//    assert(!scep->md);

//    scep->store = store;
    scep->signchain = chain;
    scep->signcert = cert;
    scep->signpkey = pkey;
//    scep->md = md;
    LOGD("Quit scep_load_signer_certificate without error");
    return 0;
}
/**
 * @fn int scep_load_certificate_chain(struct scep*, const char*, int)
 * @brief
 *
 * @param scep
 * @param certfile
 * @param certpem
 * @return
 */
int scep_load_certificate_chain(
        struct scep *scep,
        const char *certfile,
        int certpem)
{
    X509 *cert;

    if (!scep || !scep->cert) {
        return -1;
    }

    cert = scep_load_certificate_only(certfile, certpem, NULL);
    if (!cert) {
        return -1;
    }

    assert(scep->chain);
    if (sk_X509_push(scep->chain, cert) <= 0) {
        X509_free(cert);
        return -1;
    }

    return 0;
}

/**
 * @fn int scep_load_other_ca_certificate(struct scep*, const char*, int)
 * @brief
 *
 * @param scep
 * @param certfile
 * @param certpem
 * @return
 */
int scep_load_other_ca_certificate(
        struct scep *scep,
        const char *certfile,
        int certpem)
{
    X509 *cert;

    if (!scep || !scep->cert) {
        return -1;
    }

    cert = scep_load_certificate_only(certfile, certpem, NULL);
    if (!cert) {
        return -1;
    }

    assert(scep->store);
    if (X509_STORE_add_cert(scep->store, cert) != 1) {
        X509_free(cert);
        return -1;
    }

    return 0;
}

/**
 * @fn int scep_decrypt(struct scep*, BIO**)
 * @brief
 *
 * @param scep
 * @param bpp
 * @return
 */
static int scep_decrypt(struct scep *scep, BIO **bpp)
{
    PKCS7 *pkcs7;
    BIO *wbp;
    BIO *rbp;

    rbp = *bpp;
    pkcs7 = d2i_PKCS7_bio(rbp, NULL);
    if (!pkcs7) {
        return -1;
    }

    if (!PKCS7_type_is_enveloped(pkcs7)) {
        PKCS7_free(pkcs7);
        return -1;
    }

    wbp = BIO_new(BIO_s_mem());
    if (!wbp) {
        PKCS7_free(pkcs7);
        return -1;
    }

    if (PKCS7_decrypt(pkcs7, scep->pkey, scep->cert, wbp, 0) != 1) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return -1;
    }

    PKCS7_free(pkcs7);
    BIO_free_all(rbp);
    *bpp = wbp;
    return 0;
}

/**
 * @fn ASN1_TYPE scep_get_req_attribute*(X509_REQ*, int, int)
 * @brief
 *
 * @param req
 * @param nid
 * @param expected_type
 * @return
 */
static ASN1_TYPE *scep_get_req_attribute(
        X509_REQ *req,
        int nid, int expected_type)
{
    X509_ATTRIBUTE *a;
    ASN1_TYPE *type;
    int count;
    int loc;

    loc = X509_REQ_get_attr_by_NID(req, nid, -1);
    if (loc < 0) {
    	LOGD("The NID isn't find: %d",nid);
        return NULL;
    }

    a = X509_REQ_get_attr(req, loc);
    if (!a) {
    	LOGD("The attribute isn't find: %d",loc);
        return NULL;
    }

    count = X509_ATTRIBUTE_count(a);
    if (count <= 0) {
    	LOGD("The count of attribute isn't find: %d",count);
        return NULL;
    }
    LOGD("The count of attribute is: %d",count);

    type = X509_ATTRIBUTE_get0_type(a, 0);
    if (!type) {
    	LOGD("The type of attribute isn't exists");
        return NULL;
    }

    if (ASN1_TYPE_get(type) != expected_type) {
    	LOGD("We don't find the expected attribute : find %d attribute and expected %d", ASN1_TYPE_get(type), expected_type);
        return NULL;
    }

    LOGD("We find the expected attribute");
    return type;
}

/**
 * @fn int scep_get_req_extensions(struct scep*, X509_REQ*)
 * @brief this function get the extensions of the request and put them in the request
 *
 * @param scep
 * @param req
 * @return
 */
int scep_get_req_extensions(struct scep *scep, X509_REQ *req)
{
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj = NULL;
    int count = 0;
    int ret = 0;
    int i;
    int nid = 0;
    ASN1_OCTET_STRING * ASN_val = NULL;
    char *val = NULL;
    struct scep_extension *e = NULL;
    struct scep_extension *p = NULL;

    return (0);
    //TODO faire la lecture des extensions contenues dans la CSR
    exts = X509_REQ_get_extensions(req);
    if (!exts) {
        return 0;
    }

    count = sk_X509_EXTENSION_num(exts);
    for (i = 0, ret = 0; i < count; ++i) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        nid = OBJ_obj2nid(obj);
        ASN_val = X509_EXTENSION_get_data(ext);
        if (ASN_val != NULL)
        {
        	val = ASN_val->data;
        }
        if (val == NULL)
        {
        	val = "\0";
        }
//        if (OBJ_obj2nid(obj) != NID_subject_alt_name) {
//            continue;
//        }

//        if (X509_add_ext(subject, ext, -1) != 1) {
//            ret = -1;
//            break;
//        }
        LOGD("nid : %d | val=%s",nid,val);
        e = (struct scep_extension *)malloc(sizeof(*e));
		if (!e) {
			return -1;
		}

		memset(e, 0, sizeof(*e));
		e->value = val;
		e->nid = nid;

		if (!(p = scep->extensions)) {
			scep->extensions = e;
			return -1;
		}

		while (p->next) {
			p = p->next;
		}

		p->next = e;
    }

    for (i = 0, ret = 0; i < count; ++i) {
        X509_EXTENSION_free(sk_X509_EXTENSION_value(exts, i));
    }

    sk_X509_EXTENSION_free(exts);
    return ret;
}
/**
 * @fn ASN1_TYPE scep_get_attribute*(struct stack_st_X509_ATTRIBUTE*, int, int)
 * @brief
 *
 * @param attributes
 * @param nid
 * @param expected_type
 * @return
 */
static ASN1_TYPE *scep_get_attribute(
        STACK_OF(X509_ATTRIBUTE) *attributes,
        int nid, int expected_type)
{
    X509_ATTRIBUTE *a;
    ASN1_TYPE *type;
    int count;
    int loc;

    loc = X509at_get_attr_by_NID(attributes, nid, -1);
    if (loc < 0) {
        return NULL;
    }

    a = X509at_get_attr(attributes, loc);
    if (!a) {
        return NULL;
    }

    count = X509_ATTRIBUTE_count(a);
    if (count <= 0) {
        return NULL;
    }

    type = X509_ATTRIBUTE_get0_type(a, 0);
    if (!type) {
        return NULL;
    }

    if (ASN1_TYPE_get(type) != expected_type) {
        return NULL;
    }

    return type;
}

/**
 * @fn ASN1_PRINTABLESTRING scep_printable_string*(const char*)
 * @brief
 *
 * @param str
 * @return
 */
static ASN1_PRINTABLESTRING *scep_printable_string(const char *str)
{
    ASN1_PRINTABLESTRING *copy;

    copy = ASN1_PRINTABLESTRING_new();
    if (!copy) {
        return NULL;
    }

    if (ASN1_STRING_set(copy, str, -1) != 1) {
        ASN1_PRINTABLESTRING_free(copy);
        return NULL;
    }

    return copy;
}

/**
 * @fn int scep_add_printable_string(PKCS7_SIGNER_INFO*, int, ASN1_PRINTABLESTRING*)
 * @brief
 *
 * @param si
 * @param nid
 * @param str
 * @return
 */
static int scep_add_printable_string(
        PKCS7_SIGNER_INFO *si, int nid, ASN1_PRINTABLESTRING *str)
{
    ASN1_PRINTABLESTRING *copy;

    copy = ASN1_STRING_dup(str);
    if (!copy) {
        return -1;
    }

    if (PKCS7_add_signed_attribute(
            si, nid, V_ASN1_PRINTABLESTRING, copy) != 1) {

        ASN1_PRINTABLESTRING_free(copy);
        return -1;
    }

    return 0;
}

/**
 * @fn int scep_add_octet_string(PKCS7_SIGNER_INFO*, int, ASN1_OCTET_STRING*)
 * @brief
 *
 * @param si
 * @param nid
 * @param str
 * @return
 */
static int scep_add_octet_string(
        PKCS7_SIGNER_INFO *si, int nid, ASN1_OCTET_STRING *str)
{
    ASN1_PRINTABLESTRING *copy;

    copy = ASN1_STRING_dup(str);
    if (!copy) {
        return -1;
    }

    if (PKCS7_add_signed_attribute(
            si, nid, V_ASN1_OCTET_STRING, copy) != 1) {

        ASN1_PRINTABLESTRING_free(copy);
        return -1;
    }

    return 0;
}

/**
 * @fn ASN1_PRINTABLESTRING scep_get_printable_string*(struct stack_st_X509_ATTRIBUTE*, int)
 * @brief
 *
 * @param attributes
 * @param nid
 * @return
 */
static ASN1_PRINTABLESTRING *scep_get_printable_string(
        STACK_OF(X509_ATTRIBUTE) *attributes,
        int nid)
{
    ASN1_TYPE *type;

    type = scep_get_attribute(attributes, nid, V_ASN1_PRINTABLESTRING);
    if (!type) {
        return NULL;
    }

    return type->value.printablestring;
}

/**
 * @fn ASN1_PRINTABLESTRING scep_get_req_printable_string*(X509_REQ*, int)
 * @brief
 *
 * @param req
 * @param nid
 * @return
 */
static ASN1_PRINTABLESTRING *scep_get_req_printable_string(
        X509_REQ *req,
        int nid)
{
    ASN1_TYPE *type;

    //type = scep_get_req_attribute(req, nid, V_ASN1_PRINTABLESTRING);
    type = scep_get_req_attribute(req, nid,V_ASN1_UTF8STRING);
    if (!type) {
        return NULL;
    }

    //return type->value.printablestring;
    return type->value.utf8string;
}

/**
 * @fn ASN1_OCTET_STRING scep_get_octet_string*(struct stack_st_X509_ATTRIBUTE*, int)
 * @brief
 *
 * @param attributes
 * @param nid
 * @return
 */
static ASN1_OCTET_STRING *scep_get_octet_string(
        STACK_OF(X509_ATTRIBUTE) *attributes,
        int nid)
{
    ASN1_TYPE *type;

    type = scep_get_attribute(attributes, nid, V_ASN1_OCTET_STRING);
    if (!type) {
        return NULL;
    }

    return type->value.octet_string;
}

/**
 * @fn ASN1_OCTET_STRING scep_nonce*(void)
 * @brief
 *
 * @return
 */
static ASN1_OCTET_STRING *scep_nonce(void)
{
    ASN1_OCTET_STRING *s;
    unsigned char n[16];

    if (RAND_bytes(n, sizeof(n)) != 1) {
        return NULL;
    }

    s = ASN1_OCTET_STRING_new();
    if (!s) {
        return NULL;
    }

    if (ASN1_OCTET_STRING_set(s, n, sizeof(n)) != 1) {
        ASN1_OCTET_STRING_free(s);
        return NULL;
    }

    return s;
}

/**
 * @fn void scep_pkiMessage_attributes_cleanup(struct scep_pkiMessage_attributes*)
 * @brief
 *
 * @param a
 */
static void scep_pkiMessage_attributes_cleanup(
        struct scep_pkiMessage_attributes *a)
{
    if (a->transactionID) {
        ASN1_PRINTABLESTRING_free(a->transactionID);
        a->transactionID = NULL;
    }

    if (a->messageType) {
        ASN1_PRINTABLESTRING_free(a->messageType);
        a->messageType = NULL;
    }

    if (a->pkiStatus) {
        ASN1_PRINTABLESTRING_free(a->pkiStatus);
        a->pkiStatus = NULL;
    }

    if (a->failInfo) {
        ASN1_PRINTABLESTRING_free(a->failInfo);
        a->failInfo = NULL;
    }

    if (a->senderNonce) {
        ASN1_OCTET_STRING_free(a->senderNonce);
        a->senderNonce = NULL;
    }

    if (a->recipientNonce) {
        ASN1_OCTET_STRING_free(a->recipientNonce);
        a->recipientNonce = NULL;
    }
}

/**
 * @fn int scep_pkiMessage_get_attributes(struct scep*, struct scep_pkiMessage_attributes*, struct stack_st_X509_ATTRIBUTE*)
 * @brief
 *
 * @param scep
 * @param a
 * @param auth_attr
 * @return
 */
static int scep_pkiMessage_get_attributes(
        struct scep *scep,
        struct scep_pkiMessage_attributes *a,
        STACK_OF(X509_ATTRIBUTE) *auth_attr)
{
    a->transactionID = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_transactionID);

    a->messageType = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_messageType);

    a->pkiStatus = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_pkiStatus);

    a->failInfo = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_failInfo);

    a->senderNonce = scep_get_octet_string(auth_attr,
            scep->NID_SCEP_senderNonce);

    a->recipientNonce = scep_get_octet_string(auth_attr,
            scep->NID_SCEP_recipientNonce);

    return 0;
}

/**
 * @fn int scep_pkiMessage_add_attributes(struct scep*, PKCS7_SIGNER_INFO*, struct scep_pkiMessage_attributes*)
 * @brief
 *
 * @param scep
 * @param si
 * @param a
 * @return
 */
static int scep_pkiMessage_add_attributes(
        struct scep *scep, PKCS7_SIGNER_INFO *si,
        struct scep_pkiMessage_attributes *a)
{
    if (a->transactionID) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_transactionID, a->transactionID)) {
            return -1;
        }
    }

    if (a->messageType) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_messageType, a->messageType)) {
            return -1;
        }
    }

    if (a->pkiStatus) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_pkiStatus, a->pkiStatus)) {
            return -1;
        }
    }

    if (a->failInfo) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_failInfo, a->failInfo)) {
            return -1;
        }
    }

    if (a->senderNonce) {
        if (scep_add_octet_string(si,
            scep->NID_SCEP_senderNonce, a->senderNonce)) {
            return -1;
        }
    }

    if (a->recipientNonce) {
        if (scep_add_octet_string(si,
            scep->NID_SCEP_recipientNonce, a->recipientNonce)) {
            return -1;
        }
    }

    return 0;
}

/**
 * @fn int scep_pkiMessage_set_type(struct scep_pkiMessage*)
 * @brief
 *
 * @param m
 * @return
 */
static int scep_pkiMessage_set_type(struct scep_pkiMessage *m)
{
    const ASN1_PRINTABLESTRING *mt;

    mt = m->auth_attr.messageType;
    if (!mt) {
        return -1;
    }

    if (mt->length == 1) {
        if (memcmp(mt->data, "3", 1) == 0) {
            m->messageType = messageType_CertRep;
            return 0;
        }
    } else if (mt->length == 2) {
        if (memcmp(mt->data, "17", 2) == 0) {
            m->messageType = messageType_RenewalReq;
            return 0;
        } else if (memcmp(mt->data, "19", 2) == 0) {
            m->messageType = messageType_PKCSReq;
            return 0;
        } else if (memcmp(mt->data, "20", 2) == 0) {
            m->messageType = messageType_CertPoll;
            return 0;
        } else if (memcmp(mt->data, "21", 2) == 0) {
            m->messageType = messageType_GetCert;
            return 0;
        } else if (memcmp(mt->data, "22", 2) == 0) {
            m->messageType = messageType_GetCRL;
            return 0;
        }
    }

    return -1;
}

/**
 * @fn struct scep_pkiMessage scep_pkiMessage_new*(struct scep*, BIO*)
 * @brief
 *
 * @param scep
 * @param bp
 * @return
 */
struct scep_pkiMessage *scep_pkiMessage_new(struct scep *scep, BIO *bp)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signers;
    STACK_OF(X509_ATTRIBUTE) *auth_attr;
    struct scep_pkiMessage *m;
    PKCS7_SIGNER_INFO *signer;
    EVP_PKEY *signkey;
    char buffer[1024];
    int signbits;
    PKCS7 *pkcs7;
    X509 *cert;
    BIO *rbp;
    BIO *wbp;
    int size;
    int ret;

    pkcs7 = d2i_PKCS7_bio(bp, NULL);
    if (!pkcs7) {
        LOGD("scep: pkiMessage: invalid PKCS7 structure");
        return NULL;
    }

    if (!PKCS7_type_is_signed(pkcs7) || PKCS7_is_detached(pkcs7)) {
        LOGD("scep: pkiMessage: invalid PKCS7 structure type");
        PKCS7_free(pkcs7);
        return NULL;
    }

    signers = PKCS7_get_signer_info(pkcs7); /* Internal */
    if (sk_PKCS7_SIGNER_INFO_num(signers) <= 0) {
        LOGD("scep: pkiMessage: unsigned PKCS7 structure");
        PKCS7_free(pkcs7);
        return NULL;
    }

    rbp = PKCS7_dataInit(pkcs7, NULL);
    if (!rbp) {
        LOGD("scep: pkiMessage: no encapsulated message");
        PKCS7_free(pkcs7);
        return NULL;
    }

    wbp = BIO_new(BIO_s_mem());
    if (!wbp) {
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    /* Read the content once so the hash is calculated, but save the content to
     * another BIO so we can access later */

    for (;;) {
        size = BIO_read(rbp, buffer, sizeof(buffer));
        if (size < 0) {
            BIO_free_all(wbp);
            BIO_free_all(rbp);
            PKCS7_free(pkcs7);
            return NULL;
        } else if (size == 0) {
            break;
        }

        ret = BIO_write(wbp, buffer, size);
        if (ret != size) {
            BIO_free_all(wbp);
            BIO_free_all(rbp);
            PKCS7_free(pkcs7);
            return NULL;
        }
    }

    /* We only use the first signer even if there're multiple */
    signer = sk_PKCS7_SIGNER_INFO_value(signers, 0); /* Internal */
    if (scep_PKCS7_SIGNER_INFO_check_algo(signer)) {
        LOGD("scep: pkiMessage: weak encapsulated message signing algorithm");
        BIO_free_all(wbp);
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    cert = PKCS7_cert_from_signer_info(pkcs7, signer); /* Internal */
    if (!cert || scep_check_signature_algo(X509_get_signature_nid(cert))) {
        LOGD("scep: pkiMessage: weak signer certificate signing algorithm");
        BIO_free_all(wbp);
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_signatureVerify(rbp, pkcs7, signer, cert) != 1) {
        LOGD("scep: pkiMessage: invalid signature of signed message");
        BIO_free_all(wbp);
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    BIO_free_all(rbp);

    signkey = X509_get0_pubkey(cert);
    if (!signkey) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    signbits = scep_get_rsa_key_bits(signkey);
    if (signbits < 0) {
        LOGD("scep: pkiMessage: unacceptable signing key");
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    } else if (signbits < SCEP_RSA_MIN_BITS) {
        LOGD("scep: pkiMessage: weak signing key length: %d", signbits);
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    /* Fail uncompliant client exposing secret information */
    if (PKCS7_get_signed_attribute(signer, NID_pkcs9_challengePassword)) {
        if (!scep->configure.tolerate_exposed_challenge_password) {
            LOGD("scep: pkiMessage: exposed challenge password");
            BIO_free_all(wbp);
            PKCS7_free(pkcs7);
            return NULL;
        }

        LOGD("scep: pkiMessage: exposed challenge password (tolerated)");
    }

    if (scep_decrypt(scep, &wbp)) {
        LOGD("scep: pkiMessage: failed to decrypt encapsulated message");
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    auth_attr = PKCS7_get_signed_attributes(signer); /* Internal */

    m = (struct scep_pkiMessage *)malloc(sizeof(*m));
    if (!m) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    memset(m, 0, sizeof(*m));
    if (scep_pkiMessage_get_attributes(scep, &m->auth_attr, auth_attr)) {
        LOGD("scep: pkiMessage: unable to get encapsulated attributes");
        free(m);
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (scep_pkiMessage_set_type(m)) {
        LOGD("scep: pkiMessage: unsupported pkiMessage type");
        free(m);
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    LOGD("scep: pkiMessage: successfully parsed type [%d]", m->messageType);
    m->payload = wbp;
    m->signer = cert;
    m->pkcs7 = pkcs7;
    return m;
}

/**
 * @fn void scep_pkiMessage_free(struct scep_pkiMessage*)
 * @brief
 *
 * @param m
 */
void scep_pkiMessage_free(struct scep_pkiMessage *m)
{
    if (!m) {
        return;
    }

    if (m->payload) {
        BIO_free_all(m->payload);
    }

    if (m->pkcs7) {
        PKCS7_free(m->pkcs7);
    }

    free(m);
}

/**
 * @fn int scep_unhex_one(unsigned char)
 * @brief
 *
 * @param c
 * @return
 */
static int scep_unhex_one(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}

/**
 * @fn int scep_unhex(unsigned char*, unsigned int, unsigned char*)
 * @brief
 *
 * @param s
 * @param len
 * @param o
 * @return
 */
static int scep_unhex(unsigned char *s, unsigned int len, unsigned char *o)
{
    unsigned int i;
    int h;
    int l;

    for (i = 0; i < len; i += 2) {
        h = scep_unhex_one(s[i + 0]);
        l = scep_unhex_one(s[i + 1]);
        if (h < 0 || l < 0) {
            return -1;
        }

        o[i / 2] = (unsigned char)(h * 16 + l);
    }

    return 0;
}

#ifndef NDEBUG
/**
 * @fn void scep_hex(const void*, size_t, void*)
 * @brief
 *
 * @param buffer
 * @param length
 * @param output
 */
static void scep_hex(const void *buffer, size_t length, void *output)
{
    static const char H[] = "0123456789ABCDEF";
    const unsigned char *in;
    char *out;
    size_t i;

    in = (const unsigned char *)buffer;
    out = (char *)output;

    for (i = 0; i < length; ++i) {
        out[i * 2 + 0] = H[in[i] / 16];
        out[i * 2 + 1] = H[in[i] % 16];
    }
}
#endif

/**
 * @fn int scep_check_transactionID(struct scep*, X509_REQ*, ASN1_PRINTABLESTRING*)
 * @brief
 *
 * @param scep
 * @param csr
 * @param transactionID
 * @return
 */
static int scep_check_transactionID(
        struct scep *scep,
        X509_REQ *csr,
        ASN1_PRINTABLESTRING *transactionID)
{
    unsigned char received[EVP_MAX_MD_SIZE];
    unsigned char hash1[EVP_MAX_MD_SIZE];
    unsigned char hash2[EVP_MAX_MD_SIZE];
    const EVP_MD *type;
    unsigned char *p;
    unsigned int len;
    EVP_PKEY *pkey;
    int ret;

#ifndef NDEBUG
    char hex[EVP_MAX_MD_SIZE * 2];
#endif

    if (transactionID->length <= 0) {
        return -1;
    }

    if (scep->configure.no_validate_transaction_id) {
        return 0;
    }

    if (transactionID->length % 2) {
        return -1;
    }

    len = transactionID->length / 2;
    if (scep_unhex(transactionID->data, transactionID->length, received)) {
        return -1;
    }

#ifndef NDEBUG
    scep_hex(received, len, hex);
    LOGD("scep: received transactionID: %.*s", (int)(len * 2), hex);
#endif

    pkey = X509_REQ_get0_pubkey(csr); /* Internal */
    if (!pkey) {
        return -1;
    }

    switch (len) {
    case MD5_DIGEST_LENGTH:    type = EVP_md5();    break;
    case SHA_DIGEST_LENGTH:    type = EVP_sha1();   break;
    case SHA256_DIGEST_LENGTH: type = EVP_sha256(); break;
    case SHA512_DIGEST_LENGTH: type = EVP_sha512(); break;
    default : return -1;
    }

    p = NULL;
    ret = i2d_PublicKey(pkey, &p);
    if (ret < 0) {
        return -1;
    }

    if (EVP_Digest(p, (size_t)ret, hash1, NULL, type, NULL) != 1) {
        OPENSSL_free(p);
        return -1;
    }

    OPENSSL_free(p);
    p = NULL;

    ret = i2d_PUBKEY(pkey, &p);
    if (ret < 0) {
        return -1;
    }

    if (EVP_Digest(p, (size_t)ret, hash2, NULL, type, NULL) != 1) {
        OPENSSL_free(p);
        return -1;
    }

    OPENSSL_free(p);
    p = NULL;

#ifndef NDEBUG
    scep_hex(hash1, len, hex);
    LOGD("scep: expected transactionID: %.*s", (int)(len * 2), hex);
    scep_hex(hash2, len, hex);
    LOGD("scep: expected transactionID: %.*s", (int)(len * 2), hex);
#endif

    if (memcmp(received, hash1, len) && memcmp(received, hash2, len)) {
        return -1;
    }

    return 0;
}

/**
 * @fn int scep_verify(X509_STORE*, X509*)
 * @brief
 *
 * @param store
 * @param subject
 * @return
 */
static int scep_verify(X509_STORE *store, X509 *subject)
{
    X509_STORE_CTX *ctx;

    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (X509_STORE_CTX_init(ctx, store, subject, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        return -1;
    }

    if (X509_verify_cert(ctx) != 1) {
        X509_STORE_CTX_free(ctx);
        return 0;
    }

    X509_STORE_CTX_free(ctx);
    return 1;
}

/**
 * @fn struct scep_PKCSReq scep_PKCSReq_new*(struct scep*, struct scep_pkiMessage*)
 * @brief
 *
 * @param scep
 * @param m
 * @return
 */
struct scep_PKCSReq *scep_PKCSReq_new(
        struct scep *scep,
        struct scep_pkiMessage *m)
{
    struct scep_pkiMessage_attributes *a;
    ASN1_PRINTABLESTRING *cp;
    struct scep_PKCSReq *req;
    X509_NAME *subject;
    EVP_PKEY *csrkey;
    EVP_PKEY *pkey;
    BUF_MEM *bptr;
    X509_REQ *csr;
    int csrbits;
    BIO *robp;
    int valid;

    if (!scep || !scep->cert || !m) {
        return NULL;
    }

    /* TODO: a different trust store can be used */
    valid = scep_verify(scep->store, m->signer);
    if (valid < 0) {
        return NULL;
    }

    a = &m->auth_attr;
    if (!a->transactionID || !a->messageType || !a->senderNonce) {
        LOGD("scep: PKCSReq: missing contain mandatory attributes");
        return NULL;
    } else if (a->senderNonce->length != 16) {
        LOGD("scep: PKCSReq: senderNonce length is non-standard: %d",
                a->senderNonce->length);
        /* But continue to proceed */
    }

    BIO_get_mem_ptr(m->payload, &bptr);
    robp = BIO_new_mem_buf(bptr->data, bptr->length);
    if (!robp) {
        return NULL;
    }

    csr = d2i_X509_REQ_bio(robp, NULL);
    if (!csr) {
        LOGD("scep: PKCSReq: missing valid CSR");
        BIO_free_all(robp);
        return NULL;
    }

    BIO_free_all(robp);

    if (!(pkey = X509_REQ_get0_pubkey(csr))                         ||
        (csrbits = scep_get_rsa_key_bits(pkey)) < SCEP_RSA_MIN_BITS ||
        !(csrkey = X509_REQ_get0_pubkey(csr))                       ||
        !(subject = X509_REQ_get_subject_name(csr))                 ||
        X509_NAME_get_index_by_NID(subject, NID_commonName, -1) < 0 ){

        LOGD("scep: PKCSReq: invalid CSR");
        X509_REQ_free(csr);
        return NULL;
    }

    if (X509_REQ_verify(csr, pkey) != 1) {
        LOGD("scep: PKCSReq: CSR is not self signed");
        X509_REQ_free(csr);
        return NULL;
    }

    /* Enrollment, well formed transactionID is expected */
    if (scep_check_transactionID(scep, csr, a->transactionID)) {
        LOGD("scep: PKCSReq: unacceptable transactionID");
        X509_REQ_free(csr);
        return NULL;
    }

    cp = scep_get_req_printable_string(csr, NID_pkcs9_challengePassword);
    req = (struct scep_PKCSReq *)malloc(sizeof(*req));
    if (!req) {
        X509_REQ_free(csr);
        return NULL;
    }

    LOGD("scep: PKCSReq: successfully parsed");
    memset(req, 0, sizeof(*req));
    req->signer_certificate_is_valid = valid;
    req->challengePassword = cp;
    req->csrkey = csrkey;
    req->csr = csr;
    req->m = m;
    return req;
}

/**
 * @fn void scep_PKCSReq_free(struct scep_PKCSReq*)
 * @brief
 *
 * @param req
 */
void scep_PKCSReq_free(struct scep_PKCSReq *req)
{
    if (!req) {
        return;
    }

    if (req->csr) {
        X509_REQ_free(req->csr);
    }

    free(req);
}

/**
 * @fn const X509_REQ scep_PKCSReq_get_csr*(const struct scep_PKCSReq*)
 * @brief
 *
 * @param req
 * @return
 */
const X509_REQ *scep_PKCSReq_get_csr(const struct scep_PKCSReq *req)
{
    if (!req) {
        return NULL;
    }

    return req->csr;
}

/**
 * @fn int scep_add_ext(X509*, X509*, int, const char*)
 * @brief Add a new extension in the subject certificate
 *
 * @param issuer : issuer certificate
 * @param subject : subject certificate (output)
 * @param nid : nid to add
 * @param value : value to add
 * @return 0 if OK
 */
static int scep_add_ext(
        X509 *issuer,
        X509 *subject,
        int nid,
        const char *value)
{
    X509_EXTENSION *ext;
    X509V3_CTX ctx;

    // This sets the 'context' of the extensions. No database
    X509V3_set_ctx_nodb(&ctx);

    //Issuer and subject certs, no request, no CRLs, flag ADD DEFAULT
    X509V3_set_ctx(&ctx, issuer, subject, NULL, NULL, X509V3_ADD_DEFAULT);

    LOGD("Add new extention with NID=%d and value=%s",nid,value);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ext) {
    	LOGE("Impossible to configure a new extension %s",ERR_reason_error_string(ERR_peek_last_error()));
        return -1;
    }

    if (X509_add_ext(subject, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        LOGE("Impossible to add the new extension");
        return -1;
    }

    X509_EXTENSION_free(ext);
    return 0;
}

/**
 * @fn int scep_add_ext_crl_distribution_point(X509*, X509*, const char*)
 * @brief Add a crl distribution point
 *
 * @param issuer : not used
 * @param subject : certificate where to add the crl distribution point
 * @param value char* : URI of the crl distribution point write http://toto.com/crls.pem
 * @return int : -1 -> error; 0 -> no crl distribution point added; 1 -> a crl point distribution added
 */
int scep_add_ext_crl_distribution_point(X509 *issuer,
        X509 *subject,
        const char *value)
{
	(void) issuer;

	char uri[1024] = {0};

	//char *uri = "URI:http://toto.com/crls.pem\0";
	GENERAL_NAMES *gNames = NULL;
	GENERAL_NAME *gNameURI = NULL;
	ASN1_IA5STRING *ia5 = NULL;
	DIST_POINT *distPoint = NULL;
	STACK_OF(DIST_POINT) *distPoints = NULL;
	DIST_POINT_NAME *dpName = NULL;

	X509_EXTENSION *extension = NULL;

	LOGD("Enter in scep_add_ext_crl_distribution_point");

	strncpy(uri, value, sizeof(uri)-1);
	if ((strlen(value) > sizeof(uri)-5)
		|| (strlen(value) <= 8))
	{
		LOGD("No crl distribution point so leave the function");
		return(0);
	}
	snprintf(uri, sizeof(uri)-1,"URI:%s",value);

	LOGD("Add new extention with NID=%d and value=%s", NID_crl_distribution_points, uri);
	LOGD("Create distPoints");
	distPoints = sk_DIST_POINT_new_null();
	if (!distPoints)
	{
		LOGE("Impossible to create a new distPoints %s",ERR_reason_error_string(ERR_peek_last_error()));
		return -1;
	}

	LOGD("Create distPoint");
	distPoint = DIST_POINT_new();
	if (!distPoint)
	{
		LOGE("Impossible to create a new distPoint %s",ERR_reason_error_string(ERR_peek_last_error()));
		return -1;
	}

	LOGD("Create dpName");
	dpName = DIST_POINT_NAME_new();
	if (!dpName)
	{
		LOGE("Impossible to create a new dpName %s",ERR_reason_error_string(ERR_peek_last_error()));
		return -1;
	}

	LOGD("Create gNames");
	gNames = GENERAL_NAMES_new();
	if (!gNames)
	{
		LOGE("Impossible to create a new gNames %s",ERR_reason_error_string(ERR_peek_last_error()));
		return -1;
	}
	LOGD("Create gNameURI");
	gNameURI = GENERAL_NAME_new();
	if (!gNameURI)
	{
		LOGE("Impossible to create a new gNameURI %s",ERR_reason_error_string(ERR_peek_last_error()));
		return -1;
	}

	LOGD("Create ia5");
	ia5 = ASN1_IA5STRING_new();
	if (!ia5)
	{
		LOGE("Impossible to create a new ia5 %s",ERR_reason_error_string(ERR_peek_last_error()));
		return -1;
	}

	LOGD("ASN1_STRING_set");
	if (!ASN1_STRING_set(ia5, uri, strlen(uri)))
	{
		LOGE("Impossible to set ia5 %s",ERR_reason_error_string(ERR_peek_last_error()));
		return -1;
	}

	LOGD("GENERAL_NAME_set0_value");
	GENERAL_NAME_set0_value(gNameURI, GEN_URI, ia5);

	LOGD("push gNameURI to gNames");
	sk_GENERAL_NAME_push(gNames, gNameURI);

	LOGD("Init name in the distpoint");
	dpName->name.fullname = gNames;
	distPoint->distpoint = dpName;
	distPoint->distpoint->type = 0;

	LOGD("push distPoint to distPoints");
	sk_DIST_POINT_push (distPoints, distPoint);

	LOGD("Create extension");
	extension = X509V3_EXT_i2d (NID_crl_distribution_points, 0, distPoints);
	// Add the new extension
	if (X509_add_ext(subject, extension, -1) != 1) {
		X509_EXTENSION_free(extension);
		LOGE("Impossible to add the new extension");
		return -1;
	}

	X509_EXTENSION_free (extension);
	LOGD("Quit scep_add_ext_crl_distribution_point");
	return 1;
}

/**
 * @fn int scep_set_serial(X509*)
 * @brief
 *
 * @param subject
 * @return
 */
static int scep_set_serial(X509 *subject)
{
    ASN1_INTEGER *serial;
    BIGNUM *bn;

    bn = BN_new();
    if (!bn) {
        return -1;
    }

    if (BN_pseudo_rand(bn, 159, 0, 0) != 1) {
        BN_free(bn);
        return -1;
    }

    serial = BN_to_ASN1_INTEGER(bn, NULL);
    if (!serial) {
        BN_free(bn);
        return -1;
    }

    BN_free(bn);
    if (X509_set_serialNumber(subject, serial) != 1) {
        ASN1_INTEGER_free(serial);
        return -1;
    }

    ASN1_INTEGER_free(serial);
    return 0;
}

/**
 * @fn int scep_set_not_before_not_after(time_t, X509*, long, long)
 * @brief
 *
 * @param now
 * @param subject
 * @param notBeforeDays
 * @param notAfterDays
 * @return
 */
static int scep_set_not_before_not_after(
        time_t now,
        X509 *subject,
        long notBeforeDays,
        long notAfterDays)
{
    ASN1_TIME *t;

    t = ASN1_TIME_new();
    if (!t) {
        return -1;
    }

    if (!X509_time_adj_ex(t, notBeforeDays, 0, &now)) {
        ASN1_TIME_free(t);
        return -1;
    }

    if (X509_set1_notBefore(subject, t) != 1) {
        ASN1_TIME_free(t);
        return -1;
    }

    if (!X509_time_adj_ex(t, notAfterDays, 0, &now)) {
        ASN1_TIME_free(t);
        return -1;
    }

    if (X509_set1_notAfter(subject, t) != 1) {
        ASN1_TIME_free(t);
        return -1;
    }

    ASN1_TIME_free(t);
    return 0;
}

/**
 * @fn int scep_add_default_extensions(X509*, X509*)
 * @brief Add the default extension to the subject certificate
 *
 * @param issuer X509* : issuer certificate
 * @param subject X509* : subject certificate
 * @return 0 if OK
 */
static int scep_add_default_extensions(X509 *issuer, X509 *subject)
{
	LOGD("Add default extensions");
    if (scep_add_ext(issuer, subject,
            NID_basic_constraints, "critical,CA:FALSE")
        || scep_add_ext(issuer, subject,
            NID_key_usage, "critical,digitalSignature,keyEncipherment")
        || scep_add_ext(issuer, subject,
            NID_ext_key_usage, "clientAuth")
//		|| scep_add_ext(issuer, subject,
//			NID_certificate_policies, "1.2.3.4")
        || scep_add_ext(issuer, subject,
            NID_subject_key_identifier, "hash")
        || scep_add_ext(issuer, subject,
            NID_authority_key_identifier, "keyid:always")
//		|| scep_add_ext(issuer, subject,
//			NID_crl_distribution_points, "http://Your_CRL_Distrubution_Point.com/crls.pem")
		)
    {
    	LOGE("Impossible to add default extensions");
        return -1;
    }

    return 0;
}

/**
 * @fn int scep_sign(time_t, struct scep*, X509*, long)
 * @brief
 *
 * @param now
 * @param scep
 * @param subject
 * @param days
 * @return
 */
static int scep_sign(
        time_t now,
        struct scep *scep,
        X509 *subject,
        long days)
{
    struct scep_extension *p;

    if (X509_set_version(subject, 2) != 1) { /* X509 V3 */
        return -1;
    }

    if (scep_set_serial(subject)) {
        return -1;
    }

    if (X509_set_issuer_name(subject,
            X509_get_subject_name(scep->signcert)) != 1) {

        return -1;
    }

    if (scep_set_not_before_not_after(now, subject, 0, days)) {
        return -1;
    }


    if ((!scep->extensions)
    	&& (X509_get_ext_count(subject) <= 0)
		)
	{ /* Not good, we should have something... */
        if (scep_add_default_extensions(scep->signcert, subject)) {
            return -1;
        }
    } else
    {
		for (p = scep->extensions; p; p = p->next) {
			if (scep_add_ext(scep->signcert, subject, p->nid, p->value)) {
				return -1;
			}
		}
    }

    if (X509_sign(subject, scep->signpkey, scep->md) == 0) {
        return -1;
    }

    return 0;
}

/**
 * @fn int scep_pkiMessage_encrypt(BIO*, BIO*, X509*)
 * @brief
 *
 * @param input
 * @param output
 * @param recipient
 * @return
 */
static int scep_pkiMessage_encrypt(BIO *input, BIO *output, X509 *recipient)
{
    STACK_OF(X509) *recipients;
    PKCS7 *pkcs7;

    recipients = sk_X509_new_null();
    if (!recipients) {
        return -1;
    }

    if (sk_X509_push(recipients, recipient) != 1) {
        sk_X509_free(recipients);
        return -1;
    }

    pkcs7 = PKCS7_encrypt(recipients, input, EVP_aes_256_cbc(), PKCS7_BINARY);
    if (!pkcs7) {
        sk_X509_free(recipients);
        return -1;
    }

    sk_X509_free(recipients);

    if (i2d_PKCS7_bio(output, pkcs7) != 1) {
        PKCS7_free(pkcs7);
        return -1;
    }

    PKCS7_free(pkcs7);
    return 0;
}

/**
 * @fn PKCS7 scep_pkiMessage_seal*(struct scep*, BIO*, X509*, X509*, EVP_PKEY*, struct scep_pkiMessage_attributes*)
 * @brief return a pkcs7 that contain
 *
 * @param scep
 * @param payload
 * @param recipient
 * @param signer
 * @param signkey
 * @param a
 * @return
 */
static PKCS7 *scep_pkiMessage_seal(
        struct scep *scep,
        BIO *payload,
        X509 *recipient,	// correspond à
        X509 *signer,
        EVP_PKEY *signkey,
        struct scep_pkiMessage_attributes *a)
{
    PKCS7_SIGNER_INFO *si = NULL;
    BIO *content = NULL;
    PKCS7 *pkcs7 = NULL;

    pkcs7 = PKCS7_new();
    if (!pkcs7) {
        return NULL;
    }

    if (PKCS7_set_type(pkcs7, NID_pkcs7_signed) != 1) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_add_certificate(pkcs7, signer) != 1) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    si = PKCS7_add_signature(pkcs7, signer, signkey, EVP_sha1());
    if (!si) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (scep_pkiMessage_add_attributes(scep, si, a)) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
            V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data)) != 1) {

        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_content_new(pkcs7, NID_pkcs7_data) != 1) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    content = PKCS7_dataInit(pkcs7, NULL);
    if (!content) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (payload) {
        if (scep_pkiMessage_encrypt(payload, content, recipient)) {
            BIO_free_all(content);
            PKCS7_free(pkcs7);
            return NULL;
        }
    }

    if (PKCS7_dataFinal(pkcs7, content) != 1) {
        BIO_free_all(content);
        PKCS7_free(pkcs7);
        return NULL;
    }

    BIO_free_all(content);
    return pkcs7;
}

/**
 * @fn int scep_degenerate_chain(BIO*, struct stack_st_X509*)
 * @brief
 *
 * @param bp
 * @param certs
 * @return
 */
static int scep_degenerate_chain(BIO *bp, STACK_OF(X509) *certs)
{
    PKCS7_SIGNED *p7s;
    PKCS7 *pkcs7;

    pkcs7 = PKCS7_new();
    if (!pkcs7) {
        return -1;
    }

    if (PKCS7_set_type(pkcs7, NID_pkcs7_signed) != 1) {
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s = pkcs7->d.sign;
    if (ASN1_INTEGER_set(p7s->version, 1) != 1) {
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);
    if (!p7s->contents->type) {
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s->cert = certs;
    if (i2d_PKCS7_bio(bp, pkcs7) != 1) {
        p7s->cert = NULL;
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s->cert = NULL;
    PKCS7_free(pkcs7);
    return 0;
}

/**
 * @fn int scep_degenerate_va(BIO*, va_list)
 * @brief
 *
 * @param bp
 * @param ap
 * @return
 */
static int scep_degenerate_va(BIO *bp, va_list ap)
{
    STACK_OF(X509) *chain;
    X509 *cert;
    int ret;

    chain = sk_X509_new_null();
    if (!chain) {
        return -1;
    }

    while ((cert = va_arg(ap, X509 *))) {
        if (sk_X509_push(chain, cert) == 0) {
            sk_X509_free(chain);
            return -1;
        }
    }

    ret = scep_degenerate_chain(bp, chain);
    sk_X509_free(chain);
    return ret;
}

/**
 * @fn int scep_degenerate(BIO*, ...)
 * @brief
 *
 * @param bp
 * @return
 */
static int scep_degenerate(BIO *bp, ...)
{
    va_list ap;
    int ret;

    va_start(ap, bp);
    ret = scep_degenerate_va(bp, ap);
    va_end(ap);

    return ret;
}

/**
 * @fn int scep_CertRep_set_all_extensions(X509_REQ*, X509*)
 * @brief this function copy all extensions from the request to the subject certificate
 *
 * @param req
 * @param subject
 * @return
 */
static int scep_CertRep_set_all_extensions(X509_REQ *req, X509 *subject, int delCRLdistributionpoint)
{
	STACK_OF(X509_EXTENSION) *exts;
    X509_EXTENSION *ext;
    ASN1_OBJECT *obj;
    int count;
    int ret;
    int i;

    exts = X509_REQ_get_extensions(req);
    if (!exts) {
        return 0;
    }

    count = sk_X509_EXTENSION_num(exts);
    for (i = 0, ret = 0; i < count; ++i) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
//        if (OBJ_obj2nid(obj) != NID_subject_alt_name) {
//            continue;
//        }
        if ((delCRLdistributionpoint == 1)
        	&& (OBJ_obj2nid(obj) == NID_crl_distribution_points))
        {
        	continue;
        }
        if (X509_add_ext(subject, ext, -1) != 1) {
            ret = -1;
            break;
        }
    }

    for (i = 0, ret = 0; i < count; ++i) {
        X509_EXTENSION_free(sk_X509_EXTENSION_value(exts, i));
    }

    sk_X509_EXTENSION_free(exts);
    return ret;
}

/**
 * @fn int scep_CertRep_set_SAN(X509_REQ*, X509*)
 * @brief
 *
 * @param req
 * @param subject
 * @return
 */
static int scep_CertRep_set_SAN(X509_REQ *req, X509 *subject)
{
    STACK_OF(X509_EXTENSION) *exts;
    X509_EXTENSION *ext;
    ASN1_OBJECT *obj;
    int count;
    int ret;
    int i;

    exts = X509_REQ_get_extensions(req);
    if (!exts) {
        return 0;
    }

    count = sk_X509_EXTENSION_num(exts);
    for (i = 0, ret = 0; i < count; ++i) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        if (OBJ_obj2nid(obj) != NID_subject_alt_name) {
            continue;
        }

        if (X509_add_ext(subject, ext, -1) != 1) {
            ret = -1;
            break;
        }
    }

    for (i = 0, ret = 0; i < count; ++i) {
        X509_EXTENSION_free(sk_X509_EXTENSION_value(exts, i));
    }

    sk_X509_EXTENSION_free(exts);
    return ret;
}

/**
 * @fn PKCS7 scep_CertRep_seal*(struct scep*, struct scep_PKCSReq*, const char*, const char*, X509*)
 * @brief Create and return a pkcs7 with the subject and is chain and all information needed in the pkcs7 container
 *
 * @param scep
 * @param req
 * @param pkiStatus
 * @param failInfo
 * @param subject
 * @return
 */
static PKCS7 *scep_CertRep_seal(
        struct scep *scep,
        struct scep_PKCSReq *req,
        const char *pkiStatus,
        const char *failInfo,
        X509 *subject)
{
    struct scep_pkiMessage_attributes auth_attr;
    PKCS7 *pkcs7;
    BIO *payload;

    payload = NULL;
    if (subject) {
        payload = BIO_new(BIO_s_mem());
        if (!payload) {
            return NULL;
        }
        if (scep->signchain == NULL)
        {
			LOGD("Add the subject in the payload");
			if (scep_degenerate(payload, subject, NULL)) {
				LOGE("Impossible to add certificate in the payload");
				BIO_free_all(payload);
				return NULL;
			}
        }
        else
        {
        	LOGD("Add the subject in the trust chain");
        	if (sk_X509_insert(scep->signchain, subject, 0) <= 0)
        	{
        		LOGE("Impossible to add certificate in the chain");
				BIO_free_all(payload);
				return NULL;
        	}
        	LOGD("Add the subject and his trust chain in the payload");
        	if (scep_degenerate_chain(payload, scep->signchain)) {
				LOGE("Impossible to add certificate and his trust chain in the payload");
				BIO_free_all(payload);
				return NULL;
			}
        }
    }

    memset(&auth_attr, 0, sizeof(auth_attr));
    auth_attr.transactionID = ASN1_STRING_dup(req->m->auth_attr.transactionID);
    auth_attr.messageType = scep_printable_string("3");
    auth_attr.pkiStatus = scep_printable_string(pkiStatus);
    auth_attr.senderNonce = scep_nonce();
    auth_attr.recipientNonce = ASN1_STRING_dup(req->m->auth_attr.senderNonce);

    if (failInfo) {
        auth_attr.failInfo = scep_printable_string(failInfo);
    }

    if (!auth_attr.transactionID          ||
        !auth_attr.messageType            ||
        !auth_attr.senderNonce            ||
        !auth_attr.recipientNonce         ||
        !auth_attr.pkiStatus              ||
        (failInfo && !auth_attr.failInfo) ){

        scep_pkiMessage_attributes_cleanup(&auth_attr);
        BIO_free_all(payload);
        return NULL;
    }

    pkcs7 = scep_pkiMessage_seal(
            scep,
            payload,
            req->m->signer,
            scep->cert,
            scep->pkey,
            &auth_attr);

    if (!pkcs7) {
        scep_pkiMessage_attributes_cleanup(&auth_attr);
        BIO_free_all(payload);
        return NULL;
    }

    scep_pkiMessage_attributes_cleanup(&auth_attr);
    BIO_free_all(payload);
    return pkcs7;
}

/**
 * @fn struct scep_CertRep scep_CertRep_new_with*(struct scep*, struct scep_PKCSReq*, X509*)
 * @brief create the pkcs7 that include the subject certificate and return scep_CertRep
 *
 * @param scep
 * @param req
 * @param subject
 * @return
 */
struct scep_CertRep *scep_CertRep_new_with(
        struct scep *scep,
        struct scep_PKCSReq *req,
        X509 *subject)
{
    struct scep_CertRep *rep;

    if (!scep || !scep->cert || !scep->pkey || !req || !subject) {
        return NULL;
    }

    rep = (struct scep_CertRep *)malloc(sizeof(*rep));
    if (!rep) {
        return NULL;
    }

    memset(rep, 0, sizeof(*rep));
    rep->cert = subject;
    rep->pkcs7 = scep_CertRep_seal(scep, req, "0", NULL, subject);
    if (!rep->pkcs7) {
        free(rep);
        return NULL;
    }

    return rep;
}

/**
 * @fn struct scep_CertRep scep_CertRep_new*(struct scep*, struct scep_PKCSReq*, time_t, long)
 * @brief	Create a new certificate with the csr information. sign it and return it to scep_PKCSReq
 *
 * @param scep
 * @param req
 * @param now
 * @param days
 * @return
 */
struct scep_CertRep *scep_CertRep_new(
        struct scep *scep,
        struct scep_PKCSReq *req,
        time_t now,
        long days)
{
    struct scep_CertRep *rep;
    X509_NAME *name;
    EVP_PKEY *pkey;
    X509 *subject;

    STACK_OF(X509_EXTENSION) *exts;
    X509_EXTENSION *ext;
    int ret = -1;

    LOGD("Enter scep_CertRep_new");
    if (!scep || !scep->signcert || !scep->signpkey || !req) {
    	LOGE("scep or signer certificate or private key don't exists");
        return NULL;
    }

    // Get the subject name from the CSR
    name = X509_REQ_get_subject_name(req->csr);
    if (!name) {
    	LOGE("No subject name in the CSR");
        return NULL;
    }

    // Get the public key from the CSR
    pkey = X509_REQ_get0_pubkey(req->csr);
    if (!pkey) {
    	LOGE("No public key in the CSR");
        return NULL;
    }

    // Create the new certificate will send to the client
    subject = X509_new();
    if (!subject) {
        return NULL;
    }

    // set subject name
    if ((X509_set_subject_name(subject, name) != 1)
    	|| (X509_set_pubkey(subject, pkey) != 1))
    {
    	LOGE("Impossible to set public key or subject name in the new certificate");
        X509_free(subject);
        return NULL;
    }

    // get the extensions in the CSR
    exts = X509_REQ_get_extensions(req->csr);


    if (exts != NULL)
    {
    	// Puts the extensions to the scep extension
//    	if (scep_get_req_extensions(scep, req->csr) != 0)
//    	{
//    		LOGE("Impossible to get CSR extension");
//    	}
//
//    	// set the SAN if wanted
//		if (scep->configure.set_subject_alternative_name)
//		{
//			if (scep_CertRep_set_SAN(req->csr, subject))
//			{
//				LOGE("Impossible to set SAN in the new certificate");
//				X509_free(subject);
//				return NULL;
//			}
//		}
    	scep_add_ext(scep->signcert, subject, NID_authority_key_identifier, "keyid:always");
    	ret = scep_add_ext_crl_distribution_point(scep->signcert, subject, scep->configure.crl_distribution_point);
    	if (scep_CertRep_set_all_extensions(req->csr, subject, ret) != 0)
    	{
    		LOGE("Impossible to set CSR extension");
    	}

    }

    LOGD("Sign the certificate");
    if (scep_sign(now, scep, subject, days))
    {
    	LOGE("Impossible to sign the new certificate");
        X509_free(subject);
        return NULL;
    }

    LOGD("Put the subject certificate in the responds");
    rep = scep_CertRep_new_with(scep, req, subject);
    if (!rep) {
    	LOGE("ERROR with scep_CertRep_new_with");
        X509_free(subject);
        return NULL;
    }

    LOGD("Quit scep_CertRep_new returned");
    return rep;
}

/**
 * @fn struct scep_CertRep scep_CertRep_reject*(struct scep*, struct scep_PKCSReq*, enum failInfo)
 * @brief return an error scep_CertRep with information why the request is rejected
 *
 * @param scep
 * @param req
 * @param why
 * @return
 */
struct scep_CertRep *scep_CertRep_reject(
        struct scep *scep, struct scep_PKCSReq *req, enum failInfo why)
{
    struct scep_CertRep *rep;
    const char *failInfo;

    if (!scep || !scep->cert || !scep->pkey || !req) {
        return NULL;
    }

    rep = (struct scep_CertRep *)malloc(sizeof(*rep));
    if (!rep) {
        return NULL;
    }

    switch (why) {
    case failInfo_badAlg         : failInfo =  "0"; break;
    case failInfo_badMessageCheck: failInfo =  "1"; break;
    case failInfo_badRequest     : failInfo =  "2"; break;
    case failInfo_badTime        : failInfo =  "3"; break;
    case failInfo_badCertId      : failInfo =  "4"; break;
    default                      : failInfo = NULL; break;
    }

    memset(rep, 0, sizeof(*rep));
    rep->pkcs7 = scep_CertRep_seal(scep, req, "2", failInfo, NULL);
    if (!rep->pkcs7) {
        free(rep);
        return NULL;
    }

    return rep;
}

/**
 * @fn X509 scep_CertRep_get_subject*(struct scep_CertRep*)
 * @brief return the subject certificate of the response
 *
 * @param rep
 * @return
 */
X509 *scep_CertRep_get_subject(struct scep_CertRep *rep)
{
    if (!rep) {
        return NULL;
    }

    return rep->cert;
}

/**
 * @fn int scep_CertRep_save(struct scep_CertRep*, BIO*)
 * @brief save the pkcs7 respons to a BIO before send it
 *
 * @param rep struct scep_CertRep * : responds that contain pkcs7 datas
 * @param bp BIO* : Out message where we copy pkcs7 datas
 * @return 0 if OK
 */
int scep_CertRep_save(struct scep_CertRep *rep, BIO *bp)
{
    if (!rep || !bp) {
        return -1;
    }

    if (i2d_PKCS7_bio(bp, rep->pkcs7) != 1) {
        return -1;
    }

    return 0;
}

/**
 * @fn void scep_CertRep_free(struct scep_CertRep*)
 * @brief free the objects contain in a struct scep_CertRep
 *
 * @param rep struct scep_CertRep* : pointer of the object to clear
 */
void scep_CertRep_free(struct scep_CertRep *rep)
{
    if (!rep) {
        return;
    }

    if (rep->cert) {
        X509_free(rep->cert);
    }

    if (rep->pkcs7) {
        PKCS7_free(rep->pkcs7);
    }

    free(rep);
}

/**
 * @fn int scep_get_cert(struct scep*, BIO*)
 * @brief
 *
 * @param scep
 * @param bp
 * @return
 */
int scep_get_cert(struct scep *scep, BIO *bp)
{
    int num;

    if (!scep || !scep->chain) {
        return -1;
    }

    num = sk_X509_num(scep->chain);
    if (num <= 0) {
        return -1;

    } else if (num == 1) {
        if (i2d_X509_bio(bp, scep->cert) != 1) {
            return -1;
        }
        return 1;

    } else if (scep_degenerate_chain(bp, scep->chain)) {
        return -1;
    }

    return num;
}

/**
 * @fn const ASN1_PRINTABLESTRING scep_PKCSReq_get_challengePassword*(const struct scep_PKCSReq*)
 * @brief get the challenge password contain in the PKCSReq
 *
 * @param req
 * @return
 */
const ASN1_PRINTABLESTRING *scep_PKCSReq_get_challengePassword(
        const struct scep_PKCSReq *req)
{
    if (!req) {
        return NULL;
    }

    return req->challengePassword;
}

/**
 * @fn const EVP_PKEY scep_PKCSReq_get_csr_key*(const struct scep_PKCSReq*)
 * @brief
 *
 * @param req
 * @return
 */
const EVP_PKEY *scep_PKCSReq_get_csr_key(const struct scep_PKCSReq *req)
{
    if (!req) {
        return NULL;
    }

    return req->csrkey;
}

/**
 * @fn const X509 scep_PKCSReq_get_current_certificate*(const struct scep_PKCSReq*)
 * @brief
 *
 * @param req
 * @return
 */
const X509 *scep_PKCSReq_get_current_certificate(
        const struct scep_PKCSReq *req)
{
    if (!req || !req->signer_certificate_is_valid) {
        return NULL;
    }

    return req->m->signer;
}

/**
 * @fn enum messageType scep_pkiMessage_get_type(const struct scep_pkiMessage*)
 * @brief
 *
 * @param m
 * @return
 */
enum messageType scep_pkiMessage_get_type(const struct scep_pkiMessage *m)
{
    return m->messageType;
}

/**
 * @fn unsigned int handle(void*, const char*, BIO*, const char**, BIO*)
 * @brief
 *
 * @param context
 * @param operation
 * @param payload
 * @param rct
 * @param response
 * @return
 */
//static unsigned int scep_handle(
//        void *context,
//        const char *operation,
//        BIO *payload,
//        const char **rct,
//        BIO *response)
//{
//    struct context *ctx;
//
//    ctx = (struct context *)context;
//    if (strcmp(operation, "GetCACaps") == 0) {
//        return handle_GetCACaps(ctx, payload, rct, response);
//    } else if (strcmp(operation, "GetCACert") == 0) {
//        return handle_GetCACert(ctx, payload, rct, response);
//    } else if (strcmp(operation, "PKIOperation") == 0) {
//        return handle_PKIOperation(ctx, payload, rct, response);
//    } else {
//        return (400);
//    }
//}
