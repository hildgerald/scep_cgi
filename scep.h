#ifndef SCEP_H
#define SCEP_H

#include <openssl/bio.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

struct scep;
struct scep_PKCSReq;
struct scep_CertRep;
struct scep_pkiMessage;

enum messageType {
    messageType_CertRep         = 3,
    messageType_RenewalReq      = 17,
    messageType_PKCSReq         = 19,
    messageType_CertPoll        = 20,
    messageType_GetCert         = 21,
    messageType_GetCRL          = 22,
};

enum pkiStatus {
    pkiStatus_SUCCESS           = 0,
    pkiStatus_FAILURE           = 2,
    pkiStatus_PENDING           = 3,
};

enum failInfo {
    failInfo_badAlg             = 0,
    failInfo_badMessageCheck    = 1,
    failInfo_badRequest         = 2,
    failInfo_badTime            = 3,
    failInfo_badCertId          = 4,
};

enum certFormat {
	Cert_format_DER,
	Cert_format_PEM
};

enum keyFormat {
	key_format_DER,
	key_format_PEM
};

struct scep_configure { /* memset() to 0 for all default */
    /* macOS bug, challenge password is in pkcsPKIEnvelope unencrypted */
    int tolerate_exposed_challenge_password;

    /* transactionID is the hash of the pubkey but not always the case */
    int no_validate_transaction_id;

    /* Copy SAN from CSR to issued certificate */
    int set_subject_alternative_name;

    /* URI of crl distribution point like http://toto.com/crl.pem */
    char crl_distribution_point[512];
};

#define SCEP_RSA_MIN_BITS 2048

struct scep_extension {
    struct scep_extension *next;
    char *value;
    int nid;
};

struct scep {
    struct scep_configure configure;

    int NID_SCEP_messageType;
    int NID_SCEP_pkiStatus;
    int NID_SCEP_failInfo;
    int NID_SCEP_senderNonce;
    int NID_SCEP_recipientNonce;
    int NID_SCEP_transactionID;
    int NID_SCEP_extensionReq;

    X509 *cert;   // certificate of the RA or the CA that crypt datas
    EVP_PKEY *pkey; // private key of the RA or the CA that crypt datas
    const EVP_MD *md;
    STACK_OF(X509) *chain; // trust of chain of the RA or the CA that crypt datas
    X509 *signcert;   // certificate of the RA or the CA that crypt datas
    EVP_PKEY *signpkey; // private key of the of the signer CA that deliver certificate
    STACK_OF(X509) *signchain; // trust of chain of the signer CA that deliver certificate

    struct scep_extension *extensions;

    X509_STORE *store; /* For verifying certificates issued by trusted CAs */
};

struct scep_pkiMessage_attributes {
    ASN1_PRINTABLESTRING *transactionID;
    ASN1_PRINTABLESTRING *messageType;
    ASN1_PRINTABLESTRING *pkiStatus;
    ASN1_PRINTABLESTRING *failInfo;
    ASN1_OCTET_STRING    *senderNonce;
    ASN1_OCTET_STRING    *recipientNonce;
};

struct scep_pkiMessage {
    PKCS7 *pkcs7; /* Owned by this */
    BIO *payload; /* Owned by this */
    X509 *signer; /* Owned by this->pkcs7 */

    enum messageType messageType;

    struct scep_pkiMessage_attributes auth_attr; /* Owned by this->pkcs7 */
};

struct scep_PKCSReq {
    const struct scep_pkiMessage *m; /* Owns this */

    int signer_certificate_is_valid;
    X509_REQ *csr; /* Owned by this */
    const EVP_PKEY *csrkey; /* Owned by this->csr */
    const ASN1_PRINTABLESTRING *challengePassword; /* Owned by this->csr */
};

struct scep_CertRep {
    PKCS7 *pkcs7; /* Owned by this */
    X509 *cert; /* Owned by this */
};

extern struct scep 	*scep_new(const struct scep_configure *configure);
extern void 		scep_free(struct scep *scep);

/* Load signing certificate first */
extern int 			scep_load_certificate(
										struct scep *scep,
										const char *certfile,
										int certpem,
										const char *keyfile,
										int keypem,
										const char *keypass);

/* Load signer certificate to create certificate */
extern int 			scep_load_signer_certificate(
										struct scep *scep,
										const char *certfile,
										int certpem,
										const char *keyfile,
										int keypem,
										const char *keypass);

/* Then load certificate chain if needed */
extern int 			scep_load_certificate_chain(
										struct scep *scep,
										const char *certfile,
										int certpem);

/* Then load other trusted certificate if needed */
extern int 			scep_load_other_ca_certificate(
										struct scep *scep,
										const char *certfile,
										int certpem);

extern int 			scep_load_subject_extensions(
        								struct scep *scep,
										const char *filename);

/* Returns number of certificates included, or -1 for error */
extern int 			scep_get_cert(
										struct scep *scep,
										BIO *bp);

extern struct scep_pkiMessage *scep_pkiMessage_new(
										struct scep *scep,
										BIO *bp);

extern enum messageType scep_pkiMessage_get_type(
        								const struct scep_pkiMessage *m);

extern void 			scep_pkiMessage_free(struct scep_pkiMessage *m);

/* Returned object is owned by scep_pkiMessage, don't free it */
extern struct scep_PKCSReq *scep_PKCSReq_new(
        								struct scep *scep,
										struct scep_pkiMessage *m);

extern void 			scep_PKCSReq_free(struct scep_PKCSReq *req);

extern const X509_REQ 	*scep_PKCSReq_get_csr(const struct scep_PKCSReq *req);
extern const EVP_PKEY 	*scep_PKCSReq_get_csr_key(const struct scep_PKCSReq *req);

extern const ASN1_PRINTABLESTRING *scep_PKCSReq_get_challengePassword(
        								const struct scep_PKCSReq *req);

/* Only if the requester used a valid certificate issued by this CA */
extern const X509 		*scep_PKCSReq_get_current_certificate(
        								const struct scep_PKCSReq *req);

extern X509 			*scep_CertRep_get_subject(struct scep_CertRep *rep);
extern int 				scep_CertRep_save(struct scep_CertRep *rep, BIO *bp);
extern void 			scep_CertRep_free(struct scep_CertRep *rep);

extern struct scep_CertRep *scep_CertRep_new(
										struct scep *scep,
										struct scep_PKCSReq *req,
										time_t now,
										long days);

extern struct scep_CertRep *scep_CertRep_new_with(
										struct scep *scep,
										struct scep_PKCSReq *req,
										X509 *subject); /* Ownership taken if succeeded */

extern struct scep_CertRep *scep_CertRep_reject(
										struct scep *scep,
										struct scep_PKCSReq *req,
										enum failInfo why);

#ifdef __cplusplus
}
#endif

#endif /* SCEP_H */
