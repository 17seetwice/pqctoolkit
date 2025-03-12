
#include "ssl_utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define     COUNTRY         "KR"
#define     ORGANIZATION    "Crypto Lab"

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}


EVP_PKEY* make_key_pair(int sig_alg_nid) {
    EVP_PKEY *evp_pkey = EVP_PKEY_new();

    if(sig_alg_nid == NID_secp224r1 ||
        sig_alg_nid == NID_X9_62_prime256v1 ||
        sig_alg_nid == NID_secp384r1 ||
        sig_alg_nid == NID_secp521r1) {

        EC_KEY *ec_key = EC_KEY_new_by_curve_name(sig_alg_nid);

        if (ec_key == NULL) {
            fprintf(stderr, "Failed to create EC_KEY for curve %d.\n", sig_alg_nid);
            EVP_PKEY_free(evp_pkey); // Clean up
            return NULL;
        }

        if (!EC_KEY_generate_key(ec_key)) {
            fprintf(stderr, "Failed to generate EC key pair.\n");
            EC_KEY_free(ec_key);  // Free the EC key
            EVP_PKEY_free(evp_pkey); // Clean up
            return NULL;
        }

        if (!EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key)) {
            fprintf(stderr, "Failed to assign EC key to EVP_PKEY.\n");
            EC_KEY_free(ec_key);  // Free the EC key
            EVP_PKEY_free(evp_pkey); // Clean up
            return NULL;
        }

    } else {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(sig_alg_nid, NULL);

        if (ctx == NULL) {
            fprintf(stderr, "Failed to create EVP_PKEY_CTX.\n");
            EVP_PKEY_free(evp_pkey); // Clean up
            return NULL;
        }

        if (EVP_PKEY_keygen_init(ctx) != 1) {
            fprintf(stderr, "Failed to initialize keygen.\n");
            EVP_PKEY_CTX_free(ctx); // Free ctx
            EVP_PKEY_free(evp_pkey); // Clean up
            return NULL;
        }
        if (EVP_PKEY_keygen(ctx, &evp_pkey) != 1) {
            fprintf(stderr, "Failed to generate key pair.\n");
            EVP_PKEY_CTX_free(ctx); // Free ctx
            EVP_PKEY_free(evp_pkey); // Clean up
            return NULL;
        }

        EVP_PKEY_CTX_free(ctx); // Free the EVP_PKEY_CTX once we're done
    }

    return evp_pkey;
}


X509* make_selfsigned_cert(EVP_PKEY *evp_pkey){
    uint64_t serial;
    X509    *x509 = X509_new();
    if (x509 == NULL) {
        return NULL;
    }

    if (!X509_set_version(x509, X509_VERSION_3) ||
        !RAND_bytes((uint8_t *)&serial, sizeof(serial)) ||
        !ASN1_INTEGER_set_uint64(X509_get_serialNumber(x509), serial) ||
        !X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), 60 * 60 * 24 * 3650)) {
        X509_free(x509);  // Clean up
        return NULL;
    }

    X509_NAME *subject = X509_get_subject_name(x509);

    if (!X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, (const uint8_t *)COUNTRY, -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, (const uint8_t *)ORGANIZATION, -1, -1, 0) ||
        !X509_set_issuer_name(x509, subject)) {
        X509_free(x509);  // Clean up

        return NULL;
    }

    if (!X509_set_pubkey(x509, evp_pkey)) {
        fprintf(stderr, "Failed to set public key.\n");
        X509_free(x509);  // Clean up
        return NULL;
    }

    if (!X509_sign(x509, evp_pkey, EVP_sha256())) {
        fprintf(stderr, "Failed to sign certificate.\n");
        X509_free(x509);  // Clean up
        return NULL;
    }

    return x509;
}


void PrintConnectionInfo(const SSL *ssl) {
    if (ssl == NULL) {
        fprintf(stderr, "SSL object is null\n");
        return;
    }

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    printf("Connection Information\n");
    printf("    TLS Version: %s\n", SSL_get_version(ssl));
    printf("    Cipher: %s\n", SSL_CIPHER_standard_name(cipher));

    uint16_t group = SSL_get_group_id(ssl);
    if (group != 0) {
        printf("    ECDHE group: %s\n", SSL_get_group_name(group));
    }

    uint16_t sigalg = SSL_get_peer_signature_algorithm(ssl);
    if (sigalg != 0) {
        printf("    Signature algorithm: %s\n",
                SSL_get_signature_algorithm_name(
                sigalg, SSL_version(ssl) != TLS1_2_VERSION));
    }

    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer != NULL) {
        printf("    Cert subject: %s\n", X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0));
        printf("    Cert issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(peer), NULL, 0));
    }
}


int configure_context(SSL_CTX *ctx) {
    X509 *cert = NULL;
    EVP_PKEY *evp_pkey = make_key_pair(NID_haetae5);

    if (evp_pkey == NULL) {
        return 1;
    }

    cert = make_selfsigned_cert(evp_pkey);

    if (cert == NULL) {
        EVP_PKEY_free(evp_pkey);
        return 0;
    }

    if (SSL_CTX_use_PrivateKey(ctx, evp_pkey) != 1) {
        fprintf(stderr, "Failed to set private key.\n");
        EVP_PKEY_free(evp_pkey);
        X509_free(cert);
        return 0;
    }

    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        fprintf(stderr, "Failed to set certificate.\n");
        EVP_PKEY_free(evp_pkey);
        X509_free(cert);
        return 0;
    }

    // Verify the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        EVP_PKEY_free(evp_pkey);
        X509_free(cert);
        return 0;
    }

    return 1;
}
