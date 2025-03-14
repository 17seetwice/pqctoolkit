#include "ssl_utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define     COUNTRY         "KR"
#define     STATE           "Some-State"
#define     LOCALITY        "Some-City"
#define     ORGANIZATION    "Crypto Lab"
#define     ORG_UNIT        "CA Department"
#define     COMMON_NAME     "My CA Certificate"

// OpenSSL 초기화 함수
void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

// 키 쌍 생성 함수 (예시로 EC 키 사용)
EVP_PKEY* make_key_pair(int sig_alg_nid) {
    EVP_PKEY *evp_pkey = EVP_PKEY_new();

    if (sig_alg_nid == NID_secp224r1 ||
        sig_alg_nid == NID_X9_62_prime256v1 ||
        sig_alg_nid == NID_secp384r1 ||
        sig_alg_nid == NID_secp521r1) {

        EC_KEY *ec_key = EC_KEY_new_by_curve_name(sig_alg_nid);
        if (ec_key == NULL) {
            fprintf(stderr, "Failed to create EC_KEY for curve %d.\n", sig_alg_nid);
            EVP_PKEY_free(evp_pkey);
            return NULL;
        }

        if (!EC_KEY_generate_key(ec_key)) {
            fprintf(stderr, "Failed to generate EC key pair.\n");
            EC_KEY_free(ec_key);
            EVP_PKEY_free(evp_pkey);
            return NULL;
        }

        if (!EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key)) {
            fprintf(stderr, "Failed to assign EC key to EVP_PKEY.\n");
            EC_KEY_free(ec_key);
            EVP_PKEY_free(evp_pkey);
            return NULL;
        }
    } else {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(sig_alg_nid, NULL);
        if (ctx == NULL) {
            fprintf(stderr, "Failed to create EVP_PKEY_CTX.\n");
            EVP_PKEY_free(evp_pkey);
            return NULL;
        }

        if (EVP_PKEY_keygen_init(ctx) != 1) {
            fprintf(stderr, "Failed to initialize keygen.\n");
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(evp_pkey);
            return NULL;
        }
        if (EVP_PKEY_keygen(ctx, &evp_pkey) != 1) {
            fprintf(stderr, "Failed to generate key pair.\n");
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(evp_pkey);
            return NULL;
        }
        EVP_PKEY_CTX_free(ctx);
    }

    return evp_pkey;
}

// CA용 self-signed X.509 인증서를 생성하는 함수 (수정본)
// 생성된 인증서의 DER 인코딩 크기를 출력하도록 추가됨.
X509* make_selfsigned_cert(EVP_PKEY *evp_pkey) {
    X509 *x509 = X509_new();
    if (x509 == NULL) {
        return NULL;
    }

    // X.509 버전 3 (내부적으로는 버전 2로 설정됨)
    if (!X509_set_version(x509, 2)) {
        X509_free(x509);
        return NULL;
    }

    // 시리얼 번호 설정 (랜덤 값 사용)
    ASN1_INTEGER *serial = X509_get_serialNumber(x509);
    if (!RAND_bytes((unsigned char *)serial->data, serial->length)) {
        X509_free(x509);
        return NULL;
    }

    // Subject 이름 설정 (CA 인증서를 위한 필드 추가)
    X509_NAME *name = X509_get_subject_name(x509);
    if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)COUNTRY, -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)STATE, -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *)LOCALITY, -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)ORGANIZATION, -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char *)ORG_UNIT, -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)COMMON_NAME, -1, -1, 0)) {
        X509_free(x509);
        return NULL;
    }
    // Self-signed이므로 issuer를 subject와 동일하게 설정
    if (!X509_set_issuer_name(x509, name)) {
        X509_free(x509);
        return NULL;
    }

    // 유효 기간 설정: 시작 시간은 지금, 만료 시간은 10년 후
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), 60L * 60 * 24 * 365 * 10)) {
        X509_free(x509);
        return NULL;
    }

    // 공개키 설정
    if (!X509_set_pubkey(x509, evp_pkey)) {
        fprintf(stderr, "Failed to set public key.\n");
        X509_free(x509);
        return NULL;
    }

    // 확장 추가를 위한 컨텍스트 설정
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);

    // Basic Constraints: CA:TRUE
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:TRUE");
    if (!ex) {
        X509_free(x509);
        return NULL;
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    // Key Usage: certificate signing, CRL signing (critical)
    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (!ex) {
        X509_free(x509);
        return NULL;
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    // 인증서 서명 (SHA-256 사용)
    if (!X509_sign(x509, evp_pkey, EVP_sha256())) {
        fprintf(stderr, "Failed to sign certificate.\n");
        X509_free(x509);
        return NULL;
    }

    // 인증서의 DER 인코딩 크기를 계산하여 출력
    int der_len = i2d_X509(x509, NULL);
    if (der_len < 0) {
        fprintf(stderr, "Failed to compute DER encoding length.\n");
    } else {
        printf("Certificate DER encoded size: %d bytes\n", der_len);
    }

    return x509;
}

// 연결 정보를 출력하는 함수 (디버깅용)
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
        X509_free(peer);
    }
}

// SSL_CTX 설정 함수: 인증서와 개인키를 SSL 컨텍스트에 등록
int configure_context(SSL_CTX *ctx) {
    X509 *cert = NULL;
    EVP_PKEY *evp_pkey = make_key_pair(NID_secp256r1); // 예시로 ECC P-256 사용

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

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        EVP_PKEY_free(evp_pkey);
        X509_free(cert);
        return 0;
    }

    EVP_PKEY_free(evp_pkey);
    X509_free(cert);
    return 1;
}

// main 함수: OpenSSL 초기화 및 SSL 컨텍스트 구성
int main() {
    init_openssl();

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL) {
        fprintf(stderr, "Unable to create SSL context.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!configure_context(ctx)) {
        fprintf(stderr, "Failed to configure SSL context.\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("SSL context configured successfully.\n");

    // 이후 서버/클라이언트 로직 추가 가능

    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
