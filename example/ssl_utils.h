#include <openssl/base.h>

void        init_openssl();
EVP_PKEY*   make_key_pair(int sig_alg_nid);
X509*       make_selfsigned_cert(EVP_PKEY *evp_pkey);
int         configure_context(SSL_CTX *ctx);
void        PrintConnectionInfo(const SSL *ssl);