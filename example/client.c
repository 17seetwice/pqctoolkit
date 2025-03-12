#include "ssl_utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define SERVER_ADDRESS  "127.0.0.1"     // Change this to your server's host
#define SERVER_PORT     4433            // Default HTTPS port

int create_socket(const char *host, int port) {
    struct sockaddr_in server_addr;
    int sock_fd;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sock_fd < 0) {
        fprintf(stderr, "Failed to create socket\n");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(host);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Failed to connect to TLS server\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    return sock_fd;
}


void tls_client(const char *host, int port) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    char buf[1024];

    // Initialize SSL library
    init_openssl();

    // Create new TLS client SSL context
    ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL) {
        fprintf(stderr, "Failed to create TLS client context\n");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Set PQC KEM algorithms  
    if (SSL_CTX_set1_curves_list(ctx, "kyber512:smaug1:smaug3:smaug5") != 1) {
        fprintf(stderr, "Failed setting curves list\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Create a socket and connect to the server
    sockfd = create_socket(host, port);

    // Create an SSL object to hold the connection state
    ssl = SSL_new(ctx);

    SSL_set_fd(ssl, sockfd);

    // Establish a TLS/SSL connection
    printf("Connecting to %s:%d\n", SERVER_ADDRESS, SERVER_PORT);
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    PrintConnectionInfo(ssl);
    // Send a simple HTTP request (or any request, depending on server)
    const char *request = "Hello message from client";
    SSL_write(ssl, request, strlen(request));

    // Read the response from the server
    int bytes_received;
    while ((bytes_received = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_received] = '\0';
        printf("Server sent message : %s\n", buf);
    }

    if (bytes_received < 0) {
        fprintf(stderr, "SSL_read failed\n");
    }

    // Clean up and close the connection
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("Closed connection\n");
}


int main() {
    tls_client(SERVER_ADDRESS, SERVER_PORT);
    return 0;
}