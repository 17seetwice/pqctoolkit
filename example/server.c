#include "ssl_utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define SERVER_PORT 4433
#define BUFFER_SIZE 1024


void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;

    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        const char *response = "Hello from TLS server!";
        buffer[bytes] = '\0';  // Null-terminate the received data
        printf("Client sent message: %s\n", buffer);
        SSL_write(ssl, response, strlen(response));
    } else {
        ERR_print_errors_fp(stderr);
    }
}


void server_main_loop(int server_fd, SSL_CTX *ctx) {
    while (1) {
        int client_fd;
        SSL *ssl;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        printf("=================================\n");
        printf("TLS server listening on port %d\n", SERVER_PORT);
        printf("=================================\n");

        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            fprintf(stderr, "Unable to accept\n");
            continue;
        }

        // Create a new SSL object for the connection
        ssl = SSL_new(ctx);

        if (ssl == NULL) {
            close(client_fd);
            fprintf(stderr, "Failed to create SSL context\n");
            continue;
        }

        if (SSL_set_fd(ssl, client_fd) != 1) {
            close(client_fd);
            SSL_free(ssl);
            fprintf(stderr, "Failed to connect SSL context and socket\n");
            continue;
        }

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            PrintConnectionInfo(ssl);
            handle_client(ssl);
        }
        printf("Closed the connection\n\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
}


int main() {
    int server_fd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

    // Initialize OpenSSL
    init_openssl();

    // Create a new TLS server SSL context
    ctx = SSL_CTX_new(TLS_server_method());;

    if (ctx == NULL) {
        fprintf(stderr, "Failed to create TLS server context\n");
        exit(EXIT_FAILURE);
    }

    // Configure the SSL context with certificates
    if (configure_context(ctx) != 1) {
        fprintf(stderr, "Failed to configure TLS server context\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    };

    // Create a TCP socket for listening
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "Unable to create socket\n");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Unable to bind socket\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0) {
        fprintf(stderr, "Unable to listen\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    server_main_loop(server_fd, ctx);
    
    close(server_fd);
    SSL_CTX_free(ctx);

    return 0;
}