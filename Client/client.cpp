#include "client.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>

std::string aes_key = "ThisIsASecretKey"; // 16-byte key for AES-128

// Prints error if failure to initialize OpenSSL then exits
void handleErrors() {
    std::cerr << "Error: Failed to initialize OpenSSL." << std::endl;
    exit(EXIT_FAILURE);
}

// Encrypts clients message using AES encryption inc cbc mode
void encryptMessage(const std::string& plaintext, unsigned char* ciphertext, int* ciphertext_len, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx;
    int len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, reinterpret_cast<const unsigned char*>(aes_key.c_str()), iv))
        handleErrors();

    // Encrypt plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length()))
        handleErrors();

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len))
        handleErrors();
    *ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

// Uses default server address and port to connect to server socket with created client socket
int connectToServer(const char* server_ip, int server_port) {
    int clientSocket;
    struct sockaddr_in serverAddr;

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        std::cerr << "Error: Failed to create socket." << std::endl;
        return -1;
    }

    // Set server address and port
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(server_ip);
    serverAddr.sin_port = htons(server_port);

    // Connect to server
    if (connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) == -1) {
        std::cerr << "Error: Failed to connect to server." << std::endl;
        close(clientSocket);
        return -1;
    }

    return clientSocket;
}
