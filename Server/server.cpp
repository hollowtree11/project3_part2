#include "server.h"

std::string aes_key = "ThisIsASecretKey"; // 16-byte key for AES-128

// Handles client communication
void handleClient(int clientSocket) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create AES context." << std::endl;
        return;
    }

    EVP_CIPHER_CTX_init(ctx);

    unsigned char iv[EVP_MAX_IV_LENGTH];

    int bytesRead;
    while ((bytesRead = recv(clientSocket, iv, EVP_MAX_IV_LENGTH, 0)) > 0) {
        // Receive IV from client

        unsigned char encryptedBuffer[BUFFER_SIZE];
        bytesRead = recv(clientSocket, encryptedBuffer, BUFFER_SIZE, 0);

        // Decrypt the received data using AES-128-CBC
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, reinterpret_cast<const unsigned char*>(aes_key.c_str()), iv)) {
            std::cerr << "Error: Failed to initialize AES decryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        unsigned char decryptedBuffer[BUFFER_SIZE];
        int decryptedLen;

        if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &decryptedLen, encryptedBuffer, bytesRead)) {
            std::cerr << "Error: Failed to decrypt data." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        // Finalize decryption
        int finalDecryptedLen;
        if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + decryptedLen, &finalDecryptedLen)) {
            std::cerr << "Error: Failed to finalize decryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        decryptedLen += finalDecryptedLen;

        decryptedBuffer[decryptedLen] = '\0';
        std::cout << "Received encrypted message: ";
        std::cout.write(reinterpret_cast<const char*>(encryptedBuffer), bytesRead);
        std::cout << std::endl;

        std::cout << "Decrypted message: " << decryptedBuffer << std::endl;

        // Echo back the decrypted message to the client
        send(clientSocket, decryptedBuffer, decryptedLen, 0);
    }

    EVP_CIPHER_CTX_free(ctx);
    close(clientSocket);
}
