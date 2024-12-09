#include "client.h"
#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/dh.h>
#include <iomanip>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Default server IP address and port number if not specified
constexpr const char* DEFAULT_SERVER_IP = "127.0.0.1";
constexpr int DEFAULT_SERVER_PORT = 8080;

int main() {
    int clientSocket = connectToServer(DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT);
    if (clientSocket == -1) {
        std::cout << "Error in connecting to socket" << std::endl;
        return 1;
    }

    // Step 1: Generate DH key pairs and send the public key to the server
    // Diffie-Hellman components
    DH *privkey;
    int codes;
    int secret_size;

    privkey = DH_get_2048_256();
    if (privkey == NULL){
        handleErrors();
    }


    if (DH_generate_key(privkey) != 1){
        handleErrors();
    }


    const BIGNUM *pubkey = NULL;

    DH_get0_key(privkey, &pubkey, NULL);

    if (pubkey == NULL) {
        printf("Error: DH public key is NULL\n");
        handleErrors();
    }

    printf("Client's Public Key: ");
    BN_print_fp(stdout, pubkey);
    printf("\n");

    // Convert the public key's type from BigNumber to binary
    unsigned char *pubkey_bin = NULL;
    int pubkey_len = BN_num_bytes(pubkey);
    pubkey_bin = (unsigned char *)OPENSSL_malloc(pubkey_len);
    if (pubkey_bin == NULL) {
        printf("Error: Memory allocation failed\n");
        handleErrors();
    }
    BN_bn2bin(pubkey, pubkey_bin);

    // Necessary variables to encrypt the public key and send it to the server
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        std::cerr << "Error: Failed to generate random IV." << std::endl;
        close(clientSocket);
        return 1;
    }
    // Encrypt the public key
    encryptWithPSK(pubkey_bin, pubkey_len, (unsigned char*)pre_shared.c_str(), ciphertext, iv, ciphertext_len);

    int ivSent = send(clientSocket, iv, EVP_MAX_IV_LENGTH, 0);

    int ciphertextSent = send(clientSocket, ciphertext, ciphertext_len, 0);
    

    std::cout << "Encrypted public key sent to server." << std::endl;

    // Step 2: Take the server's encrypted public key and decrypt it
    // read IV from the server 
    unsigned char IV[EVP_MAX_IV_LENGTH];
    int bytesRead;

    int ivReceivedBytes = recv(clientSocket, IV, EVP_MAX_IV_LENGTH, 0);
    
    
    unsigned char encryptedBuffer[BUFFER_SIZE];
    bytesRead = recv(clientSocket, encryptedBuffer, BUFFER_SIZE, 0);
    
    unsigned char decryptedBuffer[BUFFER_SIZE];
    int decryptedLen;

    // decrypt the encrypted public key
    decryptWithPSK(encryptedBuffer, bytesRead, (unsigned char*)pre_shared.c_str(), decryptedBuffer, IV, decryptedLen);
        
    std::cout << "Decrypted Server's Public Key (Hex): ";
    for (int i = 0; i < decryptedLen; i++) {
        printf("%02x", decryptedBuffer[i]);
    }
    std::cout << std::endl;

    // Step 3: Compute the session key (shared secret)
    BIGNUM *serverPubKey = BN_bin2bn(decryptedBuffer, decryptedLen, NULL);
    unsigned char *sharedSecret = (unsigned char *)OPENSSL_malloc(DH_size(privkey));

    secret_size = DH_compute_key(sharedSecret, serverPubKey, privkey);
    

    std::cout << "Shared Secret (Hex): ";
    for (int i = 0; i < secret_size; i++) {
        printf("%02x", sharedSecret[i]);
    }
    std::cout << std::endl;
    std::cout << "Shared key was established. Enter message 'quit' to exit: \n";

    while (true) {

        // Stores client input as message string
        std::string message;
        std::getline(std::cin, message);

        // Breaks the client application if message is 'quit'
        if (message == "quit") {
            break;
        }

        // Generate random IV and closes application if error
        unsigned char iv[EVP_MAX_IV_LENGTH];
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
            std::cerr << "Error: Failed to generate random IV." << std::endl;
            close(clientSocket);
            return 1;
        }

        // Encrypt message
        unsigned char ciphertext[BUFFER_SIZE];
        int ciphertext_len;
        encryptMessage(message, ciphertext, &ciphertext_len, iv, sharedSecret);

        // Send IV and encrypted message to server
        send(clientSocket, iv, EVP_MAX_IV_LENGTH, 0);
        send(clientSocket, ciphertext, ciphertext_len, 0);
        std::cout << "Sent encrypted message to server." << std::endl;
    }
    close(clientSocket);
}
