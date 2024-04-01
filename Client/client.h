#ifndef CLIENT_H
#define CLIENT_H

#include <string>

constexpr int BUFFER_SIZE = 1024;

void handleErrors();
void encryptMessage(const std::string& plaintext, unsigned char* ciphertext, int* ciphertext_len, unsigned char* iv);
int connectToServer(const char* server_ip, int server_port);

#endif // CLIENT_H
