#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;
extern std::string aes_key;

void handleClient(int clientSocket);

#endif // SERVER_H
