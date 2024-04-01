# Creates client executable
add_executable(client_executable main.cpp
        client.cpp
)

target_link_libraries(client_executable OpenSSL::SSL OpenSSL::Crypto)