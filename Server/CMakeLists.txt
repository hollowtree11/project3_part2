# Creates the server executable
add_executable(server_executable server.cpp
        main.cpp)

target_link_libraries(server_executable OpenSSL::SSL OpenSSL::Crypto)