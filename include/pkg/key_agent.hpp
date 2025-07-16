#pragma once
#include "agent.hpp"

class KeyAgentClient: public AgentClient{
    public:
    KeyAgentClient(std::string address, int port, int d, int s, int epsilon);
    CryptoPP::Integer DoKeyRetrieve(std::shared_ptr<NetworkDriver> network_driver,
                             std::shared_ptr<CryptoDriver> crypto_driver,
                             std::string key);
    void Decrypt();

private:
    int b;
    int epsilon;
    int n;

    CryptoPP::SecByteBlock hash_key_1;
    CryptoPP::SecByteBlock hash_key_2;
    CryptoPP::SecByteBlock hash_key_r;
};
