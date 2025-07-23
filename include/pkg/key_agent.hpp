#pragma once
#include "agent.hpp"

class KeyAgentClient: public AgentClient{
    public:
    KeyAgentClient(std::string address, int port, int d, int s, int epsilon);
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
    HandleKeyExchange(std::shared_ptr<CryptoDriver> crypto_driver,
                    std::shared_ptr<NetworkDriver> network_driver) override;
    CryptoPP::Integer DoKeyRetrieve(std::shared_ptr<NetworkDriver> network_driver,
                             std::shared_ptr<CryptoDriver> crypto_driver,
                             std::string key);
    void run() override;
    void HandleKeyRetrieve(std::string input);

private:
    int b;
    int epsilon;
    int n;
    int w;

    std::vector<std::string> keys;
    CryptoPP::SecByteBlock hash_key_1;
    CryptoPP::SecByteBlock hash_key_2;
    CryptoPP::SecByteBlock hash_key_r;
    void DatabasePrint(std::string input);
    void DatabaseSetup();
    //void HashKeyExchange(std::shared_ptr<NetworkDriver> &network_driver);

};
