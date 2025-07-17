#pragma once

#include "cloud.hpp"

class KeyCloudClient: public CloudClient{
public:
    KeyCloudClient(int d, int s, int epsilon);

    void Encode();
    void DatabaseSetup();

    void run(int port) override;
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
    HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                  std::shared_ptr<CryptoDriver> crypto_driver) override;
    void HandleKeyword(std::string input);

private:
    int b;
    int epsilon;
    int n;
    std::map<std::string, int> database;

    CryptoPP::SecByteBlock hash_key_1;
    CryptoPP::SecByteBlock hash_key_2;
    CryptoPP::SecByteBlock hash_key_r;

};