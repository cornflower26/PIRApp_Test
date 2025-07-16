#pragma once

#include "cloud.hpp"

class KeyCloudClient: public CloudClient{
public:
    KeyCloudClient(int d, int s, int epsilon);

    void Encode();
    void DatabaseSetup();

private:
    int b;
    int epsilon;
    int n;
    std::map<std::string, int> database;

    CryptoPP::SecByteBlock hash_key_1;
    CryptoPP::SecByteBlock hash_key_2;
    CryptoPP::SecByteBlock hash_key_r;

};