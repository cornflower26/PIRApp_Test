#include <cmath>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../drivers/repl_driver.cxx"
#include "../../include/pkg/key_cloud.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
    src::severity_logger<logging::trivial::severity_level> lg;
}
using namespace seal;

KeyCloudClient::KeyCloudClient(int d, int s, int epsilon) : CloudClient(d, s) {
    //b = ((1 + epsilon)*pow(sidelength,dimension))/d;
    b = sidelength;
    this->epsilon = epsilon;
    this->n = pow(sidelength,dimension);
}

void KeyCloudClient::DatabaseSetup() {
    for (int i = 0; i < n; i++) {
        std::string key = "value - " + std::to_string(i);
        database.insert(std::make_pair( key,1)) ;
    }
}

void KeyCloudClient::Encode() {
    int side = sidelength;
    //if (b > sidelength) side = b;
    this->hypercube_driver = std::make_shared<HypercubeDriver>(1, side, CryptoPP::Integer(PLAINTEXT_MODULUS));
    int m = (1 + epsilon)*n;

    //std::vector<std::vector<std::pair<std::string, int>>> partitions(b-1);
    std::vector<std::pair<std::string, int>> partitions;
    auto iterator = database.begin();
    for (int i = 0; i < n; i++) {
        std::string key = iterator->first;
        int part = partition_hash(hash_key_1,key,b);
        //partitions[part].push_back(std::make_pair(iterator->first, iterator->second));
        partitions.push_back(std::make_pair(iterator->first, iterator->second));
        iterator++;
    }
    for (int i = 0; i < b; i++) {
        std::vector<int> e = GenerateEncode(hash_key_2,hash_key_r,partitions,b);
        for (int j = 0; j < e.size(); j++) {
            //std::vector<int> coords{i,j};
            //this->hypercube_driver->insert(this->hypercube_driver->from_coords(coords),e[j]);
            this->hypercube_driver->insert(j,e[j]);
        }
    }
}

/**
 * run
 */
void KeyCloudClient::run(int port) {
    // Start listener thread
    std::thread listener_thread(&CloudClient::ListenForConnections, this, port);
    listener_thread.detach();

    // Run REPL.
    REPLDriver<KeyCloudClient> repl = REPLDriver<KeyCloudClient>(this);
    repl.add_action("insert", "insert <key> <value>", &CloudClient::HandleInsert);
    repl.add_action("get", "get <key>", &CloudClient::HandleGet);
    repl.add_action("cube", "cube <filename>", &CloudClient::HandleCube);
    repl.add_action("keyword", "keyword", &KeyCloudClient::HandleKeyword);
    repl.run();
}

/**
 * Insert a value into the database
 */
void KeyCloudClient::HandleKeyword(std::string input) {
    std::vector<std::string> input_split = string_split(input, ' ');
    if (input_split.size() != 1) {
        this->cli_driver->print_left("invalid number of arguments.");
        return;
    }
    DatabaseSetup();
    Encode();
    //int key = std::stoi(input_split[1]);
    //CryptoPP::Integer value = CryptoPP::Integer(std::stoi(input_split[2]));
    //this->hypercube_driver->insert(key, value);
    this->cli_driver->print_success("Converted to Keyword");
}

/**
 * Come to a shared secret
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
KeyCloudClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                               std::shared_ptr<CryptoDriver> crypto_driver) {
    // Generate private/public DH keys
    auto dh_values = crypto_driver->DH_initialize();

    // Listen for g^a
    std::vector<unsigned char> user_public_value = network_driver->read();
    DHPublicValue_Message user_public_value_s;
    user_public_value_s.deserialize(user_public_value);

    // Respond with m = (g^b, g^a) signed with our private DSA key
    DHPublicValue_Message public_value_s;
    public_value_s.public_value = std::get<2>(dh_values);
    std::vector<unsigned char> public_value_data;
    public_value_s.serialize(public_value_data);
    network_driver->send(public_value_data);

    // Recover g^ab
    auto dh_shared_key = crypto_driver->DH_generate_shared_key(
        std::get<0>(dh_values), std::get<1>(dh_values),
        user_public_value_s.public_value);

    // Generate keys
    auto AES_key = crypto_driver->AES_generate_key(dh_shared_key);
    auto HMAC_key = crypto_driver->HMAC_generate_key(dh_shared_key);
    auto keys = std::make_pair(AES_key, HMAC_key);

    hash_key_1 = crypto_driver->SipHash_generate_key();
    hash_key_2 = crypto_driver->SipHash_generate_key();
    hash_key_r = crypto_driver->SipHash_generate_key();

    DHPublicValue_Message hashKey_1;
    hashKey_1.public_value = hash_key_1;
    std::vector<unsigned char> hash_key_1_message;
    hashKey_1.serialize(hash_key_1_message);
    network_driver->send(hash_key_1_message);

    DHPublicValue_Message hashKey_2;
    hashKey_2.public_value = hash_key_2;
    std::vector<unsigned char> hash_key_2_message;
    hashKey_2.serialize(hash_key_2_message);
    network_driver->send(hash_key_2_message);

    DHPublicValue_Message hashKey_3;
    hashKey_3.public_value = hash_key_r;
    std::vector<unsigned char> hash_key_r_message;
    hashKey_3.serialize(hash_key_r_message);
    network_driver->send(hash_key_r_message);

    return keys;
}
