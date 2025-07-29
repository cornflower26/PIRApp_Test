#include "../../include/pkg/key_agent.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/hypercube_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../drivers/repl_driver.cxx"

using namespace seal;
/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
    src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
KeyAgentClient::KeyAgentClient(std::string address, int port, int d, int s, int epsilon) : AgentClient(address, port, d, s) {
    b = ((1 + epsilon)*pow(sidelength,dimension))/d;
    this->epsilon = epsilon;
    this->n = pow(sidelength,dimension);
    this->w = sidelength/3;
    DatabaseSetup();
}


/**
 * Like DoRetrieve, but this one retrieves based off of a string key
 * @param network_driver
 * @param crypto_driver
 * @param key
 * @return
 */
CryptoPP::Integer KeyAgentClient::DoKeyRetrieve(std::shared_ptr<NetworkDriver> network_driver,
                                                std::shared_ptr<CryptoDriver> crypto_driver,
                                                std::string key) {
    // Initialize drivers.
    network_driver->connect(this->address, this->port);

    // Key exchange with server. From here on out, any outgoing messages should
    // be encrypted and MAC tagged. Incoming messages should be decrypted and have
    // their MAC checked.
    auto keys = this->HandleKeyExchange(crypto_driver, network_driver);
    //std::cout << "Connected and handled key exchange" << std::endl;
    std::vector<std::vector<int>> to_encode(dimension);
    //to_encode[0] = RandIndexVector(hash_key_2,key, sidelength);
    to_encode[0] = RandVector(hash_key_2,key, sidelength);
    //to_encode[0] = std::vector<int>(sidelength);
    //to_encode[0][5] = 1;
    /**
    int j = partition_hash(hash_key_1,key,b);
    for (int i = 1; i < dimension;i++){
       int j_i =  j/((b/sidelength)+1);
        std::vector<int> v_i(dimension,0);
        v_i[j_i + 1] = 1;
        b = (b/sidelength)+1;
        j = j % b;
        }
        **/

    return Retrieve(network_driver,crypto_driver,to_encode,keys);
}

std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
    KeyAgentClient::HandleKeyExchange(std::shared_ptr<CryptoDriver> crypto_driver,
                    std::shared_ptr<NetworkDriver> network_driver){
    // Generate private/public DH keys
    auto dh_values = crypto_driver->DH_initialize();

    // Respond with m = (g^b, g^a) signed with our private DSA key
    DHPublicValue_Message public_value_s;
    public_value_s.public_value = std::get<2>(dh_values);
    std::vector<unsigned char> public_value_data;
    public_value_s.serialize(public_value_data);
    network_driver->send(public_value_data);

    // Listen for g^a
    std::vector<unsigned char> server_public_value = network_driver->read();
    DHPublicValue_Message server_public_value_s;
    server_public_value_s.deserialize(server_public_value);

    // Recover g^ab
    auto dh_shared_key = crypto_driver->DH_generate_shared_key(
        std::get<0>(dh_values), std::get<1>(dh_values),
        server_public_value_s.public_value);

    // Generate keys
    auto AES_key = crypto_driver->AES_generate_key(dh_shared_key);
    auto HMAC_key = crypto_driver->HMAC_generate_key(dh_shared_key);
    auto keys = std::make_pair(AES_key, HMAC_key);

    std::vector<unsigned char> hash_key_1_m = network_driver->read();
    DHPublicValue_Message hash_key_1_message;
    hash_key_1_message.deserialize(hash_key_1_m);
    hash_key_1 = hash_key_1_message.public_value;

    std::vector<unsigned char> hash_key_2_m = network_driver->read();
    DHPublicValue_Message hash_key_2_message;
    hash_key_2_message.deserialize(hash_key_2_m);
    hash_key_2 = hash_key_2_message.public_value;

    std::vector<unsigned char> hash_key_r_m = network_driver->read();
    DHPublicValue_Message hash_key_r_message;
    hash_key_r_message.deserialize(hash_key_r_m);
    hash_key_r = hash_key_r_message.public_value;

    return keys;
}


/**
 * run
 */
void KeyAgentClient::run() {
    REPLDriver<KeyAgentClient> repl = REPLDriver<KeyAgentClient>(this);
    repl.add_action("get", "get <key>", &AgentClient::HandleRetrieve);
    repl.add_action("keyword", "keyword <key>", &KeyAgentClient::HandleKeyRetrieve);
    repl.add_action("keys", "keys", &KeyAgentClient::DatabasePrint);
    repl.run();
}

/**
 * Prints all of the keys in the database in case you need them
 * @param input
 */
void KeyAgentClient::DatabasePrint(std::string input) {
    std::cout << "Database keys: ";
    for (int i = 0; i < keys.size(); i++) {
        std::cout << keys[i] << " ";
    }
    std::cout << std::endl;
}


/**
 * Privately retrieve a value from the cloud given a key.
 */
void KeyAgentClient::HandleKeyRetrieve(std::string input) {
    // Parse input.
    std::vector<std::string> input_split = string_split(input, ' ');
    if (input_split.size() != 2) {
        this->cli_driver->print_left("invalid number of arguments.");
        return;
    }
    std::string key = input_split[1];

    // Call retrieve
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    this->DoKeyRetrieve(network_driver, crypto_driver, key);
}

/**
 * Generates a list of the keys
 */
void KeyAgentClient::DatabaseSetup() {
    for (int i = 0; i < n; i++) {
        std::string key = "value-" + std::to_string(i+1);
        keys.push_back(key) ;
    }
}