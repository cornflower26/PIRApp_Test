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
    b = ((1 + epsilon)*pow(sidelength,dimension))/d;
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
    int side = 0;
    if (sidelength > b) side = sidelength; else side = b;
    this->hypercube_driver = std::make_shared<HypercubeDriver>(2, side, CryptoPP::Integer(PLAINTEXT_MODULUS));
    int m = (1 + epsilon)*n;
    std::vector<std::vector<std::pair<std::string, int>>> partitions(b-1);
    auto iterator = database.begin();
    for (int i = 0; i < n; i++) {
        std::string key = iterator->first;
        int part = partition_hash(hash_key_1,key,b);
        partitions[part].push_back(std::make_pair(iterator->first, iterator->second));
        iterator++;
    }
    for (int i = 0; i < b; i++) {
        std::vector<int> e = GenerateEncode(hash_key_2,hash_key_r,partitions[i],b);
        for (int j = 0; j < e.size(); j++) {
            std::vector<int> coords{i,j};
            this->hypercube_driver->insert(this->hypercube_driver->from_coords(coords),e[j]);
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
