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

KeyAgentClient::KeyAgentClient(std::string address, int port, int d, int s, int epsilon) : AgentClient(address, port, d, s) {
    b = ((1 + epsilon)*pow(sidelength,dimension))/d;
    this->epsilon = epsilon;
    this->n = pow(sidelength,dimension);
}

CryptoPP::Integer KeyAgentClient::DoKeyRetrieve(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         std::string key) {
    std::vector<std::vector<int>> to_encode(dimension);
    to_encode[0] = RandVector(hash_key_2,key, dimension);
    int j = partition_hash(hash_key_1,key,b);
    for (int i = 1; i < dimension;i++){
       int j_i =  j/((b/sidelength)+1);
        std::vector<int> v_i(dimension,0);
        v_i[j_i + 1] = 1;
        b = (b/sidelength)+1;
        j = j % b;
        }
    Retrieve(network_driver,crypto_driver,to_encode);

}


void KeyAgentClient::Decrypt() {

}