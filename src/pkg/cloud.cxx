#include <cmath>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../drivers/repl_driver.cxx"
#include "../../include/pkg/cloud.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}
using namespace seal;

/**
 * Constructor
 */
CloudClient::CloudClient(int d, int s) {
  this->dimension = d;
  this->sidelength = s;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();
  this->hypercube_driver = std::make_shared<HypercubeDriver>(
      d, s, CryptoPP::Integer(PLAINTEXT_MODULUS));
  initLogger();
}

/**
 * run
 */
void CloudClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&CloudClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Run REPL.
  REPLDriver<CloudClient> repl = REPLDriver<CloudClient>(this);
  repl.add_action("insert", "insert <key> <value>", &CloudClient::HandleInsert);
  repl.add_action("get", "get <key>", &CloudClient::HandleGet);
  repl.add_action("cube", "cube <filename>", &CloudClient::HandleCube);
  repl.run();
}

/**
 * Insert a value into the database
 */
void CloudClient::HandleInsert(std::string input) {
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  int key = std::stoi(input_split[1]);
  CryptoPP::Integer value = CryptoPP::Integer(std::stoi(input_split[2]));
  this->hypercube_driver->insert(key, value);
  this->cli_driver->print_success("Inserted value!");
}

/**
 * Get a value from the database
 */
void CloudClient::HandleGet(std::string input) {
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 2) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  int key = std::stoi(input_split[1]);
  CryptoPP::Integer value = this->hypercube_driver->get(key);
  this->cli_driver->print_success("Get value: " + CryptoPP::IntToString(value));
}

/**
 * Get a file and put all values in the cube
 */
void CloudClient::HandleCube(std::string input) {
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 2) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::vector<int> values = read_csv_values(input_split[1]);
  for (int i = 0; i < values.size(); i++) {
    CryptoPP::Integer value = CryptoPP::Integer(values[i]);
    //std::cout << value << " ";
    this->hypercube_driver->insert(i, value);
  }
  this->cli_driver->print_success("Preset Hypercube!");
}

/**
 * Listen for new connections
 */
void CloudClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&CloudClient::HandleSend, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Come to a shared secret
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
CloudClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
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
  return keys;
}

/**
 * Obliviously send a value to the retriever. This function should:
 * 1) Generate parameters and context.
 * 2) Receive the selection vector.
 * 3) Evaluate and return a response using homomorphic operations.
 */
void CloudClient::HandleSend(std::shared_ptr<NetworkDriver> network_driver,
                             std::shared_ptr<CryptoDriver> crypto_driver) {
  // Key exchange with server. From here on out, any outgoing messages should
  // be encrypted and MAC tagged. Incoming messages should be decrypted and have
  // their MAC checked.
  auto keys = this->HandleKeyExchange(network_driver, crypto_driver);
  std::cout << "Key exchange completed" << std::endl;
  std::cout << "AES_key " << byteblock_to_string(keys.first) << std::endl;
  std::cout << "HMAC_key " << byteblock_to_string(keys.second) << std::endl;

  EncryptionParameters parms(scheme_type::bfv);

  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
  parms.set_plain_modulus((PLAINTEXT_MODULUS));

  SEALContext context(parms);
  seal::Evaluator evaluator(context);
  std::cout << "Generated parameters and context " << std::endl;

  std::vector<unsigned char> wrapped_query = network_driver->read();
  std::pair<std::vector<unsigned char>, bool> unwrapped_query = crypto_driver->decrypt_and_verify(keys.first,keys.second,wrapped_query);
  UserToServer_Query_Message query_message;
  query_message.deserialize(unwrapped_query.first,context);
  seal::RelinKeys relinKeys = query_message.rks;
  std::vector<seal::Ciphertext> query = query_message.query;
  std::cout << " Received the selection vector" << std::endl;

  /**
  std::vector<seal::Ciphertext> newCube;
  //std::cout << "Original Cube: [";
  for (int i = 0; i < pow(sidelength,dimension); i++) {
    CryptoPP::Integer element = hypercube_driver->get(i);
    //std::cout << " " << std::to_string(element.ConvertToLong()) << ",";
    seal::Plaintext plaintext(std::to_string(element.ConvertToLong()));
    seal::Ciphertext result;
    evaluator.multiply_plain(query[i/sidelength],plaintext,result);
    newCube.push_back(result);
  }
  //std::cout << "]" << std::endl;

  if (dimension > 1) {
    for (int j = 1; j < dimension; j++) {
      for (int i = 0; i < pow(sidelength,dimension); i++) {
        evaluator.multiply_inplace(newCube[i],query[sidelength*j+i%sidelength]);
        evaluator.relinearize_inplace(newCube[i],relinKeys);
      }
    }
  }**/

  std::vector<seal::Ciphertext> newCube;
  for (int i = 0; i < dimension; i++) {
    for (int j = 0; j < pow(sidelength,dimension); j++) {
      std::vector<int> coords = hypercube_driver->to_coords(j);
      if (i == 0) {
        uint64_t temp = static_cast<uint64_t>(hypercube_driver->get(j).ConvertToLong());
        std::cout << "Multiplying " << std::to_string(hypercube_driver->get(j).ConvertToLong()) << " in hex " << seal::util::uint_to_hex_string(&temp, std::size_t(1)) << std::endl;
        seal::Plaintext plaintext(seal::util::uint_to_hex_string(&temp, std::size_t(1)));
        seal::Ciphertext result;
        evaluator.multiply_plain(query[coords[i]],plaintext,result);
        newCube.push_back(result);
      }
      else {
        evaluator.multiply_inplace(newCube[j],query[sidelength*i+coords[i]]);
        evaluator.relinearize_inplace(newCube[j],relinKeys);
      }

    }
  }

  seal::Ciphertext query_result;
  for (int i = 0; i < pow(sidelength,dimension); i++) {
    if (i==0) {
      query_result = newCube[i];
      std::cout << "Creating new cube" <<std::endl;
    }
    else {
      evaluator.add_inplace(query_result,newCube[i]);
      std::cout << "Inplace add" <<std::endl;
    }
  }

  ServerToUser_Response_Message *message = new ServerToUser_Response_Message();
  message->response = query_result;

  std::vector<unsigned char> final_result = crypto_driver->encrypt_and_tag(keys.first,keys.second,message);
  network_driver->send(final_result);
  std::cout << "Evaluated and returned a response using homomorphic operations" << std::endl;
}


