#include "../../include/pkg/agent.hpp"
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
AgentClient::AgentClient(std::string address, int port, int d, int s) {
  this->address = address;
  this->port = port;
  this->dimension = d;
  this->sidelength = s;

  this->hypercube_driver = std::make_shared<HypercubeDriver>(
      d, s, CryptoPP::Integer(PLAINTEXT_MODULUS));
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();
  initLogger();
}

/**
 * run
 */
void AgentClient::run() {
  REPLDriver<AgentClient> repl = REPLDriver<AgentClient>(this);
  repl.add_action("get", "get <key>", &AgentClient::HandleRetrieve);
  repl.run();
}

/**
 * Come to a shared secret
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
AgentClient::HandleKeyExchange(std::shared_ptr<CryptoDriver> crypto_driver,
                               std::shared_ptr<NetworkDriver> network_driver) {
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
  return keys;
}

/**
 * Privately retrieve a value from the cloud.
 */
void AgentClient::HandleRetrieve(std::string input) {
  // Parse input.
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 2) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  int key = std::stoi(input_split[1]);

  // Call retrieve
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();
  this->DoRetrieve(network_driver, crypto_driver, key);
}

/**
 * Privately retrieve a value from the cloud. This function should:
 * 0) Connect and handle key exchange.
 * 1) Generate parameters, context, and keys. See constants.hpp.
 * 2) Generate a selection vector based on the key's coordinates.
 * 3) Send the selection vector to the server and decode the response.
 */
CryptoPP::Integer
AgentClient::DoRetrieve(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver, int query) {
  // Initialize drivers.
  network_driver->connect(this->address, this->port);

  // Key exchange with server. From here on out, any outgoing messages should
  // be encrypted and MAC tagged. Incoming messages should be decrypted and have
  // their MAC checked.
  auto keys = this->HandleKeyExchange(crypto_driver, network_driver);
  std::cout << "Connected and handled key exchange" << std::endl;
  std::cout << "AES_key " << byteblock_to_string(keys.first) << std::endl;
  std::cout << "HMAC_key " << byteblock_to_string(keys.second) << std::endl;

  EncryptionParameters parms(scheme_type::bfv);

  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
  parms.set_plain_modulus((PLAINTEXT_MODULUS));

  SEALContext context(parms);

  KeyGenerator keygen(context);
  SecretKey secretKey = keygen.secret_key();

  seal::PublicKey publicKey;
  keygen.create_public_key(publicKey);
  seal::RelinKeys relinKeys;
  keygen.create_relin_keys(relinKeys);

  seal::Encryptor encryptor(context, publicKey);
  seal::Decryptor decryptor(context, secretKey);
  std::cout << "Generated parameters, context, and keys" << std::endl;
  std::cout << "\t Polynomial Modulus Degree: " << POLY_MODULUS_DEGREE << std::endl;
  std::cout << "\t Plaintext Modulus Degree: " << PLAINTEXT_MODULUS << std::endl;
  //std::cout << chvec2str(params_to_chvec(parms)) << std::endl;

  std::vector<int> coordinates = this->hypercube_driver->to_coords((query));
  std::vector<int> indices(this->dimension*this->sidelength,0);
  std::cout << "Generating coordinates from index: ";
  std::cout << "( ";
  for (int j = 0; j < coordinates.size();j++) {
      std::cout << coordinates[j] << " ";
  }
  std::cout << ")";
  std::cout << std::endl;

  std::vector<seal::Ciphertext> ciphertexts(this->dimension*this->sidelength,Ciphertext());
  std::cout << "Indices [";
  for (int i = 0; i < indices.size();i++) {
    if (i%this->sidelength == coordinates[i/this->sidelength]) {
      indices[i] = 1;
    }
    std::cout << " " << indices[i] << ", ";
    seal::Plaintext plain(std::to_string(indices[i]));
    encryptor.encrypt(plain,ciphertexts[i]);
  }
  std::cout << "]" << std::endl;

  std::cout << "Ciphertexts: " << std::endl;
  std::cout << "\t Size: " <<  ciphertexts[0].dyn_array().size() << std::endl;
  for (int i = 0; i < ciphertexts.size();i++) {
    auto data = ciphertexts[i].data();
    std::cout << "\t Ciphertext " << i << " : [ " << data[0] << " ... " <<
                    data[ciphertexts[i].dyn_array().size()-1] << " ]" << std::endl;
    //std::cout << chvec2str(ciphertexts[i]) << ", ";
  }
  std::cout << "Generated a selection vector based on the key's coordinates" << std::endl;

  UserToServer_Query_Message *message = new UserToServer_Query_Message();
  message->rks = relinKeys;
  message->query = ciphertexts;

  std::vector<unsigned char> final_query = crypto_driver->encrypt_and_tag(keys.first,keys.second,message);
  network_driver->send(final_query);
  std::cout << "Sent the selection vector to the server" << std::endl;

  std::vector<unsigned char> query_response = network_driver->read();
  std::pair<std::vector<unsigned char>, bool> unwrapped_response = crypto_driver->decrypt_and_verify(keys.first,keys.second,query_response);
  ServerToUser_Response_Message response_message;
  response_message.deserialize(unwrapped_response.first,context);
  seal::Ciphertext response = response_message.response;

  seal::Plaintext plaintext;
  decryptor.decrypt(response,plaintext);
  std::cout << "Decoded the response " << plaintext.to_string() << std::endl;
  return byteblock_to_integer(string_to_byteblock(plaintext.to_string()));
}

void
AgentClient::DoBatchRetrieve(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver, std::vector<int> query) {
  // Initialize drivers.
  network_driver->connect(this->address, this->port);

  // Key exchange with server. From here on out, any outgoing messages should
  // be encrypted and MAC tagged. Incoming messages should be decrypted and have
  // their MAC checked.
  auto keys = this->HandleKeyExchange(crypto_driver, network_driver);
  std::cout << "Connected and handled key exchange" << std::endl;
  std::cout << "AES_key " << byteblock_to_string(keys.first) << std::endl;
  std::cout << "HMAC_key " << byteblock_to_string(keys.second) << std::endl;

  EncryptionParameters parms(scheme_type::bfv);

  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
  parms.set_plain_modulus((PLAINTEXT_MODULUS));

  SEALContext context(parms);

  KeyGenerator keygen(context);
  SecretKey secretKey = keygen.secret_key();

  seal::PublicKey publicKey;
  keygen.create_public_key(publicKey);
  seal::RelinKeys relinKeys;
  keygen.create_relin_keys(relinKeys);

  seal::Encryptor encryptor(context, publicKey);
  seal::Decryptor decryptor(context, secretKey);
  std::cout << "Generated parameters, context, and keys" << std::endl;

  std::cout << " Generating coordinates from index: ";
  std::vector<std::vector<int>> coordinates;
  for (int i = 0; i < query.size();i++) {
    coordinates.push_back(this->hypercube_driver->to_coords((query[i])));
    std::cout << "( ";
    for (int j = 0; j < coordinates.size();j++) {
      std::cout << coordinates[i][j];
    }
    std::cout << " )";
  }
  std::cout << std::endl;

  std::vector<int> indices(this->dimension*this->sidelength,0);

  std::vector<seal::Ciphertext> ciphertexts(this->dimension*this->sidelength,Ciphertext());
  std::cout << "Indices [";
  for (int i = 0; i < indices.size();i++) {
    for (int j = 0; j < coordinates.size(); j++) {
      if (i%this->sidelength == coordinates[j][i/this->sidelength]) {
        indices[i] = 1;
      }
    }
    std::cout << " " << indices[i] << ", ";
    seal::Plaintext plain(std::to_string(indices[i]));
    encryptor.encrypt(plain,ciphertexts[i]);
  }
  std::cout << "]" << std::endl;
  std::cout << "Generated a selection vector based on the key's coordinates" << std::endl;


  std::cout << "Ciphertexts [";
  for (int i = 0; i < ciphertexts.size();i++) {
    std::cout << chvec2str(ciphertext_to_chvec(ciphertexts[i])) << ", ";
    //std::vector<unsigned char> cipher = ciphertext_to_chvec(ciphertexts[i]);
    //std::cout << " ";
    //for (int j = 0; j < cipher.size(); j++) std::cout << cipher[i] << " ";
    //std::cout <<" ,";
  }
  std::cout << "]" << std::endl;
  std::cout << "Generated a selection vector based on the key's coordinates" << std::endl;


  UserToServer_Query_Message *message = new UserToServer_Query_Message();
  message->rks = relinKeys;
  message->query = ciphertexts;

  std::vector<unsigned char> final_query = crypto_driver->encrypt_and_tag(keys.first,keys.second,message);
  network_driver->send(final_query);
  std::cout << "Sent the selection vector to the server" << std::endl;

  std::vector<unsigned char> query_response = network_driver->read();
  std::pair<std::vector<unsigned char>, bool> unwrapped_response = crypto_driver->decrypt_and_verify(keys.first,keys.second,query_response);
  ServerToUser_Response_Message response_message;
  response_message.deserialize(unwrapped_response.first,context);
  seal::Ciphertext response = response_message.response;

  seal::Plaintext plaintext;
  decryptor.decrypt(response,plaintext);
  std::cout << "Decoded the response " << plaintext.to_string() << std::endl;
  //return byteblock_to_integer(string_to_byteblock(plaintext.to_string()));
}