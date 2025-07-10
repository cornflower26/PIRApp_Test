//
// Created by TJANUSZEWICZ on 08/07/2025.
//

#include "../../include/pkg/benchmark.hpp"
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
BenchmarkClient::BenchmarkClient(int d, int s) {
  this->dimension = d;
  this->sidelength = s;

  this->hypercube_driver = std::make_shared<HypercubeDriver>(
      d, s, CryptoPP::Integer(PLAINTEXT_MODULUS));
  initLogger();
}


/**
 * Privately retrieve a value from the cloud. This function should:
 * 0) Connect and handle key exchange.
 * 1) Generate parameters, context, and keys. See constants.hpp.
 * 2) Generate a selection vector based on the key's coordinates.
 * 3) Send the selection vector to the server and decode the response.
 */
int BenchmarkClient::get(int index) {
  EncryptionParameters parms(scheme_type::bfv);

  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
  parms.set_plain_modulus((PLAINTEXT_MODULUS));

  SEALContext context(parms);
  seal::Evaluator evaluator(context);

  KeyGenerator keygen(context);
  SecretKey secretKey = keygen.secret_key();

  seal::PublicKey publicKey;
  keygen.create_public_key(publicKey);
  seal::RelinKeys relinKeys;
  keygen.create_relin_keys(relinKeys);

  seal::Encryptor encryptor(context, publicKey);
  seal::Decryptor decryptor(context, secretKey);
  //std::cout << "Generated parameters, context, and keys" << std::endl;

  std::vector<int> coordinates = this->hypercube_driver->to_coords(index);
  std::vector<int> indices(this->dimension*this->sidelength,0);

  std::vector<seal::Ciphertext> query(this->dimension*this->sidelength,Ciphertext());
  //std::cout << "Indices [";
  for (int i = 0; i < indices.size();i++) {
    if (i%this->sidelength == coordinates[i/this->sidelength]) {
      indices[i] = 1;
    }
    //std::cout << " " << indices[i] << ", ";
    seal::Plaintext plain(std::to_string(indices[i]));
    encryptor.encrypt(plain,query[i]);
  }
  //std::cout << "]" << std::endl;
  //std::cout << "Generated a selection vector based on the key's coordinates" << std::endl;

  std::vector<seal::Ciphertext> newCube;
  for (int i = 0; i < dimension; i++) {
    for (int j = 0; j < pow(sidelength,dimension); j++) {
      std::vector<int> coords = hypercube_driver->to_coords(j);
      if (i == 0) {
        seal::Plaintext plaintext(std::to_string(hypercube_driver->get(j).ConvertToLong()));
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
    if (i==0) query_result = newCube[i];
    else evaluator.add_inplace(query_result,newCube[i]);
  }

  seal::Plaintext plaintext;
  decryptor.decrypt(query_result,plaintext);
  //std::cout << "Decoded the response " << plaintext.to_string() << std::endl;
  return stoi(plaintext.to_string());

}

/**
 * Insert a value into the database
 */
void BenchmarkClient::insert(int index, int val) {
  int key = index;
  CryptoPP::Integer value = CryptoPP::Integer(val);
  this->hypercube_driver->insert(key, value);
}

/**
 * Get a file and put all values in the cube
 */
void BenchmarkClient::cube(std::vector<int>& cube) {
    //read_csv_values(input_split[1]);
  for (int i = 0; i < cube.size(); i++) {
    CryptoPP::Integer value = CryptoPP::Integer(cube[i]);
    //std::cout << value << " ";
    this->hypercube_driver->insert(i, value);
  }
}

/**
 * Get a file and put all values in the cube
 */
void BenchmarkClient::cube(std::string filename) {
  std::vector<int> cube = read_csv_values(filename);
  this->cube(cube);
}
