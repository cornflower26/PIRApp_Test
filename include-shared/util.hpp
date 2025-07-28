#pragma once

#include <iomanip>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "seal/seal.h"
#include "boost/numeric/ublas/matrix.hpp"
#include "boost/numeric/ublas/matrix_expression.hpp"
#include "boost/numeric/ublas/lu.hpp"
#include "boost/qvm/mat.hpp"
#include "boost/qvm/mat_operations.hpp"

#include <crypto++/cryptlib.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/misc.h>
#include <crypto++/sha.h>
#include <crypto++/siphash.h>

#include <NTL/matrix.h>
#include <NTL/vec_vec_ZZ_p.h>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>

// String <=> Vec<char>.
std::string chvec2str(std::vector<unsigned char> data);
std::vector<unsigned char> str2chvec(std::string s);

// String <=> Hex.
std::string hex_encode(std::string s);
std::string hex_decode(std::string s);

// SecByteBlock <=> Integer.
CryptoPP::Integer byteblock_to_integer(CryptoPP::SecByteBlock block);
CryptoPP::SecByteBlock integer_to_byteblock(CryptoPP::Integer x);

// SecByteBlock <=> string.
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s);

// Printers.
void print_string_as_hex(std::string str);
void print_key_as_int(CryptoPP::SecByteBlock block);
void print_key_as_hex(CryptoPP::SecByteBlock block);

//HashFunctions
int partition_hash(CryptoPP::SecByteBlock hashkey, std::string key, int b);
bool hash_two(CryptoPP::SecByteBlock hashkey, std::string key);
int rep(CryptoPP::SecByteBlock hashkey, std::string key, int value);

// Splitter.
std::vector<std::string> string_split(std::string str, char delimiter);

// BGV conversions
std::vector<unsigned char> params_to_chvec(seal::EncryptionParameters params);
seal::EncryptionParameters chvec_to_params(std::vector<unsigned char> data);
std::vector<unsigned char> pubkey_to_chvec(seal::PublicKey pk);
seal::PublicKey chvec_to_pubkey(seal::SEALContext ctx,
                                std::vector<unsigned char> data);
std::vector<unsigned char> ciphertext_to_chvec(seal::Ciphertext ct);
seal::Ciphertext chvec_to_ciphertext(seal::SEALContext ctx,
                                     std::vector<unsigned char> data);
std::vector<unsigned char> relinkeys_to_chvec(seal::RelinKeys rk);
seal::RelinKeys chvec_to_relinkeys(seal::SEALContext ctx,
                                   std::vector<unsigned char> data);

//Other
std::vector<int> read_csv_values(const std::string &filename);
std::vector<int> RandVector(CryptoPP::SecByteBlock hash_key, std::string key, int d);
std::vector<int> RandVector(CryptoPP::SecByteBlock hash_key, std::string key, int d, int w);
std::vector<int> RandIndexVector(CryptoPP::SecByteBlock hash_key, std::string key, int d);
std::vector<int> GenerateEncode(CryptoPP::SecByteBlock &hash_key_1, CryptoPP::SecByteBlock hash_key_2, std::vector<std::pair<std::string, int>> partition, int d, int w);
std::vector<int> GenerateModPEncode(CryptoPP::SecByteBlock &hash_key_1, CryptoPP::SecByteBlock hash_key_2, std::vector<std::pair<std::string, int>> partition, int d);
CryptoPP::SecByteBlock SipHash_generate_key();

//Matrix operations
int determinant_sign(const boost::numeric::ublas::permutation_matrix<double>& pm);
double Determinant( boost::numeric::ublas::matrix<double> m );
std::vector<int> LinearSolve(boost::numeric::ublas::matrix<double> A, boost::numeric::ublas::vector<double> y);
std::vector<int> ModifiedLinearSolve(boost::numeric::ublas::matrix<double> A, boost::numeric::ublas::vector<double> y);
void MatrixPrint(boost::numeric::ublas::matrix<double> A);
void VectorPrint(boost::numeric::ublas::vector<double> y);