#include "../include-shared/util.hpp"
#include "../include-shared/constants.hpp"

#include <crypto++/osrng.h>

/**
 * Convert char vec to string.
 */
std::string chvec2str(std::vector<unsigned char> data) {
  std::string s(data.begin(), data.end());
  return s;
}

/**
 * Convert string to char vec.
 */
std::vector<unsigned char> str2chvec(std::string s) {
  std::vector<unsigned char> v(s.begin(), s.end());
  return v;
}

/**
 * Convert char vec to string.
 */
std::string hex_encode(std::string s) {
  std::string res;
  CryptoPP::StringSource(
      s, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(res)));
  return res;
}

/**
 * Convert string to char vec.
 */
std::string hex_decode(std::string s) {
  std::string res;
  CryptoPP::StringSource(
      s, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(res)));
  return res;
}

/**
 * Converts a byte block into an integer.
 */
CryptoPP::Integer byteblock_to_integer(CryptoPP::SecByteBlock block) {
  return CryptoPP::Integer(block, block.size());
}

/**
 * Converts an integer into a byte block.
 */
CryptoPP::SecByteBlock integer_to_byteblock(CryptoPP::Integer x) {
  size_t encodedSize = x.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
  CryptoPP::SecByteBlock bytes(encodedSize);
  x.Encode(bytes.BytePtr(), encodedSize, CryptoPP::Integer::UNSIGNED);
  return bytes;
}

/**
 * Converts a byte block into a string.
 */
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block) {
  return std::string(block.begin(), block.end());
}

/**
 * Converts a string into a byte block.
 */
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s) {
  CryptoPP::SecByteBlock block(reinterpret_cast<const CryptoPP::byte *>(&s[0]), s.size());
  return block;
}

/**
 * Given a string, it prints its hex representation of the raw bytes it
 * contains. Used for debugging.
 */
void print_string_as_hex(std::string str) {
  for (int i = 0; i < str.length(); i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(str[i]) << " ";
  }
  std::cout << std::endl;
}

/**
 * Prints contents as integer
 */
void print_key_as_int(CryptoPP::SecByteBlock block) {
  std::cout << byteblock_to_integer(block) << std::endl;
}

/**
 * Prints contents as hex.
 */
void print_key_as_hex(CryptoPP::SecByteBlock block) {
  std::string result;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));

  encoder.Put(block, block.size());
  encoder.MessageEnd();

  std::cout << result << std::endl;
}

/**
 * Split a string.
 */
std::vector<std::string> string_split(std::string str, char delimiter) {
  std::vector<std::string> result;
  // construct a stream from the string
  std::stringstream ss(str);
  std::string s;
  while (std::getline(ss, s, delimiter)) {
    result.push_back(s);
  }
  return result;
}

/**
 * Convert ciphertext to chvec
 */
std::vector<unsigned char> ciphertext_to_chvec(seal::Ciphertext ct) {
  std::stringstream str;
  ct.save(str);
  return str2chvec(str.str());
}

/**
 * Convert chvec to ciphertext
 */
seal::Ciphertext chvec_to_ciphertext(seal::SEALContext ctx,
                                     std::vector<unsigned char> data) {
  std::stringstream str(chvec2str(data));
  seal::Ciphertext ct;
  ct.load(ctx, str);
  return ct;
}

/**
 * Convert RelinKeys to chvec
 */
std::vector<unsigned char> relinkeys_to_chvec(seal::RelinKeys rk) {
  std::stringstream str;
  rk.save(str);
  return str2chvec(str.str());
}

/**
 * Convert chvec to RelinKeys
 */
seal::RelinKeys chvec_to_relinkeys(seal::SEALContext ctx,
                                   std::vector<unsigned char> data) {
  std::stringstream str(chvec2str(data));
  seal::RelinKeys rk;
  rk.load(ctx, str);
  return rk;
}

/**
 * Read CSV file
 * @param filename
 * @return
 */
std::vector<int> read_csv_values(const std::string &filename) {
  std::vector<int> values;
  std::ifstream file(filename);

  if (!file.is_open()) {
    std::cerr << "Error: Unable to open file: " << filename << "\n";
    return values; // Return an empty vector if the file cannot be opened
  }

  std::string line;
  // Read the file line by line
  while (std::getline(file, line)) {
    std::stringstream ss(line);
    std::string value;
    // Split the line by comma
    while (std::getline(ss, value, ',')) {
      //std::cout << stoi(value) << " ";
      values.push_back(stoi(value));
    }
  }

  return values;
}

/**
 * Given the hashkey, the key from the key,value pairing, and b (the number of partitions)
 * this hash function will return which partition the key,value pairing should be placed in
 * @param hashkey
 * @param key
 * @param b
 * @return
 */
int partition_hash(CryptoPP::SecByteBlock hashkey, std::string key, int b) {
  CryptoPP::SipHash<4, 8, true> mac(hashkey.data(), hashkey.size());
  CryptoPP::byte digest[mac.DigestSize()];
  mac.CalculateDigest(digest,(const CryptoPP::byte*)&key[0], key.size());

  CryptoPP::Integer hashval = CryptoPP::Integer(digest, sizeof(digest));
  uint64_t range = static_cast<uint64_t>(b) - static_cast<uint64_t>(0);
  int result = static_cast<int>(hashval % range);
  return result;
}

/**
 * Given the hashkey and the key from the key,value pairing, return a boolean
 * value. This is the hash function then used in the RandVector algorithm
 * @param hashkey
 * @param key
 * @return
 */
bool hash_two(CryptoPP::SecByteBlock hashkey, std::string key) {
  CryptoPP::SipHash<4, 8, true> mac(hashkey.data(), hashkey.size());
  CryptoPP::byte digest[mac.DigestSize()];
  mac.CalculateDigest(digest,(const CryptoPP::byte*)&key[0], key.size());

  CryptoPP::Integer hashval = CryptoPP::Integer(digest, sizeof(digest));
  uint64_t range = static_cast<uint64_t>(1) - static_cast<uint64_t>(0) + 1;
  int result = static_cast<int>(hashval % range);
  return result;
}

/**
 * Given the hashkey, the key and values from the pairing, returns the rep
 * @param hashkey
 * @param key
 * @param value
 * @return
 */
int rep(CryptoPP::SecByteBlock hashkey, std::string key, int value) {
  CryptoPP::SipHash<4, 8, true> mac(hashkey.data(), hashkey.size());
  CryptoPP::byte digest[mac.DigestSize()];
  mac.CalculateDigest(digest,(const CryptoPP::byte*)&key[0], key.size());

  CryptoPP::byte val = CryptoPP::byte(value);

  CryptoPP::byte full_rep[mac.DigestSize()+1];
  for (int i = 0; i < mac.DigestSize(); i++) {
    full_rep[i] = digest[i];
  }
  full_rep[mac.DigestSize()] = val;

  CryptoPP::Integer hashval = CryptoPP::Integer(full_rep, sizeof(digest));
  unsigned int final = hashval.ConvertToLong();
  final = final%1024;
  return final;
}

/**
 * RandVector function according to Algorithm 3 of the SparsePIR paper
 **/
//Original RandVector which doesn't return a correct matrix with high enough probability
std::vector<int> RandVector(CryptoPP::SecByteBlock hash_key, std::string key, int d) {
  std::vector<int> result(d,0);
  for (int i = 0; i < d; i++) {
    result[i] = hash_two(hash_key, key + std::to_string(i));
  }
  return result;
}

/**
 * RandVector function as described in Algorithm 8
 * of the SparsePIR paper
 * @param hash_key
 * @param key
 * @param d
 * @param w
 * @return
 */
std::vector<int> RandVector(CryptoPP::SecByteBlock hash_key, std::string key, int d, int w) {
  std::vector<int> result(d,0);
  int position = partition_hash(hash_key, key, d-w);
  for (int i = 0; i < w; i++) {
    if (i + position < d) result[i + position] = hash_two(hash_key, key + std::to_string(i));
  }
  return result;
}

/**
 * Modified to only choose one index per thing for brute force too hard reasons
 * @param hash_key
 * @param key
 * @param d
 * @param w
 * @return
 */
std::vector<int> RandIndexVector(CryptoPP::SecByteBlock hash_key, std::string key, int d) {
  std::vector<int> result(d,0);
  int position = partition_hash(hash_key, key, d);
  result[position] = 1;
  return result;
}


/**
 * GenerateEncode algorithm according to Algorithm 4
 * in the SparsePIR paper
 * @param hash_key_1
 * @param hash_key_2
 * @param partition
 * @param d
 * @param w (band size for band matrix)
 * @return
 */
std::vector<int> GenerateEncode(CryptoPP::SecByteBlock &hash_key_1, CryptoPP::SecByteBlock hash_key_2, std::vector<std::pair<std::string, int>> partition, int d, int w) {
  boost::numeric::ublas::matrix<double> M (partition.size(),d);
  boost::numeric::ublas::vector<double> y (d,0);
  double determinant = 0;

  int tries = 0;
  //while (determinant != 1 && determinant != -1){
  while (determinant == 0){
    hash_key_1 = SipHash_generate_key();
    //std::cout << "Matrix: " << std::endl;
    for (int i = 0; i < M.size1(); i++) {
      //std::vector<int> rvector = RandVector(hash_key_1, partition[i].first,d);
      std::vector<int> rvector = RandIndexVector(hash_key_1, partition[i].first,d);
      //std::cout << "[ ";
      for (int j = 0; j < rvector.size(); j++) {
        M(i,j) = rvector[j];
        //std::cout << M(i,j) << " ";
      }
      //std::cout << "]" << std::endl;
    }
    determinant = Determinant(M);
    tries++;
  }
  //std::cout << "Final number of tries: " << tries << ", and the final determinant: " << determinant << std::endl;
  //std::cout << "[ ";
  for (int i = 0; i < y.size(); i++) {
    //int reep = rep(hash_key_2, partition[i].first,partition[i].second);
    //y[i] = reep;
    y[i] = partition[i].second;
    //std::cout << y[i] << "," << partition[i].first << " ";
    //M(d,i) = y[i];
  }
  //std::cout << "]" << std::endl;

  return LinearSolve(M, y);
}

/**
* Does Generate Encoding for a matrix mod P
*/
std::vector<int> GenerateModPEncode(CryptoPP::SecByteBlock &hash_key_1, CryptoPP::SecByteBlock hash_key_2, std::vector<std::pair<std::string, int>> partition, int d) {
  NTL::ZZ_p::init(NTL::ZZ(KEYWORD_MODULUS));
  NTL::mat_ZZ_p M;
  M.SetDims(partition.size(),d);
  NTL::vec_ZZ_p y;
  y.SetLength(d);
  NTL::ZZ_p determinant( 0);

  int tries = 0;
  while (determinant == 0){
    if (tries != 0) hash_key_1 = SipHash_generate_key();
    for (int i = 0; i < M.NumCols(); i++) {
      std::vector<int> rvector = RandVector(hash_key_1, partition[i].first,d);
      //std::vector<int> rvector = RandIndexVector(hash_key_1, partition[i].first,d);
      for (int j = 0; j < rvector.size(); j++) {
        M[i][j] = NTL::to_ZZ_p(long(rvector[j]));
      }
    }
    determinant = NTL::determinant(M);
    tries++;
  }
  //std::cout << M << std::endl;
  //std::cout << "Final number of tries: " << tries << ", and the final determinant: " << determinant << std::endl;

  for (int i = 0; i < y.length(); i++) {
    y[i] = NTL::to_ZZ_p(partition[i].second);
  }
  NTL::vec_ZZ_p sol;
  sol.SetLength(y.length());
  NTL::solve(determinant,M,sol,y);

  std::vector<int> x(d);
  for (long i = 0; i < d; ++i) {
    NTL::ZZ temp = NTL::rep(sol[i]);
    x[i] = to_int(temp);
  }
  //std::cout << sol << std::endl;
  return x;
}


/**
 * Does a linear solve of Matrix A and solution vector Y
 * @param A
 * @param y
 * @return
 */
std::vector<int> LinearSolve(boost::numeric::ublas::matrix<double> A, boost::numeric::ublas::vector<double> y) {
  boost::numeric::ublas::permutation_matrix<double> pm(A.size1());
  boost::numeric::ublas::lu_factorize(A, pm);
  boost::numeric::ublas::lu_substitute(A, pm, y);

  std::vector<int> result;
  //std::cout << std::endl << "[ ";
  for (int i = 0; i < y.size(); i++) {
    //std::cout << y[i] << " ";
    result.push_back(int(y[i]));
  }
  //std::cout << "]" << std::endl;
  return result;
}

/**
 * Does not perform linear solve of Matrix A and solution vector Y
 * @param A
 * @param y
 * @return
 */
std::vector<int> ModifiedLinearSolve(boost::numeric::ublas::matrix<double> A, boost::numeric::ublas::vector<double> y) {
  std::cout << "[ ";
  for (int i = 0; i < y.size(); i++) std::cout << y[i] << " ";
  std::cout << "]" << std::endl;
  //boost::numeric::ublas::permutation_matrix<double> pm(A.size1());
  boost::numeric::ublas::lu_factorize(A);
  //boost::numeric::ublas::inplace_solve(pm, A,boost::numeric::ublas::lower_tag ());
  //boost::numeric::ublas::lu_substitute(A, pm, y);
  boost::numeric::ublas::vector<double> x = boost::numeric::ublas::solve(A,y, boost::numeric::ublas::lower_tag ());
  //boost::numeric::ublas::vector<double> x = boost::numeric::ublas::prod(A,y);

  std::vector<int> result;
  std::cout << "[ ";
  for (int i = 0; i < x.size(); i++) {
    std::cout << x[i] << " ";
    result.push_back(int(x[i]));
  }
  std::cout << "]" << std::endl;
  return result;
}

/**
 * generates a hashkey for the SipHash hash function
 * @return
 */
CryptoPP::SecByteBlock SipHash_generate_key() {
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
  prng.GenerateBlock(key, key.size());
  return key;
}

int determinant_sign(const boost::numeric::ublas::permutation_matrix<double>& pm) {
  int pm_sign=1;
  std::size_t size = pm.size();
  for (std::size_t i = 0; i < size; ++i)
    if (i != pm(i))
      pm_sign *= -1.0; // swap_rows would swap a pair of rows here, so we change sign
  return pm_sign;
}

double Determinant( boost::numeric::ublas::matrix<double> m ) {
  boost::numeric::ublas::permutation_matrix<double> pm(m.size1());
  double det = 1.0;
  if( boost::numeric::ublas::lu_factorize(m,pm) ) {
    det = 0.0;
  } else {
    for(int i = 0; i < m.size1(); i++)
      det *= m(i,i); // multiply by elements on diagonal
    det = det * determinant_sign( pm );
  }
  return det;
}


void MatrixPrint(boost::numeric::ublas::matrix<double> A) {
  std::cout << " MATRIX: " << std::endl;
  for (int i = 0; i < A.size1(); i++) {
    std::cout << "[ ";
    for (int j = 0; j < A.size2(); j++) {
      std::cout << A(i,j) << " ";
    }
    std::cout << "]" << std::endl;
  }
}

void VectorPrint(boost::numeric::ublas::vector<double> y) {
  std::cout << " VECTOR: " << std::endl;
  std::cout << "[ ";
  for (int i = 0; i < y.size(); i++) {
    std::cout << y[i] << " ";
  }
  std::cout << "]" << std::endl;
}

void VectorPrint(std::vector<int> y) {
  std::cout << " VECTOR: " << std::endl;
  std::cout << "[ ";
  for (int i = 0; i < y.size(); i++) {
    std::cout << y[i] << " ";
  }
  std::cout << "]" << std::endl;
}

std::vector<int> to_coords(int idx, int s, int d) {
  if (idx > std::pow(s,d)-1)
    throw std::runtime_error("Hypercube out of bounds");

  std::vector<int> res;
  res.resize(d);
  for (int e = d - 1; e >= 0; e--) {
    res[d - e - 1] = 0;
    int step = std::pow(s, e);
    while (idx >= step) {
      idx -= step;
      res[d - e - 1] += 1;
    }
  }
  return res;
}
