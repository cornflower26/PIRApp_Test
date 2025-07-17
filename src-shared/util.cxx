#include "../include-shared/util.hpp"

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

int partition_hash(CryptoPP::SecByteBlock hashkey, std::string key, int b) {
  CryptoPP::SipHash<4, 8, true> mac(hashkey.data(), hashkey.size());
  CryptoPP::byte digest[mac.DigestSize()];
  mac.CalculateDigest(digest,(const CryptoPP::byte*)&key[0], key.size());

  CryptoPP::Integer hashval = CryptoPP::Integer(digest, sizeof(digest));
  uint64_t range = static_cast<uint64_t>(b) - static_cast<uint64_t>(0) + 1;
  int result = static_cast<int>(hashval % range);
  return result;
}

bool hash_two(CryptoPP::SecByteBlock hashkey, std::string key) {
  CryptoPP::SipHash<4, 8, true> mac(hashkey.data(), hashkey.size());
  CryptoPP::byte digest[mac.DigestSize()];
  mac.CalculateDigest(digest,(const CryptoPP::byte*)&key[0], key.size());

  CryptoPP::Integer hashval = CryptoPP::Integer(digest, sizeof(digest));
  uint64_t range = static_cast<uint64_t>(1) - static_cast<uint64_t>(0) + 1;
  int result = static_cast<int>(hashval % range);
  return result;
}

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
  return hashval.ConvertToLong();
}


std::vector<int> RandVector(CryptoPP::SecByteBlock hash_key, std::string key, int d) {
  std::vector<int> result(d,0);
  for (int i = 0; i < d; i++) {
    result[i] = hash_two(hash_key, key + std::to_string(i));
  }
  return result;
}

std::vector<int> GenerateEncode(CryptoPP::SecByteBlock hash_key_1, CryptoPP::SecByteBlock hash_key_2, std::vector<std::pair<std::string, int>> partition, int d) {
  boost::numeric::ublas::matrix<int> M (partition.size(),d);
  std::vector<int> reps;
  for (int i = 0; i < partition.size(); i++) {
    std::vector<int> rvector = RandVector(hash_key_2, partition[i].first,d);
    for (int j = 0; j < d; j++) {
      M(i,j) = rvector[j];
    }
    reps.push_back(rep(hash_key_2, partition[i].first,partition[i].second));
  }
  return LinearSolve(M, reps);
}

std::vector<int> LinearSolve(boost::numeric::ublas::matrix<int> A, std::vector<int> sol) {
  boost::numeric::ublas::vector<int> y;
  boost::numeric::ublas::permutation_matrix<int> pm(A.size1());
  boost::numeric::ublas::lu_factorize(A, pm);
  boost::numeric::ublas::lu_substitute(A, pm, y);

  std::vector<int> result;
  for (int i = 0; i < y.size(); i++) {
    result.push_back(y[i]);
  }
  return result;
}
