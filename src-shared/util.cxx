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
 * Converts a byte block into an integer.
 */
CryptoPP::Integer byteblock_to_integer(const CryptoPP::SecByteBlock &block) {
  return CryptoPP::Integer(block, block.size());
}

/**
 * Converts an integer into a byte block.
 */
CryptoPP::SecByteBlock integer_to_byteblock(const CryptoPP::Integer &x) {
  size_t encodedSize = x.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
  CryptoPP::SecByteBlock bytes(NULL, encodedSize);
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
  CryptoPP::SecByteBlock block(reinterpret_cast<const unsigned char *>(&s[0]),
                               s.size());
  return block;
}

/**
 * Prints contents as integer
 */
void print_key_as_int(const CryptoPP::SecByteBlock &block) {
  std::cout << byteblock_to_integer(block) << std::endl;
}

/**
 * Prints contents as hex.
 */
void print_key_as_hex(const CryptoPP::SecByteBlock &block) {
  std::string result;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));

  encoder.Put(block, block.size());
  encoder.MessageEnd();

  std::cout << result << std::endl;
}

/**
 * Concatenates the fields of a message struct for HMAC tagging.
 */
std::string concat_msg_fields(CryptoPP::SecByteBlock iv,
                              CryptoPP::SecByteBlock public_value,
                              std::string ciphertext) {
  CryptoPP::SecByteBlock concated = iv + public_value;
  return std::string((const char *)concated.data(), concated.size()) +
         ciphertext;
}
