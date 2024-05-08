#include "../include-shared/messages.hpp"

#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Put string into data; prepend with length
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Put bigint into data; prepend with length
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the next string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// MESSAGES
// ================================================

/**
 * Serialize DHParams_Message.
 */
void DHParams_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::DHParams_Message);

  // Add fields.
  put_integer(this->p, data);
  put_integer(this->q, data);
  put_integer(this->g, data);
}

/**
 * Deserialize DHParams_Message.
 */
int DHParams_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(get_message_type(data) == MessageType::DHParams_Message);

  // Get fields.
  int n = 1;
  n += get_integer(&this->p, data, n);
  n += get_integer(&this->q, data, n);
  n += get_integer(&this->g, data, n);
  return n;
}

/**
 * Serialize Message.
 */
void PublicValue_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::PublicValue);

  // Add fields.
  std::string public_integer = byteblock_to_string(this->public_value);
  put_string(public_integer, data);
}

/**
 * Deserialize Message.
 */
int PublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(get_message_type(data) == MessageType::PublicValue);

  // Get fields.
  std::string public_integer;
  int n = 1;
  n += get_string(&public_integer, data, n);
  this->public_value = string_to_byteblock(public_integer);
  return n;
}

/**
 * Serialize Message.
 */
void Message_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Message);

  // Add fields.
  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);
  std::string public_integer = byteblock_to_string(this->public_value);
  put_string(public_integer, data);
  put_string(this->ciphertext, data);
  put_string(this->mac, data);
}

/**
 * Deserialize Message.
 */
int Message_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(get_message_type(data) == MessageType::Message);

  // Get fields.
  int n = 1;
  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);
  std::string public_integer;
  n += get_string(&public_integer, data, n);
  this->public_value = string_to_byteblock(public_integer);
  n += get_string(&this->ciphertext, data, n);
  n += get_string(&this->mac, data, n);
  return n;
}
