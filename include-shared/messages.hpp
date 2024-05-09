#pragma once

#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/integer.h>

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  DHParams_Message = 0,
  PublicValue = 1,
  Message = 2,
  DB_Ratchet = 3,
  Header = 4
};
}
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// Serializers.
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// Deserializers.
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// MESSAGES
// ================================================

struct DHParams_Message : public Serializable {
  CryptoPP::Integer p;
  CryptoPP::Integer q;
  CryptoPP::Integer g;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct PublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Message_Message : public Serializable {
  CryptoPP::SecByteBlock iv;
  CryptoPP::SecByteBlock public_value;
  std::string ciphertext;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Header : public Serializable{
  CryptoPP::SecByteBlock DH_public_val;
  CryptoPP::Integer pn;
  CryptoPP::Integer ns;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct DB_Ratchet_Message : public Serializable {
  Header header; // header has the public value
  std::string mac;
  std::string ciphertext;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};



