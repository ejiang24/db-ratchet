#pragma once

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>

// String <=> Vec<char>.
std::string chvec2str(std::vector<unsigned char> data);
std::vector<unsigned char> str2chvec(std::string s);

// SecByteBlock <=> Integer.
CryptoPP::Integer byteblock_to_integer(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock integer_to_byteblock(const CryptoPP::Integer &x);

// SecByteBlock <=> string.
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s);

// Printers.
void print_key_as_int(const CryptoPP::SecByteBlock &block);
void print_key_as_hex(const CryptoPP::SecByteBlock &block);

// Concat ciphertext and iv.
std::string concat_msg_fields(CryptoPP::SecByteBlock iv,
                              CryptoPP::SecByteBlock public_value,
                              std::string ciphertext);
