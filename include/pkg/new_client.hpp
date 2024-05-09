#pragma once

#include <iostream>
#include <mutex>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/new_crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class NewClient {
public:
  NewClient(std::shared_ptr<NetworkDriver> network_driver,
         std::shared_ptr<NewCryptoDriver> crypto_driver);
  void prepare_keys(CryptoPP::DH DH_obj,
                    CryptoPP::SecByteBlock DH_private_value,
                    CryptoPP::SecByteBlock DH_other_public_value);
  DB_Ratchet_Message send(std::string plaintext);
  std::pair<std::string, bool> receive(DB_Ratchet_Message ciphertext);
  void run(std::string command);
  void HandleKeyExchange(std::string command);

  void DHRatchetStep(Header header);
  std::pair<Header, std::pair<std::string, std::string>> ratchet_encrypt(std::string pt, std::string AD);
  Header create_header(SecByteBlock DHs, Integer PN, Integer Ns);
  std::string concat(std::string ad, Header header);
  std::string ratchet_decrypt(Header header, std::string ct, std::string AD);
  std::string try_skipped_message_keys(Header header, std::string ct, std::string AD);
  void skip_message_keys(CryptoPP::Integer until);

private:
  void ReceiveThread();
  void SendThread();

  std::mutex mtx;

  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<NewCryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  SecByteBlock AES_key;
  SecByteBlock HMAC_key;

  // DH Ratchet Fields
  DHParams_Message DH_params;
  bool DH_switched;
  SecByteBlock DH_current_private_value;
  SecByteBlock DH_current_public_value;
  SecByteBlock DH_last_other_public_value;

  SecByteBlock rk;
  SecByteBlock ck_sending;
  SecByteBlock ck_receiving;
  Integer msg_num_sending;
  Integer msg_num_receiving;
  Integer prev_chain_num;
  // std::map<std::pair<SecByteBlock, Integer>, SecByteBlock> mskipped;
  std::map<CryptoPP::Integer, CryptoPP::Integer> mskipped;

};
