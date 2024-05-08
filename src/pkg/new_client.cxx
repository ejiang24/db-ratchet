#include "../../include/pkg/new_client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.
 * @param port Port to listen on or connect to.
 */
NewClient::NewClient(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<NewCryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void NewClient::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  CryptoPP::SecByteBlock secret_key = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);

  CryptoPP::SecByteBlock aes_key = this->crypto_driver->AES_generate_key(secret_key);
  CryptoPP::SecByteBlock hmac_key = this->crypto_driver->HMAC_generate_key(secret_key);

  this->AES_key = aes_key;
  this->HMAC_key = hmac_key;
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message NewClient::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);// TODO: implement me!

  //first message
  if (this->DH_switched = true) {
    auto [dh_obj, prv, pub] = this->crypto_driver->DH_initialize(this->DH_params);
    this->DH_current_private_value = prv;
    this->DH_current_public_value = pub;
    this->prepare_keys(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);

    this->DH_switched = false;
  }

  // TODO: FIX lol
  auto [ciphertext, iv] = this->crypto_driver->AES_encrypt(this->AES_key, plaintext);
  std::string to_tag = concat_msg_fields(iv, this->DH_current_public_value, ciphertext);
  std::string tag = this->crypto_driver->HMAC_generate(this->HMAC_key, to_tag);

  Message_Message res;
  res.iv = iv;
  res.public_value = this->DH_current_public_value;
  res.ciphertext = ciphertext;
  res.mac = tag;
  return res;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> NewClient::receive(Message_Message msg) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  //if pub values are diff ==> if new one has been sent
  if (msg.public_value != this->DH_last_other_public_value) {
    auto [dh_obj, prv, pub] = this->crypto_driver->DH_initialize(this->DH_params);
    this->DH_last_other_public_value = msg.public_value;
    this->prepare_keys(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);
    
    this->DH_switched = true;
  }

  std::string to_decrypt = concat_msg_fields(msg.iv, msg.public_value, msg.ciphertext);
  std::string decrypted = this->crypto_driver->AES_decrypt(this->AES_key, msg.iv, msg.ciphertext); //key, iv, ciphertext 
  bool is_valid = this->crypto_driver->HMAC_verify(this->HMAC_key, to_decrypt, msg.mac);

  return {decrypted, is_valid};
}

/**
 * Run the client.
 */
void NewClient::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&NewClient::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`.
 * `command` can be either "listen" or "connect"; the listener should `read()`
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void NewClient::HandleKeyExchange(std::string command) {

    // TODO: RatchetInit
  DHParams_Message params;
  if (command == "listen") { // Alice
    this->cli_driver->print_warning("aliceeeeeeeee");
    // WAITS FOR BOB
    std::vector<unsigned char> vctr = this->network_driver->read();
    params.deserialize(vctr);
    this->DH_params = params;

    //make Alice's keys
    auto [dh_obj, prv_key, pub_key] = this->crypto_driver->DH_initialize(params);
    // making DHs
    this->DH_current_public_value = pub_key;
    this->DH_current_private_value = prv_key;

    // Alice sends her own public key? Bob can always store it for later lol (Does it matter?)
    PublicValue_Message pub_msg;
    pub_msg.public_value = this->DH_current_public_value;
    std::vector<unsigned char> pub_to_send;
    pub_msg.serialize(pub_to_send);
    this->network_driver->send(pub_to_send);

    // getting DHr (receiving DH value, the other public value)
    std::vector<unsigned char> other_pub = this->network_driver->read();
    PublicValue_Message other_pub_msg;
    other_pub_msg.deserialize(other_pub);
    this->DH_last_other_public_value = other_pub_msg.public_value;

    CryptoPP::SecByteBlock secret_key = this->crypto_driver->DH_generate_shared_key(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);
    // for ease, use shared secret as the original root key (which must be agreed upon)
    auto[new_rk, new_cks] = this->crypto_driver->KDF_RK(secret_key, secret_key);

    this->rk = new_rk;
    this->ck_sending = new_cks;
    // this->ck_receiving = SecByteBlock(NULL); // TODO: if this causes issues, fix it lol
    this->msg_num_sending = 0;
    this->msg_num_receiving = 0;
    this->prev_chain_num = 0;
    // this->mskipped = {};

  }
  else if (command == "connect") {
    params = this->crypto_driver->DH_generate_params();
    this->DH_params = params;
    std::vector<unsigned char> vctr;
    this->DH_params.serialize(vctr);
    this->network_driver->send(vctr);

    //make Bob's keys
    auto [dh_obj, prv_key, pub_key] = this->crypto_driver->DH_initialize(params);
    // making DHs
    this->DH_current_public_value = pub_key;
    this->DH_current_private_value = prv_key;

    // sends bob pub key
    PublicValue_Message pub_msg;
    pub_msg.public_value = this->DH_current_public_value;
    std::vector<unsigned char> pub_to_send;
    pub_msg.serialize(pub_to_send);
    this->network_driver->send(pub_to_send);

    // get alice pub key
    std::vector<unsigned char> other_pub = this->network_driver->read();
    PublicValue_Message other_pub_msg;
    other_pub_msg.deserialize(other_pub);
    this->DH_last_other_public_value = other_pub_msg.public_value;

    CryptoPP::SecByteBlock secret_key = this->crypto_driver->DH_generate_shared_key(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);
    // bob receives first 
    // auto[new_rk, new_ckr] = this->crypto_driver->KDF_RK(secret_key, secret_key);
    this->rk = secret_key;
    // this->ck_sending = SecByteBlock(NULL);
    // this->ck_receiving = SecByteBlock(NULL);
    this->msg_num_sending = 0;
    this->msg_num_receiving = 0;
    this->prev_chain_num = 0;
    // this->mskipped = {};
    

  }

  // TODO: deal with later?
  //set DH_switched
  this->DH_switched  = true;


}

/**
 * Listen for messages and print to cli_driver.
 */
void NewClient::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void NewClient::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}



void NewClient::DHRatchetStep(Header header) {
    this->prev_chain_num = this->msg_num_sending;

    // reset
    this->msg_num_sending = 0;
    this->msg_num_receiving = 0;

    // update stored other public value
    this->DH_last_other_public_value = header.DH_public_val;

    // redundant? but need the dh_obj, these ideally are old keys and should be same dh_obj
    auto[dh_obj, prv, pub] = this->crypto_driver->DH_initialize(this->DH_params);
    auto[new_rk, new_ckr] = this->crypto_driver->KDF_RK(this->rk, this->crypto_driver->DH_generate_shared_key(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value));
    this->rk = new_rk;
    this->ck_receiving = new_ckr;

    DHParams_Message new_params = this->crypto_driver->DH_generate_params();
    auto[new_dh_obj, new_prv, new_pub] = this->crypto_driver->DH_initialize(new_params);
    // probably need to update this in the state? 

    auto[new_new_rk, new_cks] = this->crypto_driver->KDF_RK(this->rk, this->crypto_driver->DH_generate_shared_key(new_dh_obj, new_prv, this->DH_last_other_public_value));

    //generate_DH returns new Diffie Hellman key pair
    //dh returns the shared secret

}