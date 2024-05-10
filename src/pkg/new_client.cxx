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

#include <thread>

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
 * Updated Send function!
 * This is a lot simpler than the one completed in Project 1, as most of the
 * low level complexity has been extracted to ratchet_encrypt.
 * 
 * This function encrypts the plaintext and returns it as a Double Ratchet Message struct
 * with a header, ciphertext, and MAC.
 * 
 * @return DB_Ratchet_Message struct with header, ciphertext, and MAC
 */
DB_Ratchet_Message NewClient::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Sends the message
  DB_Ratchet_Message res;
  auto[header, ct_hmac] = ratchet_encrypt(plaintext, "");
  res.header = header;
  res.ciphertext = ct_hmac.first;
  res.mac = ct_hmac.second;

  return res;
}

/**
 * Updated Receive function!
 * Also a lot simpler than the Project 1 implementation, extracts most of the
 * functionality into ratchet decrypt. If the MAC is invalid, the function will return
 * that as part of the pair.
 * @return Pair of decrypted message and boolean indicating if the MAC was valid
 */
std::pair<std::string, bool> NewClient::receive(DB_Ratchet_Message msg) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string dec = ratchet_decrypt(msg.header, msg.ciphertext, "");
  bool is_valid = this->crypto_driver->HMAC_verify(this->HMAC_key, concat("", msg.header) + msg.ciphertext, msg.mac);

  return {dec, is_valid};
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
 * Updated KeyExchange protocol.
 * 
 * This follows the RatchetInit methods explained in Perrin and Marlinspike's paper.
 * 
 * The "listen" thread is treated as "Alice" and the "connect" thread is treated as "Bob".
 */
void NewClient::HandleKeyExchange(std::string command) {

  DHParams_Message params;
  if (command == "listen") { // Alice
    // Waits for Bob's message with the DH params
    std::vector<unsigned char> vctr = this->network_driver->read();
    params.deserialize(vctr);
    this->DH_params = params;

    // Makes Alice's Keys
    auto [dh_obj, prv_key, pub_key] = this->crypto_driver->DH_initialize(params);
    // making DHs
    this->DH_current_public_value = pub_key;
    this->DH_current_private_value = prv_key;

    // Alice sends her public key to Bob
    PublicValue_Message pub_msg;
    pub_msg.public_value = this->DH_current_public_value;
    std::vector<unsigned char> pub_to_send;
    pub_msg.serialize(pub_to_send);
    this->network_driver->send(pub_to_send);

    // Getting DHr (receiving DH value, the other public value)
    std::vector<unsigned char> other_pub = this->network_driver->read();
    PublicValue_Message other_pub_msg;
    other_pub_msg.deserialize(other_pub);
    this->DH_last_other_public_value = other_pub_msg.public_value;

    // Generates a shared secret key.
    CryptoPP::SecByteBlock secret_key = this->crypto_driver->DH_generate_shared_key(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);
    this->cli_driver->print_info("HandleKeyExchange: Alice generated a shared secret: ");
    print_key_as_int(secret_key);

    // Generates preliminary root key and sending chain key
    // Note: In the paper, Alice and Bob start with a separate shared secret not generated from
    // a DH exchange. To make the implementation simpler, we use the same DH shared secret for 
    // both the root key and the secret key
    auto[new_rk, new_cks] = this->crypto_driver->KDF_RK(secret_key, secret_key);
    this->rk = new_rk;
    this->ck_sending = new_cks;

    this->cli_driver->print_info("HandleKeyExchange: Alice's preliminary ck_sending: ");
    print_key_as_int(new_cks);
    // Initializes message counters
    this->msg_num_sending = 0;
    this->msg_num_receiving = 0;
    this->prev_chain_num = 0;
  }
  else if (command == "connect") { // Bob
    // Generates DH params and sends them to Alice
    params = this->crypto_driver->DH_generate_params();
    this->DH_params = params;
    std::vector<unsigned char> vctr;
    this->DH_params.serialize(vctr);
    this->network_driver->send(vctr);

    // Make Bob's private and public keys
    auto [dh_obj, prv_key, pub_key] = this->crypto_driver->DH_initialize(params);
    this->DH_current_public_value = pub_key;
    this->DH_current_private_value = prv_key;

    // Sends Bob's public key to Alice
    PublicValue_Message pub_msg;
    pub_msg.public_value = this->DH_current_public_value;
    std::vector<unsigned char> pub_to_send;
    pub_msg.serialize(pub_to_send);
    this->network_driver->send(pub_to_send);

    // Receives Alice's public key
    std::vector<unsigned char> other_pub = this->network_driver->read();
    PublicValue_Message other_pub_msg;
    other_pub_msg.deserialize(other_pub);
    this->DH_last_other_public_value = other_pub_msg.public_value;

    // Generates a shared secret key.
    CryptoPP::SecByteBlock secret_key = this->crypto_driver->DH_generate_shared_key(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);
    this->cli_driver->print_info("HandleKeyExchange: Bob generated a shared secret: ");
    print_key_as_int(secret_key);

    // This differs from the paper's implementation of RatchetInitBob
    // In order to start our DH Ratchet, we need Bob to generate a new receiving chain key and root key
    // See note above about the use of two secret keys
    auto[new_rk, new_ckr] = this->crypto_driver->KDF_RK(secret_key, secret_key);
    this->rk = new_rk;
    this->ck_receiving = new_ckr;

    // Bob then generates a new private and public key to create his own sending key
    auto [new_dh_obj, new_prv_key, new_pub_key] = this->crypto_driver->DH_initialize(params);
    this->DH_current_public_value = new_pub_key;
    this->DH_current_private_value = new_prv_key;

    // Make a new shared key
    // Bob is now "one step ahead" of Alice as he has the old receiving chain key and the new sending chain key
    CryptoPP::SecByteBlock new_secret_key = this->crypto_driver->DH_generate_shared_key(new_dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);
    auto[newer_rk, new_cks] = this->crypto_driver->KDF_RK(this->rk, new_secret_key);
    this->rk = newer_rk;
    this->ck_sending = new_cks;
  
    this->cli_driver->print_info("HandleKeyExchange: Bob's preliminary ck_receiving: ");
    print_key_as_int(this->ck_receiving);
    this->cli_driver->print_info("HandleKeyExchange: Bob's preliminary ck_sending: ");
    print_key_as_int(this->ck_sending);

    // Initializes message counters
    this->msg_num_sending = 0;
    this->msg_num_receiving = 0;
    this->prev_chain_num = 0;
  }
}

/**
 * Implementation of a DHRatchetStep (DHRatchet from the paper)
 * 
 */
void NewClient::DHRatchetStep(Header header) {
    this->cli_driver->print_info("DHRatchetStep: Commencing a DH Ratchet step");
    this->prev_chain_num = this->msg_num_sending;
    // Resets the sending and receiving message counters
    this->msg_num_sending = 0;
    this->msg_num_receiving = 0;

    // Updates the last public key
    this->DH_last_other_public_value = header.DH_public_val;

    auto[dh_obj, prv, pub] = this->crypto_driver->DH_initialize(this->DH_params);

    // Generates the receiving chain key based on the old private value and the received public value
    auto[new_rk, new_ckr] = this->crypto_driver->KDF_RK(this->rk, this->crypto_driver->DH_generate_shared_key(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value));
    this->rk = new_rk;
    this->ck_receiving = new_ckr; // used to decrypt the incoming message from Bob (with new public ratchet)
    this->cli_driver->print_info("DHRatchetStep: New ck_receiving: ");
    print_key_as_int(new_ckr);

    // Sets current public and private values (DHs)
    this->DH_current_public_value = pub;
    this->DH_current_private_value = prv;

    // Generates the new sending chain key based on the newly generated private key and the received public key
    auto[new_new_rk, new_cks] = this->crypto_driver->KDF_RK(this->rk, this->crypto_driver->DH_generate_shared_key(dh_obj, prv, this->DH_last_other_public_value));
    this->rk = new_new_rk;
    this->ck_sending = new_cks;
    this->cli_driver->print_info("DHRatchetStep: New ck_sending: ");
    print_key_as_int(new_cks);
}

/**
 * Implementation of RatchetEncrypt from the paper
 * @return Pair of header and pair of ciphertext and MAC
 */
std::pair<Header, std::pair<std::string, std::string>> NewClient::ratchet_encrypt(std::string pt, std::string AD) {
  // Generates a new sending chain key and message key
  // (This is a symmetric key ratchet step)
  this->cli_driver->print_info("RatchetEncrypt: Commencing a symmetric key ratchet");
  auto[new_cks, new_mk] = this->crypto_driver->KDF_CK(this->ck_sending);
  this->ck_sending = new_cks;
  this->cli_driver->print_info("RatchetEncrypt: New ck_sending: ");
  print_key_as_int(new_cks);
  this->cli_driver->print_info("RatchetEncrypt: New Message Key: ");
  print_key_as_int(new_mk);
  printf("\n");

  // Creates a header with the current public value, the previous chain number, and the current message number
  Header header = create_header(this->DH_current_public_value, this->prev_chain_num, this->msg_num_sending);
  this->msg_num_sending++;

  // Encrypts the ciphertext
  auto[ct, mac] = this->crypto_driver->encrypt(new_mk, pt, concat(AD, header));
  return {header, {ct,mac}};
}

/**
 * Concatenates associated data to the header as a string
 * @return Concatenated string
*/
std::string NewClient::concat(std::string ad, Header header) {
  SecByteBlock concated = header.DH_public_val + integer_to_byteblock(header.pn) + integer_to_byteblock(header.ns);
  return ad + byteblock_to_string(concated); 
}

/**
 * Helper function to initialize a Header
*/
Header NewClient::create_header(SecByteBlock DHs, Integer PN, Integer Ns) {
  Header res;
  res.DH_public_val = DHs;
  res.pn = PN;
  res.ns = Ns;
  return res;
}

/**
 * Implementation of RatcetDecrypt from the paper
 * @return Decrypted plaintext
 */
std::string NewClient::ratchet_decrypt(Header header, std::string ct, std::string AD){
  // Tries skipped messages first
  std::string plaintext = try_skipped_message_keys(header,ct,AD);
  if (plaintext != ""){
    return plaintext;
  }

  // Check if a DHRatchet step needs to be taken
  // Note in Project 1, this was done with a DH_swapped flag
  if (header.DH_public_val != this->DH_last_other_public_value){
    this->cli_driver->print_info("RatchetDecrypt: Received a new public key, will take a DHRatchetStep ");
    // Stores skipped messages to be decrypted later
    skip_message_keys(header.pn);
    DHRatchetStep(header);
  }
  // Stores skipped messages then performs a symmetric-key step to derive the message key and receiving chain key
  skip_message_keys(header.ns);
  auto[new_ckr, new_mk] = this->crypto_driver->KDF_CK(this->ck_receiving);
  this->ck_receiving = new_ckr;
  this->msg_num_receiving++;

  this->cli_driver->print_info("RatchetDecrypt: Commencing a symmetric key ratchet");
  this->cli_driver->print_info("RatchetDecrypt: New ck_receiving: ");
  print_key_as_int(new_ckr);
  this->cli_driver->print_info("RatchetDecrypt: New Message Key: ");
  print_key_as_int(new_mk);
  printf("\n");

  // Decrypts the message
  auto[dec, hmac] = this->crypto_driver->decrypt(new_mk, ct, concat(AD, header));
  this->HMAC_key = hmac;
  return dec;

}
/**
 * Implementation of TrySkippedMessageKeys from the paper
 * This method is used to decrypt messages that were skipped because they arrived out of order
 * @return Decrypted plaintext if the message key was found, else an empty string
 */
std::string NewClient::try_skipped_message_keys(Header header, std::string ct, std::string AD){
  // Casts the key to an Integer to use as a key in the map
  CryptoPP::Integer key = byteblock_to_integer(header.DH_public_val + integer_to_byteblock(header.ns));
  // Returns an empty string if the key is not found
  if (this->mskipped.find(key) == this->mskipped.end()){
    this->cli_driver->print_info("TrySkippedMessageKeys: Didn't find any skipped message keys");
    return "";
  }
  // If it is found, decrypts the message and removes it from the map
  else{
    this->cli_driver->print_info("TrySkippedMessageKeys: Found a skipped message key, decrypting now");
    Integer mk = this->mskipped[key];
    this->mskipped.erase(key);
    auto[dec, hmac] = this->crypto_driver->decrypt(integer_to_byteblock(mk), ct, concat(AD,header));
    this->HMAC_key = hmac;
    return dec;
  }
}

/**
 * Implementation of SkipMessageKeys from the paper
 * 
 * Stores skipped message keys to decrypt out of order messages that may come later
 * If too many messages are skipped (arbitrarily chosen 4), errors out
 */
void NewClient::skip_message_keys(CryptoPP::Integer until){
  CryptoPP::Integer MAX_SKIP = 4;
  if (this->msg_num_receiving + MAX_SKIP < until){
    throw std::runtime_error("Too many skipped messages!!! Stop trying to be evil!!!");
  }
  if (this->ck_receiving != string_to_byteblock("")){
    // Creating skip message keys and storing them
    while (this->msg_num_receiving < until){
      this->cli_driver->print_info("SkipMessageKeys: Storing a message key for later");
      auto[new_ckr, new_mk] = this->crypto_driver->KDF_CK(this->ck_receiving);
      this->ck_receiving = new_ckr;
      Integer key = byteblock_to_integer(this->DH_last_other_public_value + integer_to_byteblock(this->msg_num_receiving));
      this->mskipped[key] = byteblock_to_integer(new_mk);
      this->msg_num_receiving++;
    }
  }
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
    DB_Ratchet_Message msg;
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
  DB_Ratchet_Message out_of_order;
  while (true) {
    // If there's an out of order stored, send it.
    if (out_of_order.ciphertext != "") {
        std::vector<unsigned char> data;
        out_of_order.serialize(data);
        this->network_driver->send(data);
        this->cli_driver->print_right(plaintext);
    }
    
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      // if the first character is a "d", delay
      if (plaintext[0] == 'd' || plaintext[0]== 'D') {
        // store the DB_Ratchet_Message for later
        out_of_order = this->send(plaintext);
       
        // populate plaintext with a new message to send
        this->cli_driver->print_warning("previous message delayed, please send another one:");
        std::getline(std::cin, plaintext);
      }

      DB_Ratchet_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}