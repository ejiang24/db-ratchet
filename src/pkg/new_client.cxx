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
DB_Ratchet_Message NewClient::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);// TODO: implement me!

  // apply symm key ratchet to sending chain key
  // if new other ratchet pub was received, new sending key was made in ratchet step
  auto[new_ck, new_mk] = this->crypto_driver->KDF_CK(this->ck_sending);
  // store the new chain key
  this->ck_sending = new_ck;

  // send the message
  DB_Ratchet_Message res;
  auto[header, ct_hmac] = ratchet_encrypt(plaintext, "");
  res.header = header;
  res.ciphertext = ct_hmac.first;
  res.mac = ct_hmac.second;

  return res;

  // if we're doing the thing, we need to do if switched, then ge



  // //first message
  

  // // TODO: FIX lol
  // auto [ciphertext, iv] = this->crypto_driver->AES_encrypt(this->AES_key, plaintext);
  // std::string to_tag = concat_msg_fields(iv, this->DH_current_public_value, ciphertext);
  // std::string tag = this->crypto_driver->HMAC_generate(this->HMAC_key, to_tag);

  // Message_Message res;
  // res.iv = iv;
  // res.public_value = this->DH_current_public_value;
  // res.ciphertext = ciphertext;
  // res.mac = tag;
  // return res;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> NewClient::receive(DB_Ratchet_Message msg) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string dec = ratchet_decrypt(msg.header, msg.ciphertext, "");

  // verify the message
  // make sure it's updated somewhere
  // want to verify header + ciphertext
  // concat ("", msg) basically just makes header a string
  // the whole thing that was tagged was Root AD ("") + header + ciphertext
  bool is_valid = this->crypto_driver->HMAC_verify(this->HMAC_key, concat("", msg.header) + msg.ciphertext, msg.mac);


  return {dec, is_valid};
 



  // if (msg.header.DH_public_val != this->DH_last_other_public_value) {
  //   auto [dh_obj, prv, pub] = this->crypto_driver->DH_initialize(this->DH_params);
  //   this->DH_last_other_public_value = msg.public_value;
  //   this->prepare_keys(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value);
    
  //   this->DH_switched = true;
  // }

  // std::string to_decrypt = concat_msg_fields(msg.iv, msg.public_value, msg.ciphertext);
  // std::string decrypted = this->crypto_driver->AES_decrypt(this->AES_key, msg.iv, msg.ciphertext); //key, iv, ciphertext 
  // bool is_valid = this->crypto_driver->HMAC_verify(this->HMAC_key, to_decrypt, msg.mac);

  // // TODO: make sure hmac_key is updated with new auth_keys

  // return {decrypted, is_valid};

  // when we receive, we should check fi ti's a skipped key was stored earlier
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

// Custom comparison function for CryptoPP::SecBlock<unsigned char>
bool compareSecBlocks(const CryptoPP::SecByteBlock& lhs,
                      const CryptoPP::SecByteBlock& rhs) {
    // Compare the contents of the SecBlocks byte by byte
    size_t minLength = std::min(lhs.size(), rhs.size());
    for (size_t i = 0; i < minLength; ++i) {
        if (lhs[i] < rhs[i]) return true;
        if (lhs[i] > rhs[i]) return false;
    }
    return lhs.size() < rhs.size(); // If all bytes are equal, shorter block is considered smaller
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
    // WAITS FOR BOB
    this->cli_driver->print_warning("Alice is waiting for Bob's message");
    std::vector<unsigned char> vctr = this->network_driver->read();
    params.deserialize(vctr);
    this->DH_params = params;

    //make Alice's keys
    auto [dh_obj, prv_key, pub_key] = this->crypto_driver->DH_initialize(params);
    // making DHs
    this->DH_current_public_value = pub_key;
    this->DH_current_private_value = prv_key;
    this->cli_driver->print_warning("ALICE KEYS:");
    this->cli_driver->print_warning("Alice public: " + byteblock_to_string(pub_key));
    this->cli_driver->print_warning("Alice private: " + byteblock_to_string(prv_key));

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
    // std::map<std::pair<SecByteBlock, Integer>, SecByteBlock> mskipped;
    // this->mskipped = mskipped;
    

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
      DB_Ratchet_Message msg = this->send(plaintext);
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
    // our current private value has not yet been updated
    auto[new_rk, new_ckr] = this->crypto_driver->KDF_RK(this->rk, this->crypto_driver->DH_generate_shared_key(dh_obj, this->DH_current_private_value, this->DH_last_other_public_value));
    this->rk = new_rk;
    this->ck_receiving = new_ckr; // used to decrypt the incoming message from Bob (with new public ratchet)

    // already newly generated above
    this->DH_current_public_value = pub;
    this->DH_current_private_value = prv;
    // TODO: make sure that all the instance variables are updated accordingly
    // probably need to update this in the state? 

    auto[new_new_rk, new_cks] = this->crypto_driver->KDF_RK(this->rk, this->crypto_driver->DH_generate_shared_key(dh_obj, prv, this->DH_last_other_public_value));
    this->rk = new_new_rk;
    this->ck_sending = new_cks;

}

std::pair<Header, std::pair<std::string, std::string>> NewClient::ratchet_encrypt(std::string pt, std::string AD) {
  auto[new_cks, new_mk] = this->crypto_driver->KDF_CK(this->ck_sending);
  this->ck_sending = new_cks;
  Header header = create_header(this->DH_current_public_value, this->prev_chain_num, this->msg_num_sending);

  this->msg_num_sending++; // i hope this works
  return {header, this->crypto_driver->encrypt(new_mk, pt, concat(AD, header))};
}

std::string NewClient::concat(std::string ad, Header header) {
  // TODO: hope this works lol
  SecByteBlock concated = header.DH_public_val + integer_to_byteblock(header.pn) + integer_to_byteblock(header.ns);
  return ad + byteblock_to_string(concated); 

}

Header NewClient::create_header(SecByteBlock DHs, Integer PN, Integer Ns) {
  Header res;
  res.DH_public_val = DHs;
  res.pn = PN;
  res.ns = Ns;
  return res;
}

std::string NewClient::ratchet_decrypt(Header header, std::string ct, std::string AD){
  std::string plaintext = try_skipped_message_keys(header,ct,AD);
  if (plaintext != ""){
    return plaintext;
  }
  if (header.DH_public_val != this->DH_last_other_public_value){
    skip_message_keys(header.pn);
    DHRatchetStep(header);
    // DHRatchet

    // TODO: this->DH_Switched?
  }
  skip_message_keys(header.ns);
  auto[new_ckr, new_mk] = this->crypto_driver->KDF_CK(this->ck_receiving);
  this->ck_receiving = new_ckr;
  this->msg_num_receiving++; // check ++
  return this->crypto_driver->decrypt(new_mk, ct, concat(AD, header));

}

std::string NewClient::try_skipped_message_keys(Header header, std::string ct, std::string AD){
  CryptoPP::Integer key = byteblock_to_integer(header.DH_public_val + integer_to_byteblock(header.ns));
  // std::pair<SecByteBlock, Integer> key = std::make_pair(header.DH_public_val,header.ns);
  if (this->mskipped.find(key) == this->mskipped.end()){
    return "";
  }
  else{
    Integer mk = this->mskipped[key];
    // auto found = this->mskipped.find(key);
    this->mskipped.erase(key);
    return this->crypto_driver->decrypt(integer_to_byteblock(mk), ct, concat(AD,header));
  }
}
void NewClient::skip_message_keys(CryptoPP::Integer until){
  CryptoPP::Integer MAX_SKIP = 4;
  if (this->msg_num_receiving + MAX_SKIP < until){
    throw std::runtime_error("Too many skipped messages!!! Stop trying to be evil!!!");
  }
  // TODO: unsure about this null check
  if (this->ck_receiving != string_to_byteblock("")){
    // Creating skip message keys and storing them
    while (this->msg_num_receiving < until){
      auto[new_ckr, new_mk] = this->crypto_driver->KDF_CK(this->ck_receiving);
      this->ck_receiving = new_ckr;
      Integer key = byteblock_to_integer(this->DH_last_other_public_value + integer_to_byteblock(this->msg_num_receiving));
      // this->mskipped[{this->DH_last_other_public_value, this->msg_num_receiving}] = new_mk;
      this->mskipped[key] = byteblock_to_integer(new_mk);
      this->msg_num_receiving++;
    }
  }
}