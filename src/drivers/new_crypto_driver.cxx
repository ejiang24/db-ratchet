#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/new_crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Returns (p, q, g) DH parameters. This function should:
 * 1) Initialize a `CryptoPP::AutoSeededRandomPool` object
 *    and a `CryptoPP::PrimeAndGenerator` object.
 * 2) Generate a prime p, sub-prime q, and generator g
 *    using `CryptoPP::PrimeAndGenerator::Generate(...)`
 *    with a `delta` of 1, a `pbits` of 512, and a `qbits` of 511.
 * 3) Store and return the parameters in a `DHParams_Message` object.
 * @return `DHParams_Message` object that stores Diffie-Hellman parameters
 */
DHParams_Message NewCryptoDriver::DH_generate_params() {
  AutoSeededRandomPool pool;
  PrimeAndGenerator generator;

  generator.Generate(1, pool, 512, 511);
  Integer p = generator.Prime();
  Integer q = generator.SubPrime();
  Integer g = generator.Generator();

  DHParams_Message res;
  res.p = p;
  res.q = q;
  res.g = g;
  return res;
}

/**
 * @brief Generate DH keypair. This function should
 * 1) Create a DH object and `SecByteBlock`s for the private and public keys.
 * Use `DH_obj.PrivateKeyLength()` and `PublicKeyLength()` to get key sizes.
 * 2) Generate a DH keypair using the `GenerateKeyPair(...)` method.
 * @param DH_params Diffie-Hellman parameters
 * @return Tuple containing DH object, private value, public value.
 */
std::tuple<DH, SecByteBlock, SecByteBlock>
NewCryptoDriver::DH_initialize(const DHParams_Message &DH_params) {
  const DH dh_obj(DH_params.p, DH_params.q, DH_params.g);
  SecByteBlock prv(dh_obj.PrivateKeyLength());
  SecByteBlock pub(dh_obj.PublicKeyLength());

  AutoSeededRandomPool pool;
  dh_obj.GenerateKeyPair(pool, prv, pub);

  return {dh_obj, prv, pub};
}

/**
 * @brief Generates a shared secret. This function should
 * 1) Allocate space in a `SecByteBlock` of size `DH_obj.AgreedValueLength()`.
 * 2) Run `DH_obj.Agree(...)` to store the shared key in the allocated space.
 * 3) Throw an `std::runtime_error` if failed to agree.
 * @param DH_obj Diffie-Hellman object
 * @param DH_private_value user's private value for Diffie-Hellman
 * @param DH_other_public_value other user's public value for Diffie-Hellman
 * @return Diffie-Hellman shared key
 */
SecByteBlock NewCryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {

  CryptoPP::SecByteBlock agreed(DH_obj.AgreedValueLength());
  if(!DH_obj.Agree(agreed, DH_private_value, DH_other_public_value)) {
    throw std::runtime_error("Failed to agree.");
  }

  return agreed;
}

std::pair<SecByteBlock, SecByteBlock>
NewCryptoDriver::KDF_RK(SecByteBlock rk, SecByteBlock dh_out) {
  CryptoPP::SecByteBlock key(64); // 64 bytes

  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(key, key.size(), dh_out, dh_out.size(), rk, rk.size(), NULL, 0);

  CryptoPP::SecByteBlock root_key(32);
  CryptoPP::SecByteBlock chain_key(32);
  root_key.Assign(key, 32);
  chain_key.Assign(key+32, 32);

  return {root_key, chain_key};
}

std::pair<SecByteBlock, SecByteBlock>
NewCryptoDriver::KDF_CK(SecByteBlock ck) {
  // CryptoPP::SecByteBlock key = HMAC_generate_key(ck);

  std::string msg_key = HMAC_generate(ck, "1");
  std::string chain_key = HMAC_generate(ck, "2");

  return {string_to_byteblock(msg_key), string_to_byteblock(chain_key)};
    
}

std::pair<std::string, std::string> NewCryptoDriver::encrypt(SecByteBlock mk, std::string pt, std::string ad) {
  CryptoPP::SecByteBlock full_key(80); 

  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(full_key, full_key.size(), mk, mk.size(), NULL, 0, NULL, 0);

  CryptoPP::SecByteBlock enc_key(32);
  CryptoPP::SecByteBlock auth_key(32);
  CryptoPP::SecByteBlock iv(16);
  enc_key.Assign(full_key, 32);
  auth_key.Assign(full_key + 32, 32);
  iv.Assign(full_key + 64, 16);

  std::string ct = AES_encrypt(enc_key, pt, iv);

  // calculate HMAC
  std::string hmac = HMAC_generate(auth_key, ad + ct);

  return {ct, hmac};
}

std::string NewCryptoDriver::decrypt(SecByteBlock mk, std::string ct, std::string ad) {
  CryptoPP::SecByteBlock full_key(80); 

  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(full_key, full_key.size(), mk, mk.size(), NULL, 0, NULL, 0);

  CryptoPP::SecByteBlock enc_key(32);
  CryptoPP::SecByteBlock auth_key(32);
  CryptoPP::SecByteBlock iv(16);
  enc_key.Assign(full_key, 32);
  auth_key.Assign(full_key + 32, 32);
  iv.Assign(full_key + 64, 16);

  std::string dec = AES_decrypt(mk, iv, ct);

  bool verified = HMAC_verify(auth_key, ad + ct, "HMAC");


}






/**
 * @brief Generates AES key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `AES::DEFAULT_KEYLENGTH`.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for AES using the
 * provided salt. See the `DeriveKey` function. (Use NULL for the "info"
 * argument and 0 for "infolen".)
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key Diffie-Hellman shared key
 * @return AES key
 */
SecByteBlock NewCryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  CryptoPP::SecByteBlock key(AES::DEFAULT_KEYLENGTH);

  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(key, key.size(), DH_shared_key, DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);

  return key;

}

/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size `AES::BLOCKSIZE`
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * the AES encryptor.
 * 3) Return ciphertext and iv used in encryption or throw an
 * `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::string
NewCryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext, SecByteBlock iv) {
  try {
    CBC_Mode<AES>::Encryption enc;
  
    CryptoPP::AutoSeededRandomPool pool;
    enc.GetNextIV(pool, iv);
    enc.SetKeyWithIV(key, key.size(), iv);

    std::string ciphertext;
    CryptoPP::StringSource s(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext)));

    return ciphertext;

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using `SetKeyWithIV` on the key and
 * iv. 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using the AES decryptor.
 * 3) Return the plaintext or throw an `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string NewCryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {

    CBC_Mode<AES>::Decryption dec;

    AutoSeededRandomPool pool;
    dec.SetKeyWithIV(key, key.size(), iv);

    std::string decrypted;
    StringSource s(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(decrypted)));

    return decrypted;

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `SHA256::BLOCKSIZE` for the shared key.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for HMAC using the
 * provided salt. See the `DeriveKey` function.
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key shared key from Diffie-Hellman
 * @return HMAC key
 */
SecByteBlock
NewCryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // TODO: implement me!

  SecByteBlock key(SHA256::BLOCKSIZE);

  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(key, key.size(), DH_shared_key, DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);

  return key;
}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error` upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string NewCryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {

    HMAC<SHA256> hmac(key, key.size());
    std::string tag;

    StringSource s(ciphertext, true, new HashFilter(hmac, new StringSink(tag))); 

    return tag;


  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks if the MAC is valid. This function
 * should 1) Initialize an `HMAC<SHA256>` with the provided key. 2) Run the
 * message through a `HashVerificationFilter` to verify the HMAC. 3) Return
 * false upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool NewCryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  
  try {
    HMAC<SHA256> hmac(key, key.size());
    StringSource(ciphertext + mac, true, new HashVerificationFilter(hmac, NULL, flags));
    return true;

  } catch (const CryptoPP::Exception& e) {
    return false;
  }
  


}
