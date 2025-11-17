#include "KeyManager.hpp"

KeyManager::Salt KeyManager::generateSalt() {
    Salt salt{};
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

std::string KeyManager::saltToHex(const Salt &salt) {
    char buf[crypto_pwhash_SALTBYTES * 2 + 1];
    sodium_bin2hex(buf, sizeof buf, salt.data(), salt.size());
    return std::string(buf);
}

KeyManager::Salt KeyManager::saltFromHex(const std::string &hex) {
    if (hex.size() != crypto_pwhash_SALTBYTES * 2) {
        throw std::invalid_argument("Hex salt length invalid");
    }
    Salt salt{};
    if (sodium_hex2bin(salt.data(), salt.size(),
                       hex.data(), hex.size(),
                       nullptr, nullptr, nullptr) != 0) {
        throw std::runtime_error("Invalid hex salt");
    }
    return salt;
}

KeyManager::Key KeyManager::deriveKeyFromPassword(const std::string &password,
                                                  const Salt &salt) {
    Key key{};
    const std::uint64_t OPSLIMIT = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    const std::size_t   MEMLIMIT = crypto_pwhash_MEMLIMIT_INTERACTIVE;

    if (crypto_pwhash(key.data(), key.size(),
                      password.c_str(), password.size(),
                      salt.data(),
                      OPSLIMIT, MEMLIMIT,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Key derivation failed");
    }
    return key;
}
