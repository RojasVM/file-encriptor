#include <cstdint>   
#include <cstddef>  

#pragma once
#include <array>
#include <string>
#include <stdexcept>
#include <sodium.h>

class KeyManager {
public:
    using Key  = std::array<unsigned char, crypto_secretstream_xchacha20poly1305_KEYBYTES>;
    using Salt = std::array<unsigned char, crypto_pwhash_SALTBYTES>;

    static Salt generateSalt();
    static std::string saltToHex(const Salt &salt);
    static Salt saltFromHex(const std::string &hex);
    static Key deriveKeyFromPassword(const std::string &password, const Salt &salt);
};
