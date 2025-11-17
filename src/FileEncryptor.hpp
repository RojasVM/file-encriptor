#pragma once
#include <string>
#include <vector>
#include <sodium.h>
#include "KeyManager.hpp"

class FileEncryptor {
public:
    static constexpr char MAGIC_[4] = {'F','E','N','C'};
    static constexpr unsigned char VERSION = 1;

    static bool encryptFile(const std::string &inPath,
                            const std::string &outPath,
                            const std::string &password,
                            std::string &err);

    static bool decryptFile(const std::string &inPath,
                            const std::string &outPath,
                            const std::string &password,
                            std::string &err);
};
