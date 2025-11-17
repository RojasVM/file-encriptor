#include "KeyManager.hpp"
#include "FileEncryptor.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sodium.h>

static int selftest() {
    const std::string inFile  = "selftest.in";
    const std::string encFile = "selftest.enc";
    const std::string outFile = "selftest.out";
    const std::string pass    = "test_password";

    // Create sample input
    {
        std::ofstream o(inFile, std::ios::binary);
        for (int i = 0; i < 10000; ++i) o << "Hello XChaCha20-Poly1305!\n";
    }

    std::string err;
    if (!FileEncryptor::encryptFile(inFile, encFile, pass, err)) {
        std::cerr << "[selftest] Encryption failed: " << err << "\n";
        return 1;
    }
    if (!FileEncryptor::decryptFile(encFile, outFile, pass, err)) {
        std::cerr << "[selftest] Decryption failed: " << err << "\n";
        return 2;
    }

    // Compare files
    std::ifstream a(inFile, std::ios::binary);
    std::ifstream b(outFile, std::ios::binary);
    std::istreambuf_iterator<char> ia(a), ib(b), end;
    if (!std::equal(ia, end, ib)) {
        std::cerr << "[selftest] Output does not match input after decrypt\n";
        return 3;
    }

    std::cout << "[selftest] OK\n";

    // Cleanup (best-effort)
    std::remove(inFile.c_str());
    std::remove(encFile.c_str());
    std::remove(outFile.c_str());
    return 0;
}

int main(int argc, char** argv) {
    if (sodium_init() == -1) {
        std::cerr << "libsodium initialization failed\n";
        return 1;
    }

    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " enc <input> <output> <password>\n"
                  << "  " << argv[0] << " dec <input> <output> <password>\n"
                  << "  " << argv[0] << " selftest\n";
        return 2;
    }

    std::string mode = argv[1];
    std::string err;

    if (mode == "selftest") {
        return selftest();
    }

    if (argc < 5) {
        std::cerr << "Insufficient arguments\n";
        return 2;
    }

    std::string in  = argv[2];
    std::string out = argv[3];
    std::string pass = argv[4];

    bool ok = false;
    if (mode == "enc") {
        ok = FileEncryptor::encryptFile(in, out, pass, err);
    }
    else if (mode == "dec") {
        ok = FileEncryptor::decryptFile(in, out, pass, err);
    }
    else {
        std::cerr << "Unknown mode\n";
        return 2;
    }

    if (!ok) {
        std::cerr << "Error: " << err << "\n";
        return 1;
    }

    std::cout << "Done.\n";
    return 0;
}
