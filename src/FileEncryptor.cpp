#include "FileEncryptor.hpp"
#include <fstream>
#include <vector>
#include <cstring>

namespace {
// helper
void secure_wipe(std::vector<unsigned char> &v) {
    if (!v.empty()) sodium_memzero(v.data(), v.size());
}
} // namespace

bool FileEncryptor::encryptFile(const std::string &inPath,
                                const std::string &outPath,
                                const std::string &password,
                                std::string &err) {
    std::ifstream in(inPath, std::ios::binary);
    if (!in) { err = "Failed to open input file"; return false; }
    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (!out) { err = "Failed to create output file"; return false; }

    // KDF
    KeyManager::Salt salt = KeyManager::generateSalt();
    KeyManager::Key  key;
    try {
        key = KeyManager::deriveKeyFromPassword(password, salt);
    } catch (const std::exception &e) {
        err = e.what();
        return false;
    }

    // Secretstream
    crypto_secretstream_xchacha20poly1305_state st{};
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, key.data()) != 0) {
        err = "init_push failed"; sodium_memzero(key.data(), key.size()); return false;
    }

    // Header: MAGIC(4) + VERSION(1) + reserved(3) + salt + header
    out.write(reinterpret_cast<const char*>(MAGIC_), 4);
    out.put(static_cast<char>(VERSION));
    unsigned char reserved[3] = {0,0,0};
    out.write(reinterpret_cast<char*>(reserved), 3);
    out.write(reinterpret_cast<const char*>(salt.data()), (std::streamsize)salt.size());
    out.write(reinterpret_cast<const char*>(header), (std::streamsize)sizeof header);
    if (!out) { err = "Error while writing header"; sodium_memzero(key.data(), key.size()); return false; }

    // Streaming
    constexpr std::size_t CHUNK = 4096;
    std::vector<unsigned char> plain(CHUNK), cipher(CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES);

    while (true) {
        in.read(reinterpret_cast<char*>(plain.data()), (std::streamsize)CHUNK);
        std::streamsize n = in.gcount();
        if (n < 0) { err = "Read error"; goto fail; }

        unsigned char tag = in.eof() ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                     : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long clen = 0;
        if (crypto_secretstream_xchacha20poly1305_push(&st,
                cipher.data(), &clen,
                plain.data(), (unsigned long long)n,
                nullptr, 0, tag) != 0) {
            err = "push failed"; goto fail;
        }
        if (clen > 0) {
            out.write(reinterpret_cast<char*>(cipher.data()), (std::streamsize)clen);
            if (!out) { err = "Writing encrypted data failed"; goto fail; }
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
    }

    sodium_memzero(&st, sizeof st);
    sodium_memzero(key.data(), key.size());
    secure_wipe(plain); secure_wipe(cipher);
    return true;
fail:
    sodium_memzero(&st, sizeof st);
    sodium_memzero(key.data(), key.size());
    secure_wipe(plain); secure_wipe(cipher);
    return false;
}

bool FileEncryptor::decryptFile(const std::string &inPath,
                                const std::string &outPath,
                                const std::string &password,
                                std::string &err) {
    std::ifstream in(inPath, std::ios::binary);
    if (!in) { err = "Failed to open encrypted file"; return false; }
    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (!out) { err = "Failed to create output file"; return false; }

    // Read header
    char magic[4]; in.read(magic, 4);
    if (in.gcount() != 4 || std::memcmp(magic, MAGIC_, 4) != 0) { err = "Invalid MAGIC"; return false; }
    unsigned char version=0; in.read(reinterpret_cast<char*>(&version),1);
    if (!in || version != VERSION) { err = "Unsupported version"; return false; }
    unsigned char reserved[3]; in.read(reinterpret_cast<char*>(reserved),3);
    KeyManager::Salt salt{}; in.read(reinterpret_cast<char*>(salt.data()), (std::streamsize)salt.size());
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    in.read(reinterpret_cast<char*>(header), (std::streamsize)sizeof header);
    if (!in) { err = "Incomplete header"; return false; }

    // KDF
    KeyManager::Key key;
    try {
        key = KeyManager::deriveKeyFromPassword(password, salt);
    } catch (const std::exception &e) {
        err = e.what();
        return false;
    }

    // init_pull
    crypto_secretstream_xchacha20poly1305_state st{};
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key.data()) != 0) {
        err = "init_pull failed (wrong key or file)"; sodium_memzero(key.data(), key.size()); return false;
    }

    constexpr std::size_t CHUNK = 4096 + crypto_secretstream_xchacha20poly1305_ABYTES;
    std::vector<unsigned char> cipher(CHUNK), plain(CHUNK);
    bool saw_final = false;

    while (true) {
        in.read(reinterpret_cast<char*>(cipher.data()), (std::streamsize)CHUNK);
        std::streamsize n = in.gcount();
        if (n <= 0) break;

        unsigned long long plen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(&st,
                plain.data(), &plen, &tag,
                cipher.data(), (unsigned long long)n,
                nullptr, 0) != 0) {
            err = "Authentication failed (corrupted file or wrong key)";
            goto fail;
        }

        out.write(reinterpret_cast<char*>(plain.data()),
                  (std::streamsize)plen);
        if (!out) { err = "Writing output failed"; goto fail; }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) { saw_final = true; break; }
    }

    if (!saw_final) { err = "FINAL tag not found (truncated file)"; goto fail; }

    sodium_memzero(&st, sizeof st);
    sodium_memzero(key.data(), key.size());
    secure_wipe(plain); secure_wipe(cipher);
    return true;
fail:
    sodium_memzero(&st, sizeof st);
    sodium_memzero(key.data(), key.size());
    secure_wipe(plain); secure_wipe(cipher);
    return false;
}
