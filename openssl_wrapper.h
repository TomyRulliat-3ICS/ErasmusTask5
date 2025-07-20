#ifndef OPENSSL_WRAPPER_H
#define OPENSSL_WRAPPER_H

#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

class OpenSSLWrapper {
public:
    static std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                    reinterpret_cast<const unsigned char*>(key.c_str()),
                                    reinterpret_cast<const unsigned char*>(iv.c_str()))) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption initialization failed");
        }

        std::string ciphertext;
        ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len;
        int ciphertext_len;

        if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                                   reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed");
        }
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Final encryption step failed");
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    static std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                    reinterpret_cast<const unsigned char*>(key.c_str()),
                                    reinterpret_cast<const unsigned char*>(iv.c_str()))) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption initialization failed");
        }

        std::string plaintext;
        plaintext.resize(ciphertext.size());
        int len;
        int plaintext_len;

        if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                                   reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed");
        }
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Final decryption step failed");
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }
};

#endif // OPENSSL_WRAPPER_H