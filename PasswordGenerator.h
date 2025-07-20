#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

#include <random>
#include <string>

class PasswordGenerator {
public:
    static std::string generate(int length = 16) {
        const std::string chars =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+[{]}|;:',<.>/?";

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<> dist(0, chars.size() - 1);

        std::string password;
        for (int i = 0; i < length; ++i) {
            password += chars[dist(generator)];
        }
        return password;
    }
};

#endif // PASSWORD_GENERATOR_H