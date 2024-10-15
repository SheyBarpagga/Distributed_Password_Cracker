#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <unistd.h>

// #include <crypt.h>
#include <wincrypt.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// extract hash
std::string get_shadow(const std::string& username, const std::string& file) {
    std::ifstream shadowFile(file);
    if (shadowFile.is_open()) {
        std::string line;
        while (getline(shadowFile, line)) {
            if (line.find(username) == 0) {
                return line;
            }
        }
    } else {
        std::cerr << "File not found" << std::endl;
        exit(1);
    }
    std::cerr << "Username not found" << std::endl;
    exit(1);
}

std::string get_type(const std::string& line) {
    size_t d1 = line.find('$');
    size_t d2 = line.find('$', d1 + 1);
    std::string hash_type = line.substr(d1 + 1, d2 - d1 - 1);
    return hash_type;
}

std::string get_salt(const std::string& line) {
    size_t d1 = line.find('$');
    size_t d2 = line.find('$', d1 + 1);
    size_t d3 = line.find('$', d2 + 1);
    std::string salt = line.substr(d2 + 1, (d3 - d2 - 1));
    return salt;
}

std::string get_password_hash(const std::string& line) {
    size_t c1 = line.find(':');
    size_t c2 = line.find(':', c1 + 1);
    std::string password = line.substr(c1 + 1, c2 - c1 - 1);
    return password;
}

std::string to_hex(const char* hash, const size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string md5_hash(const std::string& password, const std::string& salt) {
    std::string pass = salt + password;
    unsigned char hash[MD5_DIGEST_LENGTH];

    MD5((unsigned char*)pass.c_str(), pass.length(), hash);

    return to_hex(hash, MD5_DIGEST_LENGTH);
}

std::string blowfish_hash(const std::string& password, const std::string& salt) {
    struct crypt_data data;
    data.initialized = 0;
    char* hashed = crypt_r(password.c_str(), salt.c_str(), &data);
    return std::basic_string<char>(hashed);
}

std::string sha256_hash(const std::string& password, const std::string& salt) {
    std::string input = salt + password;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.length(), hash);

    return toHexString(hash, SHA256_DIGEST_LENGTH);
}

std::string sha512_hash(const std::string& password, const std::string& salt) {
    std::string input = salt + password;
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.length(), hash);

    return toHexString(hash, SHA256_DIGEST_LENGTH);
}

std::string check_type_and_hash(const std::string& hash_type, const std::string& password, const std::string& salt) {
    if (hash_type == "1") {
        return md5_hash(password, salt);
    } else if (hash_type == "2a" || hash_type == "2y") {
        return blowfish_hash(password, salt);
    } else if (hash_type == "5") {
        return sha256_hash(password, salt);
    } else if (hash_type == "6") {
        return sha512_hash(password, salt);
    } else {
        std::cerr << "Invalid hash type" << std::endl;
        exit(1);
    }
}


