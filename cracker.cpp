#define __XOPEN_SOURCE
#include <iostream>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <unistd.h>
#include <time.h>
#include <crypt.h>

bool FOUND = false;
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
    std::string salt = line.substr(d1, (d3 - d1));
    return salt;
}

std::string get_password_hash(const std::string& line) {
    size_t c1 = line.find(':');
    size_t c2 = line.find(':', c1 + 1);
    std::string password = line.substr(c1 + 1, c2 - c1 - 1);
    return password;
}



std::string hash(const std::string& password, const std::string& salt) {

    char* hashed = crypt(password.c_str(), salt.c_str());

    return hashed;
}




void brute_force(const std::string& salt, const std::string& password_hash, const std::string& current, const int max_length) {
    if (FOUND) {
        return;
    }

    const std::string possible_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/";

    // Attempt to find passwords of increasing lengths
    if (current.length() >= max_length) {
        return; // Stop if we reached max length
    }

    // Generate next password
    for (char c : possible_chars) {
        std::string attempt = current + c;
        std::string current_attempt = hash(attempt, salt);

        if (current_attempt == password_hash) {

            std::cout << "Password found: " << attempt << std::endl;
            std::cout << "Hash : " << current_attempt << std::endl;
            FOUND = true;
            return;
        }

        brute_force(salt, password_hash, attempt, max_length);
    }
}

void start_brute_force(const std::string& salt, const std::string& password_hash, const int max_length) {

    for (int length = 1; length <= max_length; ++length) {
        std::string current;
        brute_force(salt, password_hash, current, length);
    }
}

void dictionary_attack(const std::string& salt, const std::string& password_hash, const std::string& dict_file) {
    std::ifstream file(dict_file);
    if (!file.is_open()) {
        std::cerr << "Failed to open dictionary file" << std::endl;
        return;
    }

    std::string password;
    while (std::getline(file, password)) {
        std::string current_attempt = hash(password, salt);
        if (current_attempt == password_hash) {
            std::cout << "Password found via dictionary attack: " << password << std::endl;
            std::cout << "Hash : " << current_attempt << std::endl;
            FOUND = true;
            return;
        }
    }
}


int main() {
    std::string username;
    std::string file_path = "";
    std::string dict_file;
    int max_length = 0;

    std::cout << "Enter the file path: ";
    std::cin >> file_path;
    std::cout << "Enter the username you wish to crack: ";
    std::cin >> username;
    std::cout << "Enter the path to the dictionary file: ";
    std::cin >> dict_file;
    std::cout << "Enter the max length of the password: ";
    std::cin >> max_length;

    if (max_length == 0) {
        max_length = 5;
    }


    std::string shadow_line = get_shadow(username, file_path);
    std::string hash_type = get_type(shadow_line);
    std::string salt = get_salt(shadow_line);
    std::string password_hash = get_password_hash(shadow_line);

    dictionary_attack(salt, password_hash, dict_file);
    if (FOUND) {
        exit(0);
    }
    start_brute_force(salt, password_hash, max_length);


//  -lcrypt

    //for testing:

    // for (int i = 1; i <= 4; i++) {
    //
    //     clock_t t;
    //     t = clock();
    //
    //     std::string username = "sha512_" + std::to_string(i);
    //     std::string shadow_line = get_shadow(username, "/home/sheybarpagga/CLionProjects/8005_assignment_3/shadow.txt");
    //     std::string hash_type = get_type(shadow_line);
    //     std::string salt = get_salt(shadow_line);
    //     std::string password_hash = get_password_hash(shadow_line);
    //     start_brute_force(salt, password_hash, 15);
    //     t = clock() - t;
    //
    //     std::cout << "In " << ((float)t)/CLOCKS_PER_SEC << " seconds" << std::endl;
    //     FOUND = false;
    // }
    // std::string username = "md5_2";;
    // std::string shadow_line = get_shadow(username, "/home/sheybarpagga/CLionProjects/8005_assignment_3/shadow.txt");
    // std::string hash_type = get_type(shadow_line);
    // std::string salt = get_salt(shadow_line);
    // std::string password_hash = get_password_hash(shadow_line);
    // start_brute_force(salt, password_hash, 15);

    // std::cout << hash("a", "$1$ThisIsATestSalt") << std::endl;
    // std::cout << hash("ae", "$1$ThisIsATestSalt") << std::endl;
    // std::cout << hash("a$c", "$1$ThisIsATestSalt") << std::endl;
    // std::cout << hash("ahsb", "$1$ThisIsATestSalt") << std::endl;
    //
    // std::cout << hash("a", "$5$ThisIsATestSalt") << std::endl;
    // std::cout << hash("ae", "$5$ThisIsATestSalt") << std::endl;
    // std::cout << hash("adc", "$5$ThisIsATestSalt") << std::endl;
    // std::cout << hash("ahsb", "$5$ThisIsATestSalt") << std::endl;
    //
    // std::cout << hash("a", "$6$ThisIsATestSalt") << std::endl;
    // std::cout << hash("ae", "$6$ThisIsATestSalt") << std::endl;
    // std::cout << hash("a$c", "$6$ThisIsATestSalt") << std::endl;
    // std::cout << hash("ahsb", "$6$ThisIsATestSalt") << std::endl;

    return 0;
}