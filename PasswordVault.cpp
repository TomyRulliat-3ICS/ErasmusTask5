#include <iostream>
#include "sqlite3.h"
#include "openssl_wrapper.h"
#include "PasswordGenerator.h"

const std::string encryption_key = "thisisaverysecurekey1234567890!!"; // 32 bytes
const std::string encryption_iv  = "thisisinitialvector";              // 16 bytes

void createTable(sqlite3* db) {
    const char* sql = "CREATE TABLE IF NOT EXISTS credentials ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "site TEXT NOT NULL,"
                      "username TEXT NOT NULL,"
                      "password TEXT NOT NULL,"
                      "notes TEXT"
                      ");";
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "Error creating table: " << errMsg << "\n";
        sqlite3_free(errMsg);
    }
}

void addCredential(sqlite3* db) {
    std::string site, username, password, notes;

    std::cout << "Site: ";
    std::getline(std::cin, site);

    std::cout << "Username: ";
    std::getline(std::cin, username);

    std::cout << "Password: ";
    std::getline(std::cin, password);

    std::cout << "Notes: ";
    std::getline(std::cin, notes);

    std::string encryptedPassword = OpenSSLWrapper::encrypt(password, encryption_key, encryption_iv);

    std::string sql = "INSERT INTO credentials (site, username, password, notes) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, encryptedPassword.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, notes.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert data.\n";
    } else {
        std::cout << "Credential added.\n";
    }
    sqlite3_finalize(stmt);
}

void listCredentials(sqlite3* db) {
    const char* sql = "SELECT id, site, username, password, notes FROM credentials;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        std::string site = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        std::string encryptedPassword = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        std::string notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));

        std::string decryptedPassword;
        try {
            decryptedPassword = OpenSSLWrapper::decrypt(encryptedPassword, encryption_key, encryption_iv);
        } catch (...) {
            decryptedPassword = "[decryption failed]";
        }

        std::cout << "\n[" << id << "] "
                  << "Site: " << site << "\nUsername: " << username
                  << "\nPassword: " << decryptedPassword
                  << "\nNotes: " << notes << "\n";
    }
    sqlite3_finalize(stmt);
}

// Modify a credential by ID
bool editCredential(sqlite3* db, int id, const std::string& site, const std::string& username,
                    const std::string& encryptedPassword, const std::string& notes) {
    std::string sql = "UPDATE credentials SET site = ?, username = ?, password = ?, notes = ? WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encryptedPassword.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, notes.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, id);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

// Delete credential by ID
bool deleteCredential(sqlite3* db, int id) {
    std::string sql = "DELETE FROM credentials WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, id);
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

// Search credentials by site or username substring
void searchCredentials(sqlite3* db, const std::string& query) {
    std::string sql = "SELECT id, site, username FROM credentials WHERE site LIKE ? OR username LIKE ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cout << "Failed to prepare search statement\n";
        return;
    }

    std::string likeQuery = "%" + query + "%";
    sqlite3_bind_text(stmt, 1, likeQuery.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, likeQuery.c_str(), -1, SQLITE_TRANSIENT);

    std::cout << "Search results for \"" << query << "\":\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char* site = sqlite3_column_text(stmt, 1);
        const unsigned char* username = sqlite3_column_text(stmt, 2);
        std::cout << id << ": " << site << " / " << username << "\n";
    }
    sqlite3_finalize(stmt);
}

// Generate a random strong password
std::string generatePassword(int length = 16) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    std::string password;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, (int)chars.size() - 1);
    for (int i = 0; i < length; ++i) {
        password += chars[dis(gen)];
    }
    return password;
}

// Export the vault to an encrypted file (skeleton)
bool exportVault(sqlite3* db, const std::string& exportFilename, const std::string& masterPassword) {
    // 1. Query all credentials from DB
    // 2. Serialize into a format (e.g., JSON or CSV)
    // 3. Encrypt the serialized data using masterPassword (with your crypto wrapper)
    // 4. Write encrypted data to exportFilename
    std::cout << "[Export] This feature is not yet implemented.\n";
    return false;
}


int main() {
    sqlite3* db;
    if (sqlite3_open("vault.db", &db) != SQLITE_OK) {
        std::cerr << "Can't open database.\n";
        return 1;
    }

    createTable(db);
    std::string masterPassword = "your_master_password"; // À remplacer par une saisie si besoin

    int choice;
    do {
        std::cout << "\n--- Password Vault ---\n";
        std::cout << "1. Add Credential\n";
        std::cout << "2. List Credentials\n";
        std::cout << "3. Edit Credential\n";
        std::cout << "4. Delete Credential\n";
        std::cout << "5. Search Credentials\n";
        std::cout << "6. Generate Random Password\n";
        std::cout << "7. Export Vault (WIP)\n";
        std::cout << "0. Exit\n> ";
        std::cin >> choice;
        std::cin.ignore(); // clear newline

        if (choice == 1) {
            addCredential(db); // doit chiffrer avec masterPassword
        }
        else if (choice == 2) {
            listCredentials(db);
        }
        else if (choice == 3) {
            int id;
            std::cout << "Enter ID to edit: ";
            std::cin >> id;
            std::cin.ignore();
            std::string site, username, password, notes;
            std::cout << "New Site: "; std::getline(std::cin, site);
            std::cout << "New Username: "; std::getline(std::cin, username);
            std::cout << "New Password: "; std::getline(std::cin, password);
            std::cout << "New Notes: "; std::getline(std::cin, notes);
            std::string encrypted = OpenSSLWrapper::encrypt(password, encryption_key, encryption_iv);
            if (editCredential(db, id, site, username, encrypted, notes))
                std::cout << "Credential updated successfully.\n";
            else
                std::cout << "Error updating credential.\n";
        }
        else if (choice == 4) {
            int id;
            std::cout << "Enter ID to delete: ";
            std::cin >> id;
            std::cin.ignore();
            if (deleteCredential(db, id))
                std::cout << "Credential deleted.\n";
            else
                std::cout << "Error deleting credential.\n";
        }
        else if (choice == 5) {
            std::string query;
            std::cout << "Search for site or username: ";
            std::getline(std::cin, query);
            searchCredentials(db, query);
        }
        else if (choice == 6) {
            int length = 16;
            std::cout << "Password length (default 16): ";
            std::string input;
            std::getline(std::cin, input);
            if (!input.empty()) length = std::stoi(input);
            std::string pwd = generatePassword(length);
            std::cout << "Generated password: " << pwd << "\n";
        }
        else if (choice == 7) {
            std::string filename;
            std::cout << "Export filename: ";
            std::getline(std::cin, filename);
            if (exportVault(db, filename, masterPassword))
                std::cout << "Exported successfully.\n";
            else
                std::cout << "Export failed or not implemented.\n";
        }

    } while (choice != 0);

    sqlite3_close(db);
    return 0;
}

