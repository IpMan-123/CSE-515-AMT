#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

// Utility function to print bytes as hex string
string toHex(const unsigned char* data, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << setw(2) << (int)data[i];
    }
    return ss.str();
}

// Diffie-Hellman parameters (2048-bit MODP Group from RFC 3526)
const char* prime_hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF";

class DiffieHellman {
public:
    DiffieHellman() {
        // Initialize BIGNUMs
        p = BN_new();
        g = BN_new();
        priv_key = BN_new();
        pub_key = BN_new();
        ctx = BN_CTX_new();

        BN_hex2bn(&p, prime_hex);
        BN_set_word(g, 2); // generator 2

        // Generate private key (random)
        generatePrivateKey();

        // Compute public key
        computePublicKey();
    }

    ~DiffieHellman() {
        BN_free(p);
        BN_free(g);
        BN_free(priv_key);
        BN_free(pub_key);
        BN_CTX_free(ctx);
    }

    void generatePrivateKey() {
        // Generate a random private key less than p
        BN_rand_range(priv_key, p);
    }

    void computePublicKey() {
        // pub_key = g^priv_key mod p
        BN_mod_exp(pub_key, g, priv_key, p, ctx);
    }

    // Get public key as hex string
    string getPublicKeyHex() {
        char* hex = BN_bn2hex(pub_key);
        string pubHex(hex);
        OPENSSL_free(hex);
        return pubHex;
    }

    // Compute shared secret given other party's public key hex string
    vector<unsigned char> computeSharedSecret(const string& other_pub_hex) {
        BIGNUM* other_pub = BN_new();
        BN_hex2bn(&other_pub, other_pub_hex.c_str());

        BIGNUM* secret = BN_new();
        BN_mod_exp(secret, other_pub, priv_key, p, ctx);

        // Convert secret to bytes
        int secret_len = BN_num_bytes(secret);
        vector<unsigned char> secret_bytes(secret_len);
        BN_bn2bin(secret, secret_bytes.data());

        BN_free(other_pub);
        BN_free(secret);

        return secret_bytes;
    }

private:
    BIGNUM* p;
    BIGNUM* g;
    BIGNUM* priv_key;
    BIGNUM* pub_key;
    BN_CTX* ctx;
};

// AES CBC encryption/decryption helper class
class AESCipher {
public:
    AESCipher(const vector<unsigned char>& key) {
        // Use first 32 bytes of key for AES-256
        aes_key.assign(key.begin(), key.begin() + 32);
    }

    // Encrypt plaintext, output ciphertext and IV
    bool encrypt(const vector<unsigned char>& plaintext, vector<unsigned char>& ciphertext, vector<unsigned char>& iv) {
        iv.resize(16);
        if (!RAND_bytes(iv.data(), iv.size())) {
            cerr << "Failed to generate random IV" << endl;
            return false;
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key.data(), iv.data())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        ciphertext.resize(plaintext.size() + 16);
        int len;
        int ciphertext_len;

        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    // Decrypt ciphertext with IV, output plaintext
    bool decrypt(const vector<unsigned char>& ciphertext, const vector<unsigned char>& iv, vector<unsigned char>& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key.data(), iv.data())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        plaintext.resize(ciphertext.size());
        int len;
        int plaintext_len;

        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

private:
    vector<unsigned char> aes_key;
};

// Compute SHA-256 hash of data
vector<unsigned char> sha256(const vector<unsigned char>& data) {
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256_ctx);
    return hash;
}

int main() {
    DiffieHellman* userA = nullptr;
    DiffieHellman* userB = nullptr;
    vector<unsigned char> secretA;
    vector<unsigned char> secretB;
    vector<unsigned char> aes_key(32, 0);
    AESCipher* cipher = nullptr;
    string transaction;
    vector<unsigned char> plaintext;
    vector<unsigned char> ciphertext;
    vector<unsigned char> iv;
    vector<unsigned char> hash;
    vector<unsigned char> decrypted;
    vector<unsigned char> hash_check;

    while (true) {
        cout << "\nMenu:\n";
        cout << "1. Generate the keys\n";
        cout << "2. User Input (Enter financial transaction data and encrypt)\n";
        cout << "3. Check Integrity And Authentication (Decrypt and verify)\n";
        cout << "4. Exit\n";
        cout << "Enter your choice: ";
        int choice;
        cin >> choice;
        cin.ignore();

        if (choice == 1) {
            if (userA) delete userA;
            if (userB) delete userB;
            if (cipher) {
                delete cipher;
                cipher = nullptr;
            }

            userA = new DiffieHellman();
            userB = new DiffieHellman();

            string userA_pub = userA->getPublicKeyHex();
            string userB_pub = userB->getPublicKeyHex();

            cout << "User A Public Key: " << userA_pub << endl;
            cout << "User B Public Key: " << userB_pub << endl;

            secretA = userA->computeSharedSecret(userB_pub);
            secretB = userB->computeSharedSecret(userA_pub);

            cout << "User A Shared Secret (hex): " << toHex(secretA.data(), secretA.size()) << endl;
            cout << "User B Shared Secret (hex): " << toHex(secretB.data(), secretB.size()) << endl;

            for (size_t i = 0; i < secretA.size() && i < 32; ++i) {
                aes_key[i] = secretA[i];
            }

            cipher = new AESCipher(aes_key);
            cout << "Keys generated and cipher initialized." << endl;
        } else if (choice == 2) {
            if (!cipher) {
                cout << "Please generate keys first (option 1)." << endl;
                continue;
            }
            cout << "Enter financial transaction data: ";
            getline(cin, transaction);
            plaintext.assign(transaction.begin(), transaction.end());

            if (!cipher->encrypt(plaintext, ciphertext, iv)) {
                cerr << "Encryption failed" << endl;
                continue;
            }

            hash = sha256(plaintext);

            cout << "Encrypted Transaction (hex): " << toHex(ciphertext.data(), ciphertext.size()) << endl;
            cout << "IV (hex): " << toHex(iv.data(), iv.size()) << endl;
            cout << "SHA-256 Hash of Plaintext Transaction: " << toHex(hash.data(), hash.size()) << endl;
        } else if (choice == 3) {
            if (!cipher) {
                cout << "Please generate keys first (option 1)." << endl;
                continue;
            }
            if (ciphertext.empty() || iv.empty() || hash.empty()) {
                cout << "No encrypted data available. Please enter transaction data first (option 2)." << endl;
                continue;
            }

            if (!cipher->decrypt(ciphertext, iv, decrypted)) {
                cerr << "Decryption failed" << endl;
                continue;
            }

            hash_check = sha256(decrypted);
            cout << "SHA-256 Hash of Decrypted Plaintext: " << toHex(hash_check.data(), hash_check.size()) << endl;

            if (hash != hash_check) {
                cerr << "Message integrity check failed!" << endl;
            } else {
                cout << "Message integrity check passed. The message is authentic and unaltered." << endl;
                string decrypted_str(decrypted.begin(), decrypted.end());
                cout << "Decrypted Transaction: " << decrypted_str << endl;
            }
        } else if (choice == 4) {
            break;
        } else {
            cout << "Invalid choice. Please try again." << endl;
        }
    }

    if (userA) delete userA;
    if (userB) delete userB;
    if (cipher) delete cipher;

    return 0;
}