# Secure Financial Transactions

This project demonstrates a secure system for two users to exchange a shared secret key over an untrusted network using the Diffie-Hellman key exchange protocol. The shared secret key is then used for encrypting and decrypting sensitive financial transactions using AES encryption in CBC mode. Message integrity and authentication are ensured using SHA-256 hashing.

## Features

- **Diffie-Hellman Key Exchange:** Securely generate a shared secret key using large prime numbers and a generator.
- **AES Encryption (CBC Mode):** Encrypt financial transaction data using the shared secret key with proper handling of initialization vectors (IV).
- **Message Integrity:** Use SHA-256 hashing to ensure the encrypted message has not been altered during transmission.
- **Demonstration:** Sample financial transaction encryption and decryption with integrity verification.

## Implementation Details

1. **Diffie-Hellman Parameters:**
    - Uses a 2048-bit MODP group prime from RFC 3526.
    - Generator is set to 2.
    - Each party generates a private key and computes a public key.
    - Public keys are exchanged over the network.
    - Each party computes the shared secret using their private key and the other party's public key.

2. **AES Encryption:**
    - AES-256 in CBC mode is used.
    - A random 16-byte IV is generated for each encryption operation.
    - The IV is transmitted along with the encrypted message.
    - The shared secret is used to derive the AES key (first 32 bytes).

3. **Message Integrity:**
    - SHA-256 hash of the encrypted message is computed.
    - The hash is transmitted along with the encrypted message and IV.
    - The receiver verifies the hash to ensure message integrity.

## Dependencies

- OpenSSL library for cryptographic functions (BIGNUM, AES, SHA-256, random number generation).

## Building the Project

Make sure you have OpenSSL development libraries installed.

Compile the project using g++:

```bash
g++ -o SecureFinancialTransactions main.cpp -lcrypto
```

## Running the Project

Run the executable:

```bash
./SecureFinancialTransactions
```

You will see output showing the public keys, shared secrets, encrypted transaction, IV, SHA-256 hash, and decrypted transaction.

## Security Considerations

- The Diffie-Hellman parameters are chosen to be secure against brute-force attacks.
- AES encryption uses a fresh random IV for each encryption to ensure semantic security.
- SHA-256 hashing ensures message integrity and detects tampering.
- This is a demonstration and does not include network transmission code; in a real system, secure channels and authentication mechanisms should be used.

## License

This project is provided for educational purposes.
