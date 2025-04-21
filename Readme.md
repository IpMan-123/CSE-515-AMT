# Secure Financial Transactions

This project demonstrates two different approaches to secure financial transactions using different key exchange protocols and encryption methods.

## Menu Structure

The application provides two main implementations:

1. **Before Mid Term**
   - Uses ECDH (Elliptic Curve Diffie-Hellman) for key exchange
   - Simple encryption/decryption without integrity checks
   - Focused on basic secure communication

2. **After Mid Term**
   - Uses traditional Diffie-Hellman key exchange
   - Includes message integrity checks with SHA-256
   - Provides complete verification of transaction authenticity

## Features

### Before Mid Term Implementation

1. **ECDH Key Exchange:**
   - Uses elliptic curve cryptography for efficient key exchange
   - Generates public/private key pairs on the secp256k1 curve
   - Computes shared secret using ECDH protocol

2. **Operations:**
   - Generate keys (ECDH)
   - Encrypt user input (shows only encrypted value)
   - Decrypt (shows decrypted value)

### After Mid Term Implementation

1. **Diffie-Hellman Key Exchange:**
   - Uses a 2048-bit MODP group prime from RFC 3526
   - Generator is set to 2
   - Each party generates a private key and computes a public key
   - Public keys are exchanged over the network
   - Each party computes the shared secret

2. **AES Encryption:**
   - AES-256 in CBC mode
   - Random 16-byte IV for each encryption
   - IV transmitted with encrypted message
   - Shared secret used to derive AES key

3. **Message Integrity:**
   - SHA-256 hash of the encrypted message
   - Hash transmitted with encrypted message and IV
   - Receiver verifies hash to ensure message integrity

## Implementation Details

### ECDH Implementation (Before Mid Term)
- Uses OpenSSL's EC_KEY for ECC operations
- Implements secure key generation and exchange
- AES encryption using the derived shared secret
- Simplified encryption/decryption process

### Diffie-Hellman Implementation (After Mid Term)
- Uses OpenSSL's BIGNUM for large number operations
- Complete implementation of DH protocol
- Includes integrity verification
- Full transaction security with authentication

## Dependencies

- OpenSSL library for cryptographic functions:
   - BIGNUM (DH implementation)
   - EC_KEY (ECDH implementation)
   - AES
   - SHA-256
   - Random number generation

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

You will see a menu with options to choose between:
1. Before Mid Term (ECDH implementation)
2. After Mid Term (DH implementation)
3. Exit

### Before Mid Term Menu Options:
1. Generate the keys (ECDH)
2. User Input (Encryption only)
3. Decrypt (show decrypted value)
4. Return to Main Menu

### After Mid Term Menu Options:
1. Generate the keys
2. User Input (Enter financial transaction data and encrypt)
3. Check Integrity And Authentication (Decrypt and verify)
4. Return to Main Menu

## Security Considerations

- Both implementations use secure key exchange protocols
- ECDH provides better performance with smaller key sizes
- AES encryption ensures data confidentiality
- SHA-256 hashing (in After Mid Term) ensures message integrity
- This is a demonstration and does not include network transmission code
- In a real system, secure channels and additional authentication mechanisms should be used

## License

This project is provided for educational purposes.
