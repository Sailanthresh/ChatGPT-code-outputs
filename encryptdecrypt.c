#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// This function encrypts the contents of a file using the AES-256 algorithm in CBC mode
// and a password. It derives the encryption key from the password using PBKDF2-HMAC-SHA256.
void encrypt_file(const char *filename, const char *password) {
    // Open the file in read/write mode
    FILE *file = fopen(filename, "r+");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Read the file's contents into a buffer
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *buffer = malloc(size);
    fread(buffer, size, 1, file);

    // Generate a random 16-byte IV
    unsigned char iv[16];
    RAND_bytes(iv, 16);

    // Derive a 32-byte key from the password using PBKDF2-HMAC-SHA256
    unsigned char key[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), iv, 16, 10000, EVP_sha256(), 32, key);

    // Create a new AES-256 encryption context
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);

    // Encrypt the buffer using AES-256 in CBC mode
    AES_cbc_encrypt(buffer, buffer, size, &aes_key, iv, AES_ENCRYPT);

    // Write the IV and encrypted data back to the file
    fseek(file, 0, SEEK_SET);
    fwrite(iv, 16, 1, file);
    fwrite(buffer, size, 1, file);

    // Close the file and free the buffer
    fclose(file);
    free(buffer);
}

// This function decrypts the contents of a file using the AES-256 algorithm in CBC mode
// and a password. It derives the decryption key from the password using PBKDF2-HMAC-SHA256.
void decrypt_file(const char *filename, const char *password) {
    // Open the file