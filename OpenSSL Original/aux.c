#include "aux.h"

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context 
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the encryption operation with AES-256-CBC 
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();

    // Provide the message to be encrypted, and obtain the encrypted output 
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    // Finalize the encryption 
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    // Clean up 
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context 
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the decryption operation with AES-256-CBC 
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();

    // Provide the message to be decrypted, and obtain the plaintext output 
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    // Finalize the decryption 
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    // Clean up 
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
