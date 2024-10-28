#include <stdio.h>
#include <stdlib.h>
#include "aux.h"

int main(void){
    // Sample data
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // 256-bit key
    unsigned char *iv = (unsigned char *)"0123456789012345";                 // 128-bit IV
    unsigned char *plaintext = (unsigned char *)"Segredo muito secreto!";    // Plaintext

    // Buffers for ciphertext and decrypted text
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    // Encrypt the plaintext
    int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);

    // Decrypt the ciphertext
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    // Null-terminate the decrypted text
    decryptedtext[decryptedtext_len] = '\0';

    // Print results
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    for(int i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]); // 02x means print at least 2 digits, with leading zeros
    printf("\n");
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
