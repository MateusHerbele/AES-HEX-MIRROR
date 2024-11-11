#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./aes_local.h"
//#include <openssl/aes.h>
//#include <openssl/aes.h>


// Print a buffer as a hex string
void print_hex(unsigned char *buf, int len){
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(){
    // Sample data
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // 256-bit key
    unsigned char *plaintext = (unsigned char *)"Segredo muito! eita";    // Plaintext

    // Buffers for ciphertext, decrypted text and padded text
    unsigned char paddedtext[128];
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    // Padding the plaintext if necessary
   
    // Inicializando a estrutura AES_KEY
    AES_KEY encryptKey;

    // Configuring the encryption key
    if(AES_set_encrypt_key(key, 256, &encryptKey) < 0){
        fprintf(stderr, "Failed to set encryption key\n");
        return 1;
    }

    // Encrypting the plaintext
   teste(plaintext, ciphertext, &encryptKey);
   descriptogranfando(ciphertext, decryptedtext, &encryptKey);

    // Length of the ciphertext
    int ciphertext_len = strlen((char *)plaintext);
    // Length of the decrypted text
    //int decryptedtext_len = strlen((char *)decryptedtext);
    //decryptedtext[decryptedtext_len] = '\0';


    // Printing results
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    print_hex(ciphertext, ciphertext_len);
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
