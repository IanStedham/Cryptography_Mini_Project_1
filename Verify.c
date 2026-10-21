///////////////////////////////
//   Bob as a Verifier       //
//////////////////////////////

/*************************************
 *      Signcryption Project         *
 *************************************
 *Description:      1. Bob reads the signcryption from "SigncryptedMessage.txt" file
 *                  2. Bob reads parameters and keys from files
 *                  3. Bob unsigncrypts the message
 *                  4. Bob verifies the signcryption
 *                  5. Bob writes the verification result to "Verification.txt"
 *                  6. Bob writes the decrypted message to "DecryptedMessage.txt" if verification succeeds
 * 
 *
 *Compile:          gcc Verify.c -lcrypto -o Bob
 * 
 *Run:              ./Bob
 *
 *Documentation:    OpenSSL Manual
 *
 * Created By:       *Lazar Lazarevic* 
 *************************************/

//Header Files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Function prototypes
void Write_File(char fileName[], char *input);
void Read_Parameters(BIGNUM **p, BIGNUM **q, BIGNUM **g);
void Read_Keys(char *filename, BIGNUM **private_key, BIGNUM **public_key);
void Read_Public_Key(char *filename, BIGNUM **public_key);
void Hash_G(const BIGNUM *w, unsigned char *key, size_t key_len);
void Hash_H(const unsigned char *message, size_t message_len, const BIGNUM *w, BIGNUM *r);
int Decrypt_Message(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **message, size_t *message_len);
int Unsigncrypt(BIGNUM *p, BIGNUM *q, BIGNUM *g, BIGNUM *r, BIGNUM *s, const unsigned char *ciphertext, size_t ciphertext_len, BIGNUM *bob_private_key, BIGNUM *alice_public_key, unsigned char **message, size_t *message_len);
void Show_BN(const char *label, const BIGNUM *bn);
void Show_Hex(const char *label, const unsigned char *data, size_t len);
void Read_Signcryption_From_File(const char *filename, BIGNUM **r, BIGNUM **s, unsigned char **ciphertext, size_t *ciphertext_len);

/*************************************************************
                        M A I N
**************************************************************/
int main(int argc, char* argv[])
{   
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Read signcryption from file
    printf("Reading signcryption from file...\n");
    BIGNUM *r = NULL, *s = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    Read_Signcryption_From_File("SigncryptedMessage.txt", &r, &s, &ciphertext, &ciphertext_len);
    
    Show_BN("r", r);
    Show_BN("s", s);
    Show_Hex("Ciphertext", ciphertext, ciphertext_len);

    printf("\n==================================================\n");

    // Read parameters (p, q, g)
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    printf("Reading parameters (p, q, g)...\n");
    Read_Parameters(&p, &q, &g);
    
    Show_BN("p", p);
    Show_BN("q", q);
    Show_BN("g", g);

    printf("\n==================================================\n");

    // Read Bob's keys
    BIGNUM *bob_private_key = NULL, *bob_public_key = NULL;
    printf("Reading Bob's keys...\n");
    Read_Keys("BobKeys.txt", &bob_private_key, &bob_public_key);
    
    Show_BN("Bob's private key (x_b)", bob_private_key);
    Show_BN("Bob's public key (y_b)", bob_public_key);

    printf("\n==================================================\n");

    // Read Alice's public key
    BIGNUM *alice_public_key = NULL;
    printf("Reading Alice's public key...\n");
    Read_Public_Key("AlicePublicKey.txt", &alice_public_key);
    
    Show_BN("Alice's public key (y_a)", alice_public_key);

    printf("\n==================================================\n");

    // Unsigncrypt the message
    printf("Unsigncrypting the message...\n");
    unsigned char *message = NULL;
    size_t message_len = 0;
    
    int result = Unsigncrypt(p, q, g, r, s, ciphertext, ciphertext_len, bob_private_key, alice_public_key, &message, &message_len);
    
    if (result) {
        printf("Verification successful!\n");
        printf("Decrypted message: %.*s\n", (int)message_len, message);
        
        // Write verification result to file
        Write_File("Verification.txt", "Signature is Valid");
        
        // Write decrypted message to file in binary mode
        FILE *decrypted_file = fopen("DecryptedMessage.txt", "wb");
        if (decrypted_file == NULL) {
            printf("Error opening DecryptedMessage.txt for writing\n");
            exit(1);
        }
        fwrite(message, 1, message_len, decrypted_file);
        fclose(decrypted_file);
        
        free(message);
    } else {
        printf("Verification failed!\n");
        
        // Write verification result to file
        Write_File("Verification.txt", "Signature is Invalid");
    }
    
    // Free memory
    free(ciphertext);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(bob_private_key);
    BN_free(bob_public_key);
    BN_free(alice_public_key);
    BN_free(r);
    BN_free(s);
    
    EVP_cleanup();
    
    printf("==============The End========================\n");

    return 0;
}

/*************************************************************
                    F u n c t i o n s
**************************************************************/
/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char *input)
{
    FILE *pFile;
    pFile = fopen(fileName, "wb");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    fputs(input, pFile);
    fclose(pFile);
}

/*============================
    Read Parameters
==============================*/
void Read_Parameters(BIGNUM **p, BIGNUM **q, BIGNUM **g)
{
    FILE *params_file = fopen("Params.txt", "r");
    if (params_file == NULL) {
        printf("Error opening Params.txt for reading\n");
        exit(1);
    }
    
    char line[1024];
    char value[1024];
    
    // Read p
    fgets(line, sizeof(line), params_file);
    sscanf(line, "p: %s", value);
    *p = BN_new();
    BN_hex2bn(p, value);
    
    // Read q
    fgets(line, sizeof(line), params_file);
    sscanf(line, "q: %s", value);
    *q = BN_new();
    BN_hex2bn(q, value);
    
    // Read g
    fgets(line, sizeof(line), params_file);
    sscanf(line, "g: %s", value);
    *g = BN_new();
    BN_hex2bn(g, value);
    
    fclose(params_file);
}

/*============================
    Read Keys
==============================*/
void Read_Keys(char *filename, BIGNUM **private_key, BIGNUM **public_key)
{
    FILE *keys_file = fopen(filename, "r");
    if (keys_file == NULL) {
        printf("Error opening %s for reading\n", filename);
        exit(1);
    }
    
    char line[1024];
    char value[1024];
    
    // Read private key
    fgets(line, sizeof(line), keys_file);
    if (strstr(line, "x_a:")) {
        sscanf(line, "x_a: %s", value);
    } else {
        sscanf(line, "x_b: %s", value);
    }
    *private_key = BN_new();
    BN_hex2bn(private_key, value);
    
    // Read public key
    fgets(line, sizeof(line), keys_file);
    if (strstr(line, "y_a:")) {
        sscanf(line, "y_a: %s", value);
    } else {
        sscanf(line, "y_b: %s", value);
    }
    *public_key = BN_new();
    BN_hex2bn(public_key, value);
    
    fclose(keys_file);
}

/*============================
    Read Public Key
==============================*/
void Read_Public_Key(char *filename, BIGNUM **public_key)
{
    FILE *public_key_file = fopen(filename, "r");
    if (public_key_file == NULL) {
        printf("Error opening %s for reading\n", filename);
        exit(1);
    }
    
    char line[1024];
    char value[1024];
    
    // Read public key
    fgets(line, sizeof(line), public_key_file);
    if (strstr(line, "y_a:")) {
        sscanf(line, "y_a: %s", value);
    } else {
        sscanf(line, "y_b: %s", value);
    }
    *public_key = BN_new();
    BN_hex2bn(public_key, value);
    
    fclose(public_key_file);
}

/*============================
    Read Signcryption From File
==============================*/
void Read_Signcryption_From_File(const char *filename, BIGNUM **r, BIGNUM **s, unsigned char **ciphertext, size_t *ciphertext_len)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening %s for reading\n", filename);
        exit(1);
    }
    
    char line[65536];  // Large buffer for ciphertext
    char value[65536];
    
    // Read r
    fgets(line, sizeof(line), file);
    sscanf(line, "r: %s", value);
    *r = BN_new();
    BN_hex2bn(r, value);
    
    // Read s
    fgets(line, sizeof(line), file);
    sscanf(line, "s: %s", value);
    *s = BN_new();
    BN_hex2bn(s, value);
    
    // Read ciphertext length
    fgets(line, sizeof(line), file);
    sscanf(line, "ciphertext_len: %zu", ciphertext_len);
    
    // Read ciphertext
    fgets(line, sizeof(line), file);
    sscanf(line, "ciphertext: %s", value);
    
    // Convert hex ciphertext to binary
    *ciphertext = malloc(*ciphertext_len);
    for (size_t i = 0; i < *ciphertext_len; i++) {
        sscanf(&value[i*2], "%2hhx", &(*ciphertext)[i]);
    }
    
    fclose(file);
}

/*============================
    Hash Function G
==============================*/
void Hash_G(const BIGNUM *w, unsigned char *key, size_t key_len)
{
    unsigned char w_bin[256];
    int w_len = BN_bn2bin(w, w_bin);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(w_bin, w_len, hash);

    // Truncate to 128 bits (16 bytes)
    size_t copy_len = key_len < 16 ? key_len : 16;
    memcpy(key, hash, copy_len);
}

/*============================
    Hash Function H
==============================*/
void Hash_H(const unsigned char *message, size_t message_len, const BIGNUM *w, BIGNUM *r)
{
    // Implement Full Domain Hash to expand to 2048 bits
    // We'll hash 8 times with different counters and concatenate the results
    
    // First, create a buffer to hold the 2048-bit (256-byte) result
    unsigned char full_hash[256]; // 2048 bits = 256 bytes
    
    // Initial hash of message and w
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    
    // Hash the message
    EVP_DigestUpdate(mdctx, message, message_len);
    
    // Hash w
    unsigned char w_bin[256];
    int w_len = BN_bn2bin(w, w_bin);
    EVP_DigestUpdate(mdctx, w_bin, w_len);
    
    // Finalize initial hash
    unsigned char initial_hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, initial_hash, &hash_len);
    
    // Copy the initial hash to the first part of the full hash
    memcpy(full_hash, initial_hash, SHA256_DIGEST_LENGTH);
    
    // Generate the remaining 7 hash blocks (32 bytes each)
    for (int i = 1; i < 8; i++) {
        // Create a new hash context for each iteration
        EVP_MD_CTX *iter_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(iter_ctx, EVP_sha256(), NULL);
        
        // Hash the previous hash result
        EVP_DigestUpdate(iter_ctx, initial_hash, SHA256_DIGEST_LENGTH);
        
        // Add a counter to ensure different hash outputs
        unsigned char counter = i;
        EVP_DigestUpdate(iter_ctx, &counter, 1);
        
        // Finalize this iteration's hash
        EVP_DigestFinal_ex(iter_ctx, full_hash + (i * SHA256_DIGEST_LENGTH), &hash_len);
        EVP_MD_CTX_free(iter_ctx);
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Convert the full 2048-bit hash to BIGNUM
    BN_bin2bn(full_hash, 256, r);
}

/*============================
    Decrypt Message
==============================*/
int Decrypt_Message(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **message, size_t *message_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // Extract IV from the beginning of ciphertext
    unsigned char iv[16];
    memcpy(iv, ciphertext, sizeof(iv));
    
    // Initialize decryption
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    
    // Allocate memory for plaintext
    *message = malloc(ciphertext_len);
    
    // Decrypt ciphertext
    int len;
    EVP_DecryptUpdate(ctx, *message, &len, ciphertext + sizeof(iv), ciphertext_len - sizeof(iv));
    int plaintext_len = len;
    
    int ret = EVP_DecryptFinal_ex(ctx, *message + len, &len);
    plaintext_len += len;
    *message_len = plaintext_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*============================
    Unsigncrypt
==============================*/
int Unsigncrypt(BIGNUM *p, BIGNUM *q, BIGNUM *g, BIGNUM *r, BIGNUM *s, const unsigned char *ciphertext, size_t ciphertext_len, BIGNUM *bob_private_key, BIGNUM *alice_public_key, unsigned char **message, size_t *message_len)
{
/*============================
    YOUR CODE HERE
==============================*/
}

/*============================
    Show BIGNUM
==============================*/
void Show_BN(const char *label, const BIGNUM *bn)
{
    char *hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

/*============================
    Show Hex
==============================*/
void Show_Hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}