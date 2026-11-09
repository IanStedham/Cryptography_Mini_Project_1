///////////////////////////////
//   Alice as a Signer      //
//////////////////////////////

/*************************************
 *      Signcryption Project         *
 *************************************
 *Description:      1. Alice reads the message from "Message.txt"
 *                  2. Alice reads parameters and keys from files
 *                  3. Alice signcrypts the message for Bob
 *                  4. Alice writes the signcryption to "Signcryption.txt"
 *                  5. Alice writes the signcryption to "SigncryptedMessage.txt" for Bob to read
 * 
 *
 *Compile:          gcc Sign.c -lcrypto -o Alice
 * 
 *Run:              ./Alice Message#.txt Seed#.txt
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
unsigned char* Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char *input);
void Read_Parameters(BIGNUM **p, BIGNUM **q, BIGNUM **g);
void Read_Keys(char *filename, BIGNUM **private_key, BIGNUM **public_key);
void Read_Public_Key(char *filename, BIGNUM **public_key);
void Hash_G(const BIGNUM *w, unsigned char *key, size_t key_len);
void Hash_H(const unsigned char *message, size_t message_len, const BIGNUM *w, BIGNUM *r);
void Encrypt_Message(const unsigned char *key, const unsigned char *message, size_t message_len, unsigned char **ciphertext, size_t *ciphertext_len, unsigned char *seed, size_t seed_len);
void Signcrypt(BIGNUM *p, BIGNUM *q, BIGNUM *g, const unsigned char *message, size_t message_len, BIGNUM *alice_private_key, BIGNUM *bob_public_key, BIGNUM **r, BIGNUM **s, unsigned char **ciphertext, size_t *ciphertext_len, unsigned char *seed, size_t seed_len, int seed_offset);
unsigned char* PRNG(unsigned char *seed, size_t seed_len, size_t output_len);
void Show_BN(const char *label, const BIGNUM *bn);
void Show_Hex(const char *label, const unsigned char *data, size_t len);
void Write_Signcryption_To_File(BIGNUM *r, BIGNUM *s, unsigned char *ciphertext, size_t ciphertext_len, const char *filename);

/*************************************************************
                        M A I N
**************************************************************/
int main(int argc, char* argv[])
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Check command line arguments
    if (argc < 3) {
        printf("Usage: %s <message_file> <seed_file>\n", argv[0]);
        return 1;
    }
    
    // Read message from file
    printf("Getting the Message from File . . .\n");
    int message_length = 0;
    unsigned char* message = Read_File(argv[1], &message_length);
    printf("Message: %s\n", message);
    printf("Message Length: %d\n", message_length);

    // Read seed from file
    printf("Getting the Seed from File . . .\n");
    int seed_length = 0;
    unsigned char* seed = Read_File(argv[2], &seed_length);
    printf("Seed: %s\n", seed);
    printf("Seed Length: %d\n", seed_length);
    
    // Prepare seed for PRNG
    // Create a 32-byte seed for ChaCha20 by hashing the input seed
    unsigned char prng_seed[32];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, seed, seed_length);
    SHA256_Final(prng_seed, &sha_ctx);

    printf("\n==================================================\n");

    // Read parameters (p, q, g)
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    printf("Reading parameters (p, q, g)...\n");
    Read_Parameters(&p, &q, &g);
    
    Show_BN("p", p);
    Show_BN("q", q);
    Show_BN("g", g);

    printf("\n==================================================\n");

    // Read Alice's keys
    BIGNUM *alice_private_key = NULL, *alice_public_key = NULL;
    printf("Reading Alice's keys...\n");
    Read_Keys("AliceKeys.txt", &alice_private_key, &alice_public_key);
    
    Show_BN("Alice's private key (x_a)", alice_private_key);
    Show_BN("Alice's public key (y_a)", alice_public_key);

    printf("\n==================================================\n");

    // Read Bob's public key
    BIGNUM *bob_public_key = NULL;
    printf("Reading Bob's public key...\n");
    Read_Public_Key("BobPublicKey.txt", &bob_public_key);
    
    Show_BN("Bob's public key (y_b)", bob_public_key);

    printf("\n==================================================\n");

    // Signcrypt the message
    printf("Signcrypting the message...\n");
    BIGNUM *r = NULL, *s = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    Signcrypt(p, q, g, message, message_length, alice_private_key, bob_public_key, &r, &s, &ciphertext, &ciphertext_len, prng_seed, sizeof(prng_seed), 2);
    
    Show_BN("r", r);
    Show_BN("s", s);
    Show_Hex("Ciphertext", ciphertext, ciphertext_len);

    printf("\n==================================================\n");

    // Write signcryption to file
    printf("Writing signcryption to file...\n");
    
    FILE *signcryption_file = fopen("Signcryption.txt", "wb");
    if (signcryption_file == NULL) {
        printf("Error opening Signcryption.txt for writing\n");
        exit(1);
    }
    
    char *r_hex = BN_bn2hex(r);
    char *s_hex = BN_bn2hex(s);
    
    fprintf(signcryption_file, "r: %s\n", r_hex);
    fprintf(signcryption_file, "s: %s\n", s_hex);
    fprintf(signcryption_file, "ciphertext_len: %zu\n", ciphertext_len);
    fprintf(signcryption_file, "ciphertext: ");
    
    for (size_t i = 0; i < ciphertext_len; i++) {
        fprintf(signcryption_file, "%02x", ciphertext[i]);
    }
    fprintf(signcryption_file, "\n");
    
    fclose(signcryption_file);
    
    OPENSSL_free(r_hex);
    OPENSSL_free(s_hex);

    printf("\n==================================================\n");

    // Write signcryption to file for Bob
    printf("Writing signcryption to file for Bob...\n");
    Write_Signcryption_To_File(r, s, ciphertext, ciphertext_len, "SigncryptedMessage.txt");
    
    // Free memory
    free(ciphertext);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(alice_private_key);
    BN_free(alice_public_key);
    BN_free(bob_public_key);
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
        Read from File
==============================*/
unsigned char* Read_File(char fileName[], int *fileLen)
{
    FILE *pFile;
    pFile = fopen(fileName, "rb");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile);
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
    *fileLen = fread(output, 1, temp_size, pFile);
    fclose(pFile);
    return output;
}

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
    // Full Domain Hash to expand to 2048 bits
    // We'll hash 8 times with different counters and concatenate the results

    // Buffer to hold the 2048-bit (256-byte) result
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
    Encrypt Message
==============================*/
void Encrypt_Message(const unsigned char *key, const unsigned char *message, size_t message_len, unsigned char **ciphertext, size_t *ciphertext_len, unsigned char *seed, size_t seed_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    

    // Create a modified seed for x generation using PRNG
    unsigned char iv_seed[32];
    unsigned char iv_seed_modifier[32];
    memcpy(iv_seed_modifier, seed, seed_len);
    iv_seed_modifier[31] = (unsigned char)(3); 
    unsigned char *prng_out = PRNG(iv_seed_modifier, 32, 32);
    memcpy(iv_seed, prng_out, 32);
    free(prng_out);
    
    unsigned char *iv_bytes = PRNG(iv_seed, 32, 16);
    unsigned char iv[16];
    memcpy(iv, iv_bytes, 16);
    free(iv_bytes);
    
    // Initialize encryption
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    
    // Allocate memory for ciphertext (message + padding + IV)
    *ciphertext = malloc(message_len + EVP_CIPHER_block_size(EVP_aes_128_cbc()) + sizeof(iv));
    
    // Copy IV to the beginning of ciphertext
    memcpy(*ciphertext, iv, sizeof(iv));
    
    // Encrypt message
    int len;
    int ciphertext_offset = sizeof(iv);
    EVP_EncryptUpdate(ctx, *ciphertext + ciphertext_offset, &len, message, message_len);
    ciphertext_offset += len;
    
    EVP_EncryptFinal_ex(ctx, *ciphertext + ciphertext_offset, &len);
    ciphertext_offset += len;
    
    *ciphertext_len = ciphertext_offset;
    EVP_CIPHER_CTX_free(ctx);
}

/*============================
    Signcrypt
==============================*/
void Signcrypt(BIGNUM *p, BIGNUM *q, BIGNUM *g, const unsigned char *message, size_t message_len, BIGNUM *alice_private_key, 
    BIGNUM *bob_public_key, BIGNUM **r, BIGNUM **s, unsigned char **ciphertext, size_t *ciphertext_len, unsigned char *seed, 
    size_t seed_len, int seed_offset)
{
    BN_CTX *bn_ctx = BN_CTX_new();

    // 1. Generate random k using PRNG with modified seed
    unsigned char seed_cpy[32] = {0};
    memcpy(seed_cpy, seed, seed_len);
    seed_cpy[31] = (unsigned char)seed_offset;

    // unsigned char *prng = PRNG(seed_cpy, (size_t)32, (size_t)32);
    unsigned char *x_seed = PRNG(seed_cpy, (size_t)32, (size_t)32);
    unsigned char *k_bytes = PRNG(x_seed, (size_t)32, (size_t)32); 

    BIGNUM *k = BN_new();
    // BN_bin2bn(prng, 32, k);
    BN_bin2bn(k_bytes, 32, k);
    BN_mod(k, k, q, bn_ctx);   
    // printf("Step 1\n");
    Show_BN("k: ", k);
    printf("\n");

    // 2. Compute w = y_b^k mod p (shared secret)
    BIGNUM *w = BN_new();
    BN_mod_exp(w, bob_public_key, k, p, bn_ctx);
    // printf("Step 2\n");
    // Show_BN("w: ", w);
    // printf("\n");

    // 3. Derive encryption key K_e = Hash_G(w)
    unsigned char *K_e = malloc(16);
    Hash_G(w, K_e, 16);
    // printf("Step 3\n");
    // printf("K_e: %s\n\n", K_e);

    // 4. Encrypt the message using K_e
    Encrypt_Message(K_e, message, message_len, ciphertext, ciphertext_len, seed_cpy, seed_len);
    // printf("Step 4\n");
    // printf("message: %s\n", message);
    // printf("ciphertext: %s\n\n", *ciphertext);

    // 5. Compute r = Hash_H(m, w)
    *r = BN_new();
    Hash_H(message, message_len, w, *r);
    // printf("Step 5\n");
    //Show_BN("r: ", *r);
    // printf("\n\n");

    // 6. Compute s = x/(r + x_a) mod q
    BIGNUM *denominator = BN_new();
    *s = BN_new();
    BN_add(denominator, *r, alice_private_key);
    BN_mod_inverse(denominator, denominator, q, bn_ctx);
    BN_mod_mul(*s, k, denominator, q, bn_ctx);
    //Show_BN("s: ", *s);
    // printf("Step 6\n");

    // 7. Compute c = E_k(m) (encrypt the message)
    // this step might be wrong
    Encrypt_Message(K_e, message, message_len, ciphertext, ciphertext_len, seed_cpy, seed_len);
    // printf("Step 7\n");

    free(x_seed);
    free(k_bytes);
    // free(prng);
    free(K_e);
    BN_free(k);
    BN_free(w);
    BN_free(denominator);
    BN_CTX_free(bn_ctx);
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

/*============================
    PRNG Function 
==============================*/
unsigned char* PRNG(unsigned char *seed, size_t seed_len, size_t output_len)
{
    // User-provided seed (must be 32 bytes for ChaCha20)
    if (seed_len != 32) {
        printf("Seed length must be 32 bytes.\n");
        return NULL;
    }

    // Fixed and zeroed iv (16 bytes (4 counter, 12 nonce))
    unsigned char iv[16] = {0};

    // Output buffer
    unsigned char* output = malloc(output_len + 1); // +1 for possible null terminator
    unsigned char plaintext[output_len];
    memset(plaintext, 0, sizeof(plaintext));  // Encrypting zeros

    // Initialize ChaCha20 context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context.\n");
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to initialize cipher.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Set seed and nonce
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, seed, iv) != 1) {
        fprintf(stderr, "Failed to set key and nonce.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Encrypt (in the context of chacha20, simply XORs plaintext with keystream, and since plaintext is zeroes, result is just keystream)
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, output, &outlen, plaintext, sizeof(plaintext)) != 1) {
        fprintf(stderr, "Encryption failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    return output;
}

/*============================
    Write Signcryption To File
==============================*/
void Write_Signcryption_To_File(BIGNUM *r, BIGNUM *s, unsigned char *ciphertext, size_t ciphertext_len, const char *filename)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Error opening file %s for writing\n", filename);
        exit(1);
    }
    
    // Write r
    char *r_hex = BN_bn2hex(r);
    fprintf(file, "r: %s\n", r_hex);
    OPENSSL_free(r_hex);
    
    // Write s
    char *s_hex = BN_bn2hex(s);
    fprintf(file, "s: %s\n", s_hex);
    OPENSSL_free(s_hex);
    
    // Write ciphertext length
    fprintf(file, "ciphertext_len: %zu\n", ciphertext_len);
    
    // Write ciphertext in hex format
    fprintf(file, "ciphertext: ");
    for (size_t i = 0; i < ciphertext_len; i++) {
        fprintf(file, "%02x", ciphertext[i]);
    }
    fprintf(file, "\n");
    
    fclose(file);
    printf("Signcryption written to %s\n", filename);
}