///////////////////////////////
//   Certificate Authority  //
//////////////////////////////

/*************************************
 *      Signcryption Project         *
 *************************************
 *Description:      1. CA reads the seed (32 Bytes) from "Seed#.txt" file
 *                  2. CA reads system parameters (p, q, g) from parameter file
 *                  3. CA generates key pairs for Alice and Bob
 *                  4. CA writes parameters and keys to files
 *
 *
 *Compile:          gcc KeyGen.c -lcrypto -o CertificateAuthority
 *
 *Run:              ./CertificateAuthority Seed#.txt Parameters#.txt
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
void Write_BN_to_File(char fileName[], BIGNUM *bn, const char *label);
void Read_Parameters_From_File(char *filename, BIGNUM **p, BIGNUM **q, BIGNUM **g);
void Generate_Key_Pair(BIGNUM *p, BIGNUM *q, BIGNUM *g, BIGNUM **private_key, BIGNUM **public_key, unsigned char *seed, int seed_offset);
void Show_BN(const char *label, const BIGNUM *bn);
unsigned char* PRNG(unsigned char *seed, size_t seed_len, size_t output_len);

/*************************************************************
                        M A I N
**************************************************************/
int main(int argc, char* argv[])
{   
    // Check command line arguments
    if (argc < 3) {
        printf("Usage: %s <seed_file> <parameters_file>\n", argv[0]);
        return 1;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Read seed from file
    printf("Getting the Seed from File . . .\n");
    int seed_length = 0;
    unsigned char* seed = Read_File(argv[1], &seed_length);
    printf("Seed: %s\n", seed);
    printf("Seed Length: %d\n", seed_length);

    printf("\n==================================================\n");

    // Read parameters (p, q, g) from file
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    printf("Reading parameters (p, q, g) from file %s...\n", argv[2]);
    Read_Parameters_From_File(argv[2], &p, &q, &g);
    
    Show_BN("p", p);
    Show_BN("q", q);
    Show_BN("g", g);

    printf("\n==================================================\n");

    // Generate Alice's key pair
    BIGNUM *alice_private_key = NULL, *alice_public_key = NULL;
    printf("Generating Alice's key pair...\n");
    Generate_Key_Pair(p, q, g, &alice_private_key, &alice_public_key, seed, 0);
    
    Show_BN("Alice's private key (x_a)", alice_private_key);
    Show_BN("Alice's public key (y_a)", alice_public_key);

    printf("\n==================================================\n");

    // Generate Bob's key pair
    BIGNUM *bob_private_key = NULL, *bob_public_key = NULL;
    printf("Generating Bob's key pair...\n");
    Generate_Key_Pair(p, q, g, &bob_private_key, &bob_public_key, seed, 1);
    
    Show_BN("Bob's private key (x_b)", bob_private_key);
    Show_BN("Bob's public key (y_b)", bob_public_key);

    printf("\n==================================================\n");

    // Write parameters and keys to files
    printf("Writing parameters and keys to files...\n");
    
    // Write parameters to Params.txt
    FILE *params_file = fopen("Params.txt", "w");
    if (params_file == NULL) {
        printf("Error opening Params.txt for writing\n");
        exit(1);
    }
    
    char *p_hex = BN_bn2hex(p);
    char *q_hex = BN_bn2hex(q);
    char *g_hex = BN_bn2hex(g);
    
    fprintf(params_file, "p: %s\n", p_hex);
    fprintf(params_file, "q: %s\n", q_hex);
    fprintf(params_file, "g: %s\n", g_hex);
    
    fclose(params_file);
    
    // Write Alice's keys to AliceKeys.txt
    FILE *alice_keys_file = fopen("AliceKeys.txt", "w");
    if (alice_keys_file == NULL) {
        printf("Error opening AliceKeys.txt for writing\n");
        exit(1);
    }
    
    char *alice_private_hex = BN_bn2hex(alice_private_key);
    char *alice_public_hex = BN_bn2hex(alice_public_key);
    
    fprintf(alice_keys_file, "x_a: %s\n", alice_private_hex);
    fprintf(alice_keys_file, "y_a: %s\n", alice_public_hex);
    
    fclose(alice_keys_file);
    
    // Write Bob's keys to BobKeys.txt
    FILE *bob_keys_file = fopen("BobKeys.txt", "w");
    if (bob_keys_file == NULL) {
        printf("Error opening BobKeys.txt for writing\n");
        exit(1);
    }
    
    char *bob_private_hex = BN_bn2hex(bob_private_key);
    char *bob_public_hex = BN_bn2hex(bob_public_key);
    
    fprintf(bob_keys_file, "x_b: %s\n", bob_private_hex);
    fprintf(bob_keys_file, "y_b: %s\n", bob_public_hex);
    
    fclose(bob_keys_file);
    
    // Write Alice's public key to AlicePublicKey.txt
    FILE *alice_public_file = fopen("AlicePublicKey.txt", "w");
    if (alice_public_file == NULL) {
        printf("Error opening AlicePublicKey.txt for writing\n");
        exit(1);
    }
    
    fprintf(alice_public_file, "y_a: %s\n", alice_public_hex);
    
    fclose(alice_public_file);
    
    // Write Bob's public key to BobPublicKey.txt
    FILE *bob_public_file = fopen("BobPublicKey.txt", "w");
    if (bob_public_file == NULL) {
        printf("Error opening BobPublicKey.txt for writing\n");
        exit(1);
    }
    
    fprintf(bob_public_file, "y_b: %s\n", bob_public_hex);
    
    fclose(bob_public_file);
    
    // Free memory
    OPENSSL_free(p_hex);
    OPENSSL_free(q_hex);
    OPENSSL_free(g_hex);
    OPENSSL_free(alice_private_hex);
    OPENSSL_free(alice_public_hex);
    OPENSSL_free(bob_private_hex);
    OPENSSL_free(bob_public_hex);
    
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(alice_private_key);
    BN_free(alice_public_key);
    BN_free(bob_private_key);
    BN_free(bob_public_key);
    
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
    pFile = fopen(fileName, "r");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
    fgets(output, temp_size, pFile);
    fclose(pFile);

    *fileLen = temp_size-1;
    return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char *input)
{
    FILE *pFile;
    pFile = fopen(fileName, "w");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    fputs(input, pFile);
    fclose(pFile);
}

/*============================
    Write BIGNUM to File
==============================*/
void Write_BN_to_File(char fileName[], BIGNUM *bn, const char *label)
{
    FILE *pFile;
    pFile = fopen(fileName, "w");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    
    char *hex = BN_bn2hex(bn);
    fprintf(pFile, "%s: %s\n", label, hex);
    OPENSSL_free(hex);
    
    fclose(pFile);
}

/*============================
    Read Parameters From File
==============================*/
void Read_Parameters_From_File(char *filename, BIGNUM **p, BIGNUM **q, BIGNUM **g)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening parameter file: %s\n", filename);
        exit(1);
    }
    
    char line[2048];
    char value[2048];
    
    // Initialize p, q, g
    *p = BN_new();
    *q = BN_new();
    *g = BN_new();
    
    // Read p
    if (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "p: %s", value) == 1) {
            BN_hex2bn(p, value);
        } else {
            printf("Error parsing p from file\n");
            exit(1);
        }
    } else {
        printf("Error reading p from file\n");
        exit(1);
    }
    
    // Read q
    if (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "q: %s", value) == 1) {
            BN_hex2bn(q, value);
        } else {
            printf("Error parsing q from file\n");
            exit(1);
        }
    } else {
        printf("Error reading q from file\n");
        exit(1);
    }
    
    // Read g
    if (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "g: %s", value) == 1) {
            BN_hex2bn(g, value);
        } else {
            printf("Error parsing g from file\n");
            exit(1);
        }
    } else {
        printf("Error reading g from file\n");
        exit(1);
    }
    
    fclose(file);
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
    Generate Key Pair
==============================*/
void Generate_Key_Pair(BIGNUM *p, BIGNUM *q, BIGNUM *g, BIGNUM **private_key, BIGNUM **public_key, unsigned char *seed, int seed_offset)
{
    BN_CTX *bn_ctx = BN_CTX_new();

    // 1. Create a modified seed with the offset
    seed[31] += (unsigned char)seed_offset;

    // 2. Use PRNG to generate random bytes
    unsigned char *prng = PRNG(seed, (size_t)32, (size_t)BN_num_bytes(q));
    
    // 3. Convert random bytes to BIGNUM for private key
    *private_key = BN_new();
    BN_bin2bn(prng, BN_num_bytes(q), *private_key);

    // 4. Ensure private key is in range [1, q-1]
    BN_mod(*private_key, *private_key, q, bn_ctx);

    // 5. Calculate public key as g^x mod p
    *public_key = BN_new();
    BN_mod_exp(*public_key, g, *private_key, p, bn_ctx);
;
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