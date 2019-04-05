#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "tiny-AES128-C-master/aes.h"

static void counter(unsigned long long *n)
{
    /* unique counter, it's just an increment */
    n++;
}

/*  generate initialization vector */
static void gen_iv(char iv[16])
{
    int i;
    srand(time(NULL));

    for(i = 0; i < 8; i++)
        iv[i] = rand() % 256;
}

static void aes_ctr_encrypt(const uint8_t* key, uint8_t* iv,
                char *data_unenc, int size_data_unenc,
                char *data_enc, int size_data_enc)
{
    unsigned long long cnt = 0;
    int i, j;
    char out[16];

    for(i = 0; i < size_data_enc; i += 16) {
        counter(&cnt);
        memcpy(iv + 8, &cnt, 8); /* IV concat counter */
        AES128_ECB_encrypt(iv, key, out); 
        for(j = i; j < i + 16; j++) /* XOR */
            data_enc[j] = out[j] ^ data_unenc[j];
    }
}

static void aes_ctr_decrypt(const uint8_t* key, uint8_t* iv,
                char *data_enc, int size_data_enc,
                char *data_unenc)
{
    unsigned long long cnt = 0;
    int i, j;
    char out[16];

    for(i = 0; i < size_data_enc; i += 16) {
        counter(&cnt);
        memcpy(iv + 8, &cnt, 8); /* IV concat counter */
        AES128_ECB_encrypt(iv, key, out); 
        for(j = i; j < i + 16; j++) /* XOR */
            data_unenc[j] = out[j] ^ data_enc[j];
    }
}

/*
 * The program requires two arguments:
 *  - unecrypted_file
 *  -the file that will contain the encrypted unecrypted_file
 */

int main(int argc, char **argv)
{
    /* a key */
    char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    char iv[16] = {0};

    FILE *fin, *fout, *fcheck;
    char *data_unenc, *data_enc = NULL, *data_check;
    int size_data_unenc, size_data_enc;

    if (argc != 3) {
        printf("Usage: escrypt unencrypted_file encrypted_file\n");
        return -1;
    }

    fin = fopen(argv[1], "r");
    if (!fin) {
        printf("fopen: Unable to open unencrypted_file\n");
        return -1;
    }
    fseek(fin, 0, SEEK_END);
    size_data_unenc = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    fout = fopen(argv[2], "w");
    if (!fout) {
        printf("fopen: Unable to open encrypted_file\n");
        return -1;
    }

    fcheck = fopen("fcheck", "w");
    if (!fcheck) {
        printf("fopen: Unable to open fcheck file\n");
        return -1;
    }    

    data_unenc = calloc(size_data_unenc, sizeof(char));
    /* encrypted data will be always multiple of 16 */
    size_data_enc = ((size_data_unenc / 16) + 1) * 16;
    data_enc = calloc(size_data_enc, sizeof(char));
    data_check = calloc(size_data_enc, sizeof(char));

    fread(data_unenc, sizeof(char), size_data_unenc, fin);
    printf("Encrypting %d bytes...\n", size_data_unenc);

    gen_iv(iv);
    aes_ctr_encrypt(key, iv, data_unenc, size_data_unenc, data_enc, size_data_enc);

    fwrite(data_enc, sizeof(char), size_data_enc, fout);

    /* reset iv */
    memset(iv + 8, 0x0, 8); 
    aes_ctr_decrypt(key, iv, data_enc, size_data_enc, data_check);
    
    fwrite(data_check, sizeof(char), size_data_unenc, fcheck);
    
    free(data_unenc);
    free(data_enc);
    free(data_check);

    fclose(fin);
    fclose(fout);
    fclose(fcheck);

    return 0;
}