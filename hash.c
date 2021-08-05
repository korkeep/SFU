#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>

#define HEADER_SIZE 1024

void main(int argc, char *argv[])
{
    FILE *fp;
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len, i;
    int fsize = 0;
    char fwBuf[HEADER_SIZE];

    md = EVP_get_digestbyname("sha256");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    fp = fopen("/home/ubuntu/BoB/FW-Update/FW", "rb");
    fread(fwBuf, HEADER_SIZE, 1, fp);

    EVP_DigestUpdate(mdctx, fwBuf, HEADER_SIZE);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    fp = fopen("/home/ubuntu/BoB/FW-Update/hash.txt", "wb");
    printf("SHA-256: ");
    for (i = 0; i < md_len; i++){
        printf("%02x", md_value[i]);
        fprintf(fp, "%02x", md_value[i]);
    }
    printf("\n");

    exit(0);
}