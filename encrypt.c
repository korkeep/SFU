#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>

#define TAR_FILE_CNT 3      // Number of tar files
#define HEADER_SIZE 1024    // Hash header size
#define BLOCK_SIZE 16      // Block size
char temp_tar_name_list[TAR_FILE_CNT][255];
static int indent = 0;      // File path parsing

// Error handler
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Encryption
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
 
    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
 
    // Initialise the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();
 
    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
 
    // Finalise the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
 
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
 
    return ciphertext_len;
}

// Encrypt directory list
void encryptFunc(char *file)
{
    FILE* fp1;
    FILE* fp2;
    int fsize = 0;
    int bsize = 0;
    int block_cnt = 0;
    char path[255];
    char cdir[128];
    char buf[BLOCK_SIZE + 1];
    char cbuf[BLOCK_SIZE + 1];
    unsigned char key[32];    // 256 Bit
    unsigned char iv[16];     // 128 Bit
    char temp_s[2];

	//Open key-symmetric.txt, iv-symmetric.txt
	fp1 = fopen("/home/ubuntu/BoB/FW-Update/key-symmetric.txt", "r");
	if (fp1 == NULL) {
		fprintf(stdout, "Error: Unable to find key-symmetric.txt\n");
		exit(1);
	}
	while (feof(fp1) == 0) {
		temp_s[0] = fgetc(fp1);
		temp_s[1] = '\0';
		strcat(key, temp_s);
	}
    fp2 = fopen("/home/ubuntu/BoB/FW-Update/iv-symmetric.txt", "r");
	if (fp2 == NULL) {
		fprintf(stdout, "Error: Unable to find iv-symmetric.txt\n");
		exit(1);
	}
	while (feof(fp2) == 0) {
		temp_s[0] = fgetc(fp2);
		temp_s[1] = '\0';
		strcat(iv, temp_s);
	}

    // AES-CTR Encryption Function
    printf("AES-CTR Encryption: %s/%s\n", getcwd(cdir, 128), file);
    sprintf(path, "%s/%s", getcwd(cdir, 128), file);
    if(isFile(path)) {
        fp1 = fopen(path, "rb");
        fseek(fp1, 0, SEEK_END);
        fsize = ftell(fp1);

        block_cnt = fsize / BLOCK_SIZE;
        fp2 = fopen(path, "wb");
        for (int j = 0; j < block_cnt; j++) {
            fread(buf, BLOCK_SIZE, 1, fp1);
            bsize = encrypt(buf, strlen(buf), key, iv, cbuf);
            cbuf[bsize] = '\0';
            BIO_dump_fp(fp2, cbuf, BLOCK_SIZE);
            //fwrite(cbuf, BLOCK_SIZE, 1, fp2);
            memset(buf, 0, strlen(buf));
            memset(cbuf, 0, strlen(cbuf));
        }
        fread(buf, fsize % BLOCK_SIZE, 1, fp1);
        encrypt(buf, strlen(buf), key, iv, cbuf);
        BIO_dump_fp(fp2, cbuf, fsize % BLOCK_SIZE);
        //fwrite(cbuf, fsize % BLOCK_SIZE, 1, fp2);
        memset(buf, 0, strlen(buf));
        memset(cbuf, 0, strlen(cbuf));
        memset(path, 0, strlen(path));
    }
    memset(key, 0, strlen(key));
    memset(iv, 0, strlen(iv));
    fclose(fp1);
    fclose(fp2);
}

// Check if path is direcory or file
int isFile(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

// Scan directory list
void scanDir(char *wd, void (*func)(char *), int depth)
{
    struct dirent **items;
    int nitems, i; 

    if (chdir(wd) < 0) {
        printf("DIR : %s\n", wd);
        perror("chdir ");
        exit(1);
    }
 
    nitems = scandir(".", &items, NULL, alphasort);
 
    for (i = 0; i < nitems; i++) {
        struct stat fstat;
        if ( (!strcmp(items[i]->d_name, ".")) || (!strcmp(items[i]->d_name, "..")) )
            continue;

        func(items[i]->d_name);
        lstat(items[i]->d_name, &fstat);
        if ((fstat.st_mode & S_IFDIR) == S_IFDIR) {
            if (indent < (depth-1) || (depth == 0)) {
                indent ++;
                scanDir(items[i]->d_name, func, depth);
            }
        }
    } 

    indent--;
    chdir("..");
}

// Extract files
int file_extract(char* path)
{
    FILE* fp1;
    FILE* fp2;
    int fsize = 0, fnameSize = 0;
    int i = 0, j = 0;
    int block_cnt = 0;
    char buf[255];
    char temp_tar_name[255];
    
    // Extract files
    fp1 = fopen(path, "rb");
    printf("%s\n", path);
    for (i = 0; i < TAR_FILE_CNT; i++)
    {
        printf("start\n");
        fread(&fnameSize, 4, 1, fp1);
        memset(temp_tar_name, 0, 255);
        
        fread(temp_tar_name, fnameSize, 1, fp1);
        printf("tar name : %s \n" , temp_tar_name);
        
        fread(&fsize, 4, 1, fp1);
        block_cnt = fsize / 255;
        fp2 = fopen(temp_tar_name, "wb");
        for (j = 0; j < block_cnt; j++)
        {
            fread(buf, 255, 1, fp1);
            fwrite(buf, 255, 1, fp2);
            memset(buf, 0, strlen(buf));
        }
        fread(buf, fsize % 255, 1, fp1);
        fwrite(buf, fsize % 255, 1, fp2);
        memset(buf, 0, strlen(buf));
        
        strcpy(temp_tar_name_list[i], temp_tar_name);
    }
    fclose(fp1);
    fclose(fp2);
    return 0;
}

// Extract tar files
int tar_extract()
{
    FILE* stream;
    char line[1024];
    char tar_fn[255] = { 0x00, };
    char cmd[1024] = { 0x00, };
    int i = 0;
    
    // Extract tar files
    for (i = 0; i < TAR_FILE_CNT; i++)
    {
        strcpy(tar_fn, temp_tar_name_list[i]);
        if (access(tar_fn, 0) == 0) {
            rmdir("./boot");
            rmdir("./documentation");
            rmdir("./opt");
        }
        mkdir("/home/ubuntu/BoB/FW-Update/encrypted", 0655);
        sprintf(cmd, "pv %s | tar xf %s -C /home/ubuntu/BoB/FW-Update/encrypted/", tar_fn, tar_fn);
        //mkdir("/var/update_test_origin", 0655);
        //sprintf(cmd, "pv %s | tar xf %s -C /var/update_test_origin/", tar_fn, tar_fn);
        stream = popen(cmd, "r");

        if (stream == NULL) {
            remove(tar_fn);
            return -1;
        }

        pclose(stream);
        remove(tar_fn);
    }

    // Call encryptFunc
    scanDir("/home/ubuntu/BoB/FW-Update/encrypted/boot", encryptFunc, 0);
    scanDir("/home/ubuntu/BoB/FW-Update/encrypted/opt", encryptFunc, 0);

    return 1;
}

int main(int argc, char* argv[])
{
    char firmware_path[255];
    int fsize = 0;
    int ret = 0;

    // Binary usage
    if (argc != 2) {
        printf("usage: %s [firmware path]\n", argv[0]);
        exit(0);
    }
    sprintf(firmware_path,"%s", argv[1]);

    // Firmware extract
    printf("[Firmware Extract] \n");
    if ((ret = file_extract(firmware_path)) < 0) {
        printf("File system extraction failed.(%d)", ret);
        exit(0);
    }
    printf("OK\n");

    // Firmware Encrypt
    printf("[Encrypt]\n");
    tar_extract();

    printf("[Firmware Encrypt] Success\n");
}