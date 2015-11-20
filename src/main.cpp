//
//  main.cpp
//  openssl
//
//  Created by Xinbao Dong on 15/4/4.
//  Copyright (c) 2015年 com.dongxinbao. All rights reserved.
//

#include <iostream>
#include <unistd.h>
#include <errno.h>
#include "pkcs1_rsa.h"
#include "osdep.h"

using namespace std;

#define MALLOC_EXPANT 4096

int main(int argc,  char * argv[])
 {
    int c;

    opterr = 0;
    while ((c = getopt(argc, argv, "ga:e:d:s:v:")) != -1)
    {
     switch (c)
     {
      case 'a':
        AddNovelSupertvHeadV3(optarg);
        goto End;
        break;
      case 'g':
        GenerateNewKey(2048, 3, "publickey.pem", "privatekey.pem");
        goto End;
        break;
      case 's':
        Signature(optarg);
        goto End;
        break;
      case 'v':
        Verify(optarg);
        goto End;
        break;
      case 'e':
        Encryption(optarg, "publickey.pem", "privatekey.pem");
        goto End;
        break;
      case 'd':
        Decryption(optarg, "publickey.pem", "privatekey.pem");
        goto End;
        break;
      case '?':
      default:
        if (optopt == 'v')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (optopt == 's')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        usage();
        exit(EXIT_FAILURE);      
    }
  }
  usage();
End:  
    return 0;
}

static void PUBLIC
AddNovelSupertvHeadV3(char *argv)
{
    MovelSuperTvHead *mMovelSuperTvHead = NULL;
    int ret = -1;
    
    PRO_START_PRINT
    if(NULL == argv){
        fprintf(stderr, "argv is NULL, invaild parament\n");
        exit(-1);
    }

    if(access(argv, F_OK) == -1) {   //F_OK(0) Test for existence
        fprintf(stderr, "%s:%s\n", argv, strerror(errno));
        exit(-1);
    }

    mMovelSuperTvHead = new MovelSuperTvHead;
    if(mMovelSuperTvHead == NULL){
        fprintf(stderr, "new error\n");
        exit(-1);
    }

    RsaPkcs1Sign *rsa = new RsaPkcs1Sign();
    ret = rsa->AddMovSuperTvHead(argv, mMovelSuperTvHead);

    if (ret == 1/* condition */)
    {
        fprintf(stdout, "Add MovSuperTvHead V3 successfully!\n");
    }else{
        fprintf(stdout, "Add MovelSuperTvHead V3 Failure!\n");
    }

    delete mMovelSuperTvHead;
    PRO_END_PRINT
}

static void PUBLIC 
GenerateNewKey(int num, unsigned long e, string PubkeyFile, string PriKeyFile)
{
    Key *key = new Key(num, e);
    key->generateNewKey(PubkeyFile, PriKeyFile);
}
static void PUBLIC
Signature(char *argv)
{
    const char *delim = " ";
    char *file = NULL, *KeyFile = NULL;
    MovelSuperTvHead  *mMovelSuperTvHead = NULL;

    
    file = strtok(argv, delim);
    KeyFile = strtok(NULL, delim);
    if (NULL == file || KeyFile == NULL) usage();
    
    if(access(KeyFile, F_OK) == -1) {   //F_OK(0) Test for existence
        fprintf(stderr, "%s:%s\n", KeyFile, strerror(errno));
        exit(-1);
    }
    if(access(file, F_OK) == -1) {   //F_OK(0) Test for existence
        fprintf(stderr, "%s:%s\n", file, strerror(errno));
        exit(-1);
    }

    string PriKeyFile(KeyFile);
    Key *key = new Key(PriKeyFile, 1, 1);
    RsaPkcs1Sign *rsa = new RsaPkcs1Sign(key);
    PRO_START_PRINT
    printf("You selected KeyFile is:%s\n", KeyFile);
    printf("Reading the %s document to be signed…\n", file);
    mMovelSuperTvHead = new MovelSuperTvHead;
    //rsa->AddMovSuperTvHead(file, mMovelSuperTvHead);
    FILE *originalFile = fopen(file, "rb");
    if (originalFile == NULL) {
        printf("File not exits!\n");
        exit(0);
    }
    fseek(originalFile, 0, SEEK_END);
    unsigned int originalSize = ftell(originalFile);
    rewind(originalFile);
    unsigned char *originalBuffer = (unsigned char *)malloc(sizeof(char) * originalSize +1024);
    if (originalBuffer == NULL) {
        printf("Memory Error!\n"); 
        exit(0);
    }
    
    if (fread(originalBuffer, 1, originalSize, originalFile) != originalSize) {
        printf("File load error!\n");
        exit(0);
    }
    fclose(originalFile);
    printf("File read successfully, length:%d\n", originalSize); 
    printf("\033[1;32;40mStart Signing…\033[0m\n");
    //sign
    
    unsigned int *signatureLength = 0;
    unsigned char *signature =NULL;

    signatureLength = new unsigned int;
    
    //signature = new unsigned char[sizeof(char) * originalSize  + MALLOC_EXPANT];
    //memset(signature, 0, (sizeof(char) * originalSize + MALLOC_EXPANT));

    /*    
    if (rsa->mySign((unsigned char *)originalBuffer, originalSize, signature, signatureLength) <= 0) {
        printf("Signature Error!\n");
    }
    */
    if(rsa->Sign_Type3((unsigned char *)originalBuffer, originalSize, &signature, signatureLength))
     {  printf("Signature Error!\n");
        exit(-1);
     }

    printf("signatureLength:%d\n", *signatureLength);
#ifdef DEBUG
    for(int i = 0; i < *signatureLength; i++) 
    { 
        if (i%6==0) 
            printf("\n%08xH: ",i); 
            printf("%02x ", *signature[i]); 
    } 
    printf("\n");
#endif    
    //save signature
    rsa->AddSignHead(file, signature, *signatureLength);

    free(originalBuffer);
    //delete [] signature;
    free(signature);
    delete mMovelSuperTvHead;
    delete signatureLength;
    printf("Signature successful, signature length is% d, total length is% d," 
           "after signature file has been saved.\n", 
            *signatureLength, *signatureLength + originalSize);    
    PRO_END_PRINT
}

static void PUBLIC
Verify(char *argv)
{
    const char *delim = " ";
    char *file = NULL, *KeyFile = NULL;
    unsigned int mDefSignaLen = 256;
    
    file = strtok(argv, delim);
    KeyFile = strtok(NULL, delim);
    if (NULL == file || KeyFile == NULL) usage();
    if(access(KeyFile, F_OK) == -1) {   //F_OK(0) Test for existence
        fprintf(stderr, "%s:%s\n", KeyFile, strerror(errno));
        exit(-1);
    }
    if(access(file, F_OK) == -1) {   //F_OK(0) Test for existence
        fprintf(stderr, "%s:%s\n", file, strerror(errno));
        exit(-1);
    }
   
    string PubKeyFile(KeyFile);
    Key *key = new Key(PubKeyFile, 1);
    RsaPkcs1Sign *rsa = new RsaPkcs1Sign(key);
    PRO_START_PRINT
    //Extraction last 256 signatures
    FILE *signatureFile = fopen(file, "rb");
    fseek(signatureFile, 0, SEEK_END);
    unsigned int FileSize = ftell(signatureFile);
    rewind(signatureFile);
    printf("You selected KeyFile is:%s\n", KeyFile);
    printf("Reading the %s document Len: %d to be Verify…\n", file, FileSize);
    if(FileSize < mDefSignaLen){
        fprintf(stderr, "%s is invaild signature file.\n", file);
        exit(-1);
    }

    unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * FileSize + MALLOC_EXPANT);
    if (fread(buffer, 1, FileSize, signatureFile) != FileSize) {
        printf("fread File load error!\n");
        exit(-1);
    }
    fclose(signatureFile);
    printf("File read successfully, length: %d\n", FileSize);

    int originalSize = FileSize - mDefSignaLen;
    printf("original File Size: %d\n", originalSize);
    unsigned char *originalBuffer = (unsigned char*)malloc(sizeof(char) * originalSize + MALLOC_EXPANT);
    memcpy(originalBuffer, buffer + mDefSignaLen, originalSize);
    //Verify
    printf("\033[1;32;40mVerifying signatures…\033[0m\n");
    //int res = rsa->myVerify(buffer, 256, originalBuffer, originalSize);       
    unsigned long res = rsa->Verify_Type3(originalBuffer, originalSize, buffer, mDefSignaLen);
    if (res == 0) {
        printf("\033[1;34;40mVerifying signatures successful!\033[0m\n");
    } else {
        printf("\033[1;35;40mVerifying signatures failure!\033[0m\n");
    }
    free(originalBuffer);
    free(buffer);
    PRO_END_PRINT
}

static void PUBLIC 
Encryption(char *file, string PubkeyFile, string PriKeyFile)
{
    Key *key = new Key(PubkeyFile, PriKeyFile);
    RsaPkcs1Sign *rsa = new RsaPkcs1Sign(key);
    //load the signed file
    FILE *File = fopen(file, "rb");
    if (File == NULL) {
        printf("file not exits!\n");
        exit(0);
    }
    fseek(File, 0, SEEK_END);
    unsigned int FileSize = ftell(File);
    rewind(File);
    unsigned char * inBuffer = (unsigned char *)malloc(sizeof(char) * FileSize);
    if (inBuffer == NULL) {
        printf("Memory Error!\n");
        exit(0);
    }
    if (fread(inBuffer, 1, FileSize, File) != FileSize) {
        printf("Signed File load error!\n");
        exit(0);
    }
    fclose(File);
    printf("Cryptographic signature file…\n");
    //encrypt and save
    FILE *outFile = fopen("encryptedFile.out", "wb");
    if (outFile == NULL) {
        printf("Create encrypted file error!\n");
        exit(0);
    }
    
    key->reload();
    unsigned int encryptedLength =  RSA_size(key->publicKey);
    unsigned char *encryptedBuffer = (unsigned char *)malloc(sizeof(char) * encryptedLength);
    unsigned int i = 0;
    while (i < FileSize) {
        if (rsa->myEncrypt((unsigned char *)(inBuffer + i), 100, encryptedBuffer, encryptedLength) <= 0) {
            printf("Signed File encrypt error!\n");
            exit(0);
        }
        fwrite(encryptedBuffer, 1, encryptedLength, outFile);
        i +=  100;              //100为单位加密，其实只要小于128-11就行了。
    }

    fclose(outFile);
    free(encryptedBuffer);
    free(inBuffer);
    printf("Encryption is successful, the length of%d，"
           "has been saved to fileSigned.encrypted\n", FileSize / 100 * 128);
}

static void PUBLIC
Decryption(char *file, string PubkeyFile, string PriKeyFile)
{
    Key *key = new Key(PubkeyFile, PriKeyFile);
    RsaPkcs1Sign *rsa = new RsaPkcs1Sign(key);
    
    printf("Decrypt the encrypted file…\n");
    //decrypt the file
    FILE* encryptedFile = fopen(file, "rb");
    if (encryptedFile == NULL) {
        printf("Encryped file not exits!\n");
        exit(0);
    }
    fseek(encryptedFile, 0, SEEK_END);
    unsigned int encryptedLength = ftell(encryptedFile);
    rewind(encryptedFile);
    unsigned char *encryptedBuffer = (unsigned char *)malloc(sizeof(char) * encryptedLength);
    if (encryptedBuffer == NULL) {
        printf("Memory Error!\n");
        exit(0);
    }
    if (fread(encryptedBuffer, 1, encryptedLength, encryptedFile) != encryptedLength) {
        printf("Encrypted File load error!\n");
        exit(0);
    }
    fclose(encryptedFile);
    
    FILE *decryptedFile = fopen("decryptedFile.out", "wb");
    if (decryptedFile == NULL) {
        printf("Create decrypted file error!\n");
        exit(0);
    } 
    //save the uncrypted data to file
    key->reload();
    unsigned int decryptionLen = RSA_size(key->publicKey);
    unsigned char *plain = (unsigned char *)malloc(sizeof(char) * decryptionLen);
    unsigned int i = 0, y = 0;
    while (i < encryptedLength) 
    {
        y = rsa->myDecrypt((unsigned char *)encryptedBuffer + i, 128, plain, decryptionLen);
        
        //去除空格
        if (i + 128 >= encryptedLength) {
            y = 100;
            while (plain[y - 1] == 0) {
                y --;
                if (y == 0) {
                    break ;
                }
            }
        }
        fwrite(plain, 1, y, decryptedFile);
        i += 128;
    }
    fclose(decryptedFile);
    free(encryptedBuffer);
    free(plain);
    printf("Decryption is successful\n");
}

static void usage() {
    fprintf(stderr, "%s\n"
        "Usage:%s\n"
        "  Options:\n"
        "   -a                           # Add Novel Super Tv Head V3\n"
        "   -g                           # Generates a pair of keys\n"
        "   -e                           # Cryptographic file\n"
        "   -d                           # Decrypt the encrypted file\n"
        "   -s \033[5;31;40m\"\033[0m\033[0;34;40mSignFile PriKeyFile\033[5;31;40m\"\033[0m\033[0m     # signature \n"
        "   -v \033[5;31;40m\"\033[0m\033[0;34;40mVerifyFile PubKeyFile\033[5;31;40m\"\033[0m\033[0m   # Verifying signatures\n"
        "\n A RSASSA_PKCS1#_SIGNED and RSASSA_PKCS1#_VERIFY implements.\n",    
        ME_TITLE, ME_NAME);
    exit(-1);
}