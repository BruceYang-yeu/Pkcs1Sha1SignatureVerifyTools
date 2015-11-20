
#include "pkcs1_rsa.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <errno.h>
#include <unistd.h>

//#define DEBUG
#ifndef DEBUG
    #define DEBUG_HELP fprintf(stdout, "\033[1;31;40m[debug]Line: %d Function: %s\n\033[0m", __LINE__, __FUNCTION__);
#else
    #define DEBUG_HELP
#endif

RsaPkcs1Sign::RsaPkcs1Sign(Key *key):mSignedLen(256)
{
    this->key = key;
}

RsaPkcs1Sign::RsaPkcs1Sign()
{
    this->key = NULL;
}

/**
* Extracts filename from the given path
* @param[in] path Path to extract filename from
* @return Extracted filename
*/
char* 
RsaPkcs1Sign::GetFileName(char* path)
{
    char* fileName = strrchr(path, '/');

    if (fileName == NULL) {
        fileName = path;
    } else {
        fileName++;
    }

    return fileName;
}

/**
* Calculates the given open file size
* @param[in] pFile pointer to file stream
* @return Given file size
*/
int32 
RsaPkcs1Sign::GetFileSize(FILE* pFile)
{
    fseek(pFile, 0, SEEK_END);
    int32 fileSize = ftell(pFile);
    rewind(pFile);

    return fileSize;
}   

/**
* Removes first mSignedLen bytes from the given file.
* @param[in] fileName
*/
int 
RsaPkcs1Sign::RemoveSigHead(char* fileName)
{
    FILE* pFile = fopen(fileName, "rb+");
    if (pFile == NULL) {
        fprintf(stderr, "Can't open file.\n");
        return -1;
    }

    if (GetFileSize(pFile) < mSignedLen) {
        fprintf(stderr, "Invalid file.\n");
        return -1;
    }
    fprintf(stderr, "Creating File backup...\n");

    char* bakFileName = strcat(fileName, ".bak");
    FILE *pBakFile = fopen(bakFileName, "wb+");
    if (pBakFile == NULL) {
        fprintf(stderr, "Can't create backup file.\n");
        return -1;
    }

    char buffer[1024];

    size_t n;
    while((n = fread(buffer, sizeof(char), sizeof(buffer), pFile)) > 0) {
        fwrite(buffer, sizeof(char), n, pBakFile);
    }

    printf("Remove signature Head...\n");

    fseek(pBakFile, mSignedLen, SEEK_SET);
    fseek(pFile, 0, SEEK_SET);

    while((n = fread(buffer, sizeof(char), sizeof(buffer), pBakFile)) > 0) {
        fwrite(buffer, sizeof(char), n, pFile);
    }

    printf("Remove Signature Head Done.\n");

    fclose(pBakFile);
    fclose(pFile);

    return 1;
}


int 
RsaPkcs1Sign::AddMovSuperTvHead(char* fileName, MovelSuperTvHead *mMovelSuperTvHead)
{
    const char *bakStr = ".oribak";
    const char *DataName = "JustTes";
    char tempArr[256] = {""};
    int32 mFileLen = 0;

    if(fileName == NULL|| mMovelSuperTvHead == NULL) 
    {
        fprintf(stderr, "Argv Is Invalid\n");
        return -1;
    }
    strncpy(tempArr, fileName, strlen(fileName));
    FILE* pFile = fopen(fileName, "rb+");
    if (pFile == NULL) {
        fprintf(stderr, "Can't open file.\n");
        return -1;
    }
    mFileLen = GetFileSize(pFile);
    printf("Filename:%s: Len:%d\n", fileName, mFileLen);
    printf("MovelSuperTvHead Len:%ld\n", sizeof(MovelSuperTvHead));
    memset(mMovelSuperTvHead, 0, sizeof(MovelSuperTvHead));
    strcpy(mMovelSuperTvHead->Name, DataName);
    mMovelSuperTvHead->Length = mFileLen;

    printf("Add MovSuperTv Head Creating File backup...\n");
    
    char* bakFileName = strcat(tempArr, bakStr);
    FILE *pBakFile = fopen(bakFileName, "wb+");
    if (pBakFile == NULL) {
        fprintf(stderr, "Can't create backup file.\n");
        return -1;
    }

    char buffer[1024];
    size_t n;
    memset(buffer, 0, sizeof(buffer));
    while((n = fread(buffer, sizeof(char), sizeof(buffer), pFile)) > 0) {
        fwrite(buffer, sizeof(char), n, pBakFile);
    }

    printf("\033[1;32;40mAdd MovSuperTv Head...\033[0m\n");
    fseek(pBakFile, 0, SEEK_SET);
    fseek(pFile, 0, SEEK_SET);
    fwrite((const void*)mMovelSuperTvHead, 1, sizeof(MovelSuperTvHead), pFile);

    while((n = fread(buffer, sizeof(char), sizeof(buffer), pBakFile)) > 0) {
        fwrite(buffer, sizeof(char), n, pFile);
    }

    printf("Add Movel SuperTv Head Done.\n");
    mFileLen = GetFileSize(pFile);
    printf("Filename:%s: Len:%d\n", fileName, mFileLen);
    fclose(pBakFile);
    fclose(pFile);
    unlink(bakFileName);

    return 1;
}
/**
* Writes slen bytes at beginning of the given file
* @param[in] fileName
*/
int 
RsaPkcs1Sign::AddSignHead(char* fileName, 
                          const unsigned char *signature, 
                          unsigned int slen)
{
    const char *bakStr = ".bak";
    if(fileName == NULL|| signature == NULL || slen == 0) 
    {
        fprintf(stderr, "Argv Is Invalid\n");
        return -1;
    }

    FILE* pFile = fopen(fileName, "rb+");
    if (pFile == NULL) {
        fprintf(stderr, "Can't open file.\n");
        return -1;
    }

    printf("Creating File backup...\n");

    char* bakFileName = strcat(fileName, bakStr);
    printf("bakFileName:%s\n", bakFileName);
    FILE *pBakFile = fopen(bakFileName, "wb+");
    if (pBakFile == NULL) {
        fprintf(stderr, "Can't create backup file.\n");
        return -1;
    }

    char buffer[1024];
    size_t n;
    memset(buffer, 0, sizeof(buffer));
    while((n = fread(buffer, sizeof(char), sizeof(buffer), pFile)) > 0) {
        fwrite(buffer, sizeof(char), n, pBakFile);
    }

    printf("\033[1;32;40mAddSignHead...\033[0m\n");
    fseek(pBakFile, 0, SEEK_SET);
    fseek(pFile, 0, SEEK_SET);
    fwrite((const void*)signature, 1, slen, pFile);

    while((n = fread(buffer, sizeof(char), sizeof(buffer), pBakFile)) > 0) {
        fwrite(buffer, sizeof(char), n, pFile);
    }

    printf("Add SignatureHead Done.\n");

    fclose(pBakFile);
    fclose(pFile);
    unlink(bakFileName);

    return 1;

}

int RsaPkcs1Sign::myEncrypt(const unsigned char *plain, int length, 
                            unsigned char *cipher, unsigned int &r_length) 
{
    key->reload();
    r_length = RSA_size(key->privateKey);
    //cipher = (unsigned char *)malloc(sizeof(char) * r_length);
    memset((void *)cipher, 0, r_length);
    int res = RSA_private_encrypt(length, (unsigned char *)plain, (unsigned char *)cipher, key->privateKey, RSA_PKCS1_PADDING);
    return res;
}

int RsaPkcs1Sign::myDecrypt(const unsigned char *cipher, int length, 
                            unsigned char *plain, unsigned int &r_length) 
{
    key->reload();
    r_length = RSA_size(key->publicKey);
    //*plain = (unsigned char *)malloc(sizeof(char) * r_length);
    memset((void *)plain, 0, r_length);
    return RSA_public_decrypt(length, (unsigned char *)cipher, (unsigned char *)plain, key->publicKey, RSA_PKCS1_PADDING);
}


int RsaPkcs1Sign::Sign_Type1(const unsigned char *plain, int length, 
                         unsigned char *cipher, unsigned int &r_length) 
{
    BIGNUM *f, *ret, *res;
    int i,j,k,num=0,r= -1;
    unsigned char *buf=NULL;
    BN_CTX *ctx=NULL;

    key->reload();
    if ((ctx=BN_CTX_new()) == NULL) goto err;
    BN_CTX_start(ctx);
    f   = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(key->privateKey->n);
    printf("KeyLen:%d\n", num);
    
    buf = (unsigned char *)OPENSSL_malloc(num);
    if(!f || !ret || !buf)
    {
        printf("RSA_F_RSA_EAY_PRIVATE_ENCRYPT,ERR_R_MALLOC_FAILURE\n");
        goto err;
    }
    
    i=RSA_padding_add_PKCS1_type_1(buf, num, plain, length);
    if (i <= 0) goto err;

    if (BN_bin2bn(buf,num,f) == NULL) goto err;
    if (BN_ucmp(f, key->privateKey->n) >= 0)
    {   
        /* usually the padding functions would catch this */
        printf("RSA_F_RSA_EAY_PRIVATE_ENCRYPT,RSA_R_DATA_TOO_LARGE_FOR_MODULUS\n");
        goto err;
    }

    if (!(key->privateKey)->meth->bn_mod_exp(ret, f, (key->privateKey)->d,(key->privateKey)->n,ctx,
                (key->privateKey)->_method_mod_n)) goto err;
    res = ret;

    /* put in leading 0 bytes if the number is less than the
     * length of the modulus */
    j = BN_num_bytes(res);
    i = BN_bn2bin(res, &(cipher[num-j]));
    for ( k=0;  k < (num-i); k++)
        cipher[k]=0;
    r=num;
    r_length =r;


err:
    if (ctx != NULL)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL)
    {
        OPENSSL_cleanse(buf,num);
        OPENSSL_free(buf);
    }
    return(r);
 
    
}
int RsaPkcs1Sign::Sign_Type2(const unsigned char *plain, int length, 
                         unsigned char *cipher, unsigned int &r_length) 
{    
    key->reload();
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, key->privateKey);
    EVP_MD_CTX md_ctx;
    
    //cipher = (unsigned char *)malloc(1024 * 4);
    //memset((void *)cipher, 0, 1024 * 4);
    EVP_SignInit(&md_ctx, EVP_sha1());
    EVP_SignUpdate(&md_ctx, plain, length);
    if (EVP_SignFinal(&md_ctx, cipher, &r_length, pkey) <= 0) {
        printf("EVP_Sign Error");
        return 0;   
    }
    EVP_PKEY_free(pkey);
    return 1; 
    
}



unsigned long 
RsaPkcs1Sign::Sign_Type3( unsigned char *inBuffer,
                    unsigned long inBufferLen,
                    unsigned char **outSignature,
                    unsigned int *outSignatureLen )
{
   RSA *keyLocal = NULL;                        /* OpenSSL RSA key structure */
   int cypherLen;                               /* RSA key length */
   unsigned char SHA1digest[SHA_DIGEST_LENGTH]; /* holds digests */
   int status;                                  /* status code for RSA_sign function, returned value */

   key->reload();   

   /* allocate RSA key */
   //keyLocal = RSA_new();

   /* put key modulos and private exponent in big number repr in newly allocated RSA key */
   //keyLocal->n = BN_bin2bn( key->privateKey->mod, key->privateKey->modBufLen, NULL );
   //keyLocal->d = BN_bin2bn( key->privateKey->exp, key->privateKey->expBufLen, NULL );
   keyLocal =  key->privateKey;
   /* key length */
   cypherLen = RSA_size( keyLocal );
   printf("cypherLen:%d\n", cypherLen);
   DEBUG_HELP
   
   SHA1(inBuffer, inBufferLen, SHA1digest );
   *outSignature = (unsigned char*)malloc( cypherLen );
   
    /* sign the digest */
    status = RSA_sign( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, *outSignature, outSignatureLen, keyLocal );
    /* check for success */
    if ( status ) {
       RSA_free( keyLocal );
       return OK;
    }else {
       RSA_free( keyLocal );
       return SIGN_ERROR;
    }
   return OK;
}

unsigned long 
RsaPkcs1Sign::Sign_Type4( unsigned char *inBuffer,
                          unsigned long inBufferLen,
                          unsigned char **outSignature,
                          unsigned int *outSignatureLen )
{
   RSA *keyLocal = NULL;                        /* OpenSSL RSA key structure */
   int cypherLen;                               /* RSA key length */
   unsigned char *message;                      /* holds pieces of original message */
   unsigned char SHA1digest[SHA_DIGEST_LENGTH]; /* holds digests */
   div_t divResult;                             /* div_t type to hold multiple of key lengths in input data */
   unsigned int localLength;                    /* holds signature length */
   int offset = 0;                              /* offset in the input buffer */
   int counter;                                 /* while loop index */ 
   int status;                                  /* status code for RSA_sign function, returned value */

   key->reload();   

   /* allocate RSA key */
   //keyLocal = RSA_new();

   /* put key modulos and private exponent in big number repr in newly allocated RSA key */
   //keyLocal->n = BN_bin2bn( key->privateKey->mod, key->privateKey->modBufLen, NULL );
   //keyLocal->d = BN_bin2bn( key->privateKey->exp, key->privateKey->expBufLen, NULL );
   keyLocal =  key->privateKey;
   /* key length */
   cypherLen = RSA_size( keyLocal );
   /* calculate mutiple number - how many key lengths in input buffer */
   divResult = div( inBufferLen, cypherLen );
    /* intialize counter */
   counter = divResult.quot;

   /* clear the output parameter */
   *outSignatureLen = 0;
   DEBUG_HELP
   printf("quot:%d  rem:%d\n", divResult.quot, divResult.rem);
   /* key is bigger than the input buffer ? */
   if ( divResult.quot == 0 ){
      /* get the message digest */
      SHA1(inBuffer, inBufferLen, SHA1digest );
      DEBUG_HELP
      /* allocate space for output parameter, size is key length */
      *outSignature = (unsigned char*)malloc( cypherLen );
      
      /* sign the digest */
      status = RSA_sign( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, *outSignature, outSignatureLen, keyLocal );
      /* check for success */
      if ( status )
      {
         RSA_free( keyLocal );
         return OK;
      }else 
      {
         RSA_free( keyLocal );
         return SIGN_ERROR;
      }
   } else {  /* input buffer length is bigger than key length */

    /* allocate enough space for outSignature */
      if ( divResult.rem != 0 ){
         *outSignature = (unsigned char*)malloc( (divResult.quot+1)*cypherLen );
      } else {
         *outSignature = (unsigned char*)malloc( divResult.quot*cypherLen );
      }

      /* allocate space for pieces of input buffer */
      message = (unsigned char*)malloc( cypherLen );
      /* do it counter times */
      while ( counter != 0 )
      {
         /* get the message */
         memcpy( message, inBuffer + offset, cypherLen );
         /* get the digest */
         SHA1( message, cypherLen, SHA1digest );
         /* sign the digest and check for success */
         if ( !RSA_sign( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, *outSignature + offset, &localLength, keyLocal) )
         {
            /* error - free the memory and return */
            free( message );
            RSA_free( keyLocal );

            return SIGN_ERROR;
         }
         /* update the offset, counter, and output length  */
         offset = offset + cypherLen;
         counter--;
         *outSignatureLen = *outSignatureLen + localLength;
      }
      /* more data in input buffer - if so do the same above for the last time */
      if ( divResult.rem != 0 )
      {
         memcpy(message, inBuffer + offset, divResult.rem );
         SHA1( message, divResult.rem, SHA1digest );
         if ( !RSA_sign( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, *outSignature + offset, &localLength, keyLocal) )
         {
            free( message );
            RSA_free( keyLocal );
            return SIGN_ERROR;
         }
         *outSignatureLen = *outSignatureLen + localLength;
      }

      /* free the memory and return OK */
      free( message );
      RSA_free( keyLocal );
      return OK;
   }
}

int RsaPkcs1Sign::Verify_Type1(const unsigned char *cipher, int length, 
                           unsigned char *plain, int plainLength) 
{
 
    BN_CTX *ctx=NULL;
    BIGNUM *f, *ret, *bignum;
    unsigned char *toBuf = NULL;
    unsigned char *buf = NULL, *p = NULL;
    int  num = 0, i = 0, r= -1, mBufOutLenEx = 4, mIntercmp = -1;

    DEBUG_HELP
 
    key->reload();
    if (BN_num_bits((key->publicKey)->n) > OPENSSL_RSA_MAX_MODULUS_BITS)
    {
        printf("RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_MODULUS_TOO_LARGE\n");
        return -1;
    }
    DEBUG_HELP

    if((ctx = BN_CTX_new()) == NULL) goto err;
    BN_CTX_start(ctx);
    bignum = BN_CTX_get(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num=BN_num_bytes(key->publicKey->n);
    printf("KeyLen:%d\n", num);
    buf = (unsigned char*)OPENSSL_malloc(num * mBufOutLenEx);
    toBuf = (unsigned char *)OPENSSL_malloc(num * mBufOutLenEx);
    if(!f || !ret || !buf)
    {
        printf("RSA_F_RSA_EAY_PUBLIC_DECRYPT,ERR_R_MALLOC_FAILURE\n");
        goto err;
    }
    /* This check was for equality but PGP does evil things
     * and chops off the top '0' bytes */
    if (length > num)
    {
        printf("RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_DATA_GREATER_THAN_MOD_LEN\n");
        goto err;
    }   
    

    if (BN_bin2bn(cipher,length,f) == NULL) goto err;
    if (BN_ucmp(f, key->publicKey->n) >= 0)
    {
        printf("RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_DATA_TOO_LARGE_FOR_MODULUS\n");
        goto err;
    }

    if (!(key->publicKey)->meth->bn_mod_exp(ret,f,key->publicKey->e,key->publicKey->n,ctx,
        key->publicKey->_method_mod_n)) goto err;

    p=buf;
    i=BN_bn2bin(ret,p);
    printf("\033[1;33;40mBN_bn2dec(ret):%s\n\033[0m", BN_bn2dec(ret));

    if (RSA_padding_add_PKCS1_type_1(toBuf, num, plain, plainLength) != 1){
        fprintf(stderr,"Error: RSA_PADDING error\n");
        exit(-1);
    }

    BN_bin2bn(toBuf, num, bignum);
    printf("\033[1;34;40mBN_bn2dec(num):%s\033[0m\n", BN_bn2dec(bignum));
    mIntercmp = strcmp(BN_bn2dec(bignum), BN_bn2dec(ret));

    r = RSA_padding_check_PKCS1_type_1(plain, num, buf, i, num);    
    if (r < 0)
        printf("RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_PADDING_CHECK_FAILED\n");

 err:   
    if (ctx != NULL)
        {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        }
    if (buf != NULL)
        {
        OPENSSL_cleanse(buf,num * mBufOutLenEx);
        OPENSSL_free(buf);
        }
    if (toBuf != NULL)
        {
        OPENSSL_cleanse(toBuf,num * mBufOutLenEx);
        OPENSSL_free(toBuf);
        }   
    return(mIntercmp);   
}

int RsaPkcs1Sign::Verify_Type2(const unsigned char *cipher, int length, 
                           unsigned char *plain, int plainLength) 
{

    key->reload();
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, key->publicKey);
    
    EVP_MD_CTX md_ctx;
    EVP_VerifyInit(&md_ctx, EVP_sha1());
    EVP_VerifyUpdate(&md_ctx, plain, plainLength);
    int ret1 = EVP_VerifyFinal(&md_ctx, cipher, length, pkey); 
    printf("\033[1;32;40mEVP_VerifyFinal:%d\n\033[0m", ret1);
    if (!ret1) {
        return 0;
    }
    EVP_PKEY_free(pkey);
    return ret1;   
}


unsigned long RsaPkcs1Sign::Verify_Type3(unsigned char *inData,
                         unsigned long inDataLen,
                         unsigned char *pSignature,
                         unsigned long pSigLen)
{
    RSA *keyLocal;                               /* OpenSSL RSA key structure */
    int cypherLen;                               /* RSA key length */
    unsigned char SHA1digest[SHA_DIGEST_LENGTH]; /* holds digests */
    int status;                                  /* status code for RSA_sign function, returned value */
    
    key->reload();    
    keyLocal =  key->publicKey;
    /* key length */
    cypherLen = RSA_size( keyLocal );
    printf("cypherLen:%d\n", cypherLen);

    /* get the digest of message */
    SHA1( inData, inDataLen, SHA1digest );
    /* verify the digest against the signature */
    status = RSA_verify( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, pSignature, cypherLen, keyLocal );
    printf("status:%d\n", status);
    /* check for errror and return */
    if ( status ){
         RSA_free( keyLocal );
         return OK;
     } else {
         RSA_free( keyLocal );
         return VERIFY_ERROR;
      }

}


unsigned long RsaPkcs1Sign::Verify_Type4(unsigned char *inData,
                         unsigned long inDataLen,
                         unsigned char *pSignature,
                         unsigned long pSigLen)
{
    RSA *keyLocal;                               /* OpenSSL RSA key structure */
   int cypherLen;                               /* RSA key length */
   unsigned char *message;                      /* holds pieces of original message */
   unsigned char SHA1digest[SHA_DIGEST_LENGTH]; /* holds digests */
   div_t divResult;                             /* div_t type to hold multiple of key lengths in input data */
   int offset = 0;                              /* offset in the input buffer */
   int counter;                                 /* while loop index */
   int status;                                  /* status code for RSA_sign function, returned value */


    key->reload();    
    keyLocal =  key->publicKey;
    /* get the key length */
    cypherLen = RSA_size( keyLocal );

    /* calculate multiple number */
    divResult = div( inDataLen, cypherLen );
    counter = divResult.quot;

    /* key is bigger than the input data ? */
    if ( divResult.quot == 0 ){
      /* get the digest of message */
      SHA1( inData, inDataLen, SHA1digest );
      /* verify the digest against the signature */
      status = RSA_verify( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, pSignature, cypherLen, keyLocal );
      /* check for errror and return */
      if ( status ){
         RSA_free( keyLocal );
         return OK;
      }else{
         RSA_free( keyLocal );
         return VERIFY_ERROR;
      }
   } else {/* input data is bigger than the key */ 

      /* allocate the space for message */
      message = (unsigned char*)malloc( cypherLen );
      /* do it counter times */
      while ( counter != 0 )
      {

         /* get the message */
         memcpy( message, inData + offset, cypherLen );
         /* get the digest */
         SHA1( message, cypherLen, SHA1digest );

         /* verify the message and check for error */
         if ( !RSA_verify( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, pSignature + offset, cypherLen, keyLocal) )
         {
            /* free the memory and return error */
            free( message );
            RSA_free( keyLocal );

            return VERIFY_ERROR;
         }
         /* update the counter and the offset */
         offset = offset + cypherLen;
         counter--;
      }
      /* any input data left - if so do the same as above for the last time */
      if ( divResult.rem != 0 )
      {
         memcpy(message, inData + offset, divResult.rem );
         SHA1( message, divResult.rem, SHA1digest );
         if ( !RSA_verify( NID_sha1, SHA1digest, SHA_DIGEST_LENGTH, pSignature + offset, cypherLen, keyLocal) )
         {
            free( message );
            RSA_free( keyLocal );
            return VERIFY_ERROR;
         }

      }
      /* free the memory and return OK */
      free( message );
      RSA_free( keyLocal );
      return OK;
   }
}

/**
* Prints the given error message to stderr and exits with given error number
* @param number       Error number
* @param description  Error description
*/
void RsaPkcs1Sign::showError(int number, char* description)
 {
    fprintf(stderr, "Error %d: %s\n", number, description);
}

//char *RsaPkcs1Sign::base64encode(const unsigned char *inputBuffer, int inputLen) {
//    EVP_ENCODE_CTX  ctx;
//    int base64Len = (((inputLen+2)/3)*4) + 1; // Base64 text length
//    int pemLen = base64Len + base64Len/64; // PEM adds a newline every 64 bytes
//    char* base64 = new char[pemLen];
//    int result;
//    EVP_EncodeInit(&ctx);
//    EVP_EncodeUpdate(&ctx, (unsigned char *)base64, &result, (unsigned char *)inputBuffer, inputLen);
//    EVP_EncodeFinal(&ctx, (unsigned char *)&base64[result], &result);
//    return base64;
//}