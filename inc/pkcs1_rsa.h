#ifndef __openssl__MyRSA__
#define __openssl__MyRSA__

#include <stdio.h>
#include <string.h>
#include "key.h"

/* error codes */
#define BAD_DATA  1
#define GENERATOR_ERROR  2
#define KEY_GEN_ERROR 3
#define MEM_ALLOC_ERROR 4
#define STRING_SET_ERROR 5
#define BUF_SHORT 6

/* verification errors */
#define SELF_SIGN_OR_PATH 7
#define CERT_EXPIRED 8
#define CA_INVALID 9
#define SIGN_ERROR 10
#define VERIFY_ERROR 11
#define  OK 0
#define  SHA_DIGEST_LENGTH  20

typedef unsigned  int32 __attribute__ ((aligned (8)));

struct MovelSuperTvHead{
	char Name[8];
	int32_t Length;
	char Type;
    char staAttr;
	short dynAttr;
}__attribute__ ((aligned (8)));
typedef struct MovelSuperTvHead MovelSuperTvHead;

class RsaPkcs1Sign 
{
public:
    RsaPkcs1Sign(Key *key);
	RsaPkcs1Sign();
	
	char* GetFileName(char* path);
	int32 GetFileSize(FILE* pFile);

	int RemoveSigHead(char* fileName);
    int AddSignHead(char* fileName, 
					const unsigned char *signature, 
					unsigned int slen);	
	int AddMovSuperTvHead(char* fileName, MovelSuperTvHead *mMovelSuperTvHead);
	
	int myEncrypt(const unsigned char *plain, 
				  int length,
	              unsigned char *cipher, 
				  unsigned int &r_length);
	int myDecrypt(const unsigned char *cipher, 
				  int length, 
		          unsigned char *plain, 
				  unsigned int &r_length);
    
	int Sign_Type1(const unsigned char *plain, 
				   int length, 
    	           unsigned char *cipher, 
				   unsigned int &r_length);			   
	int Verify_Type1(const unsigned char *cipher, 
					 int length, 
    		         unsigned char *plain, 
					 int plainLength); 
					 
	int Sign_Type2(const unsigned char *plain, 
				   int length, 
    	           unsigned char *cipher, 
				   unsigned int &r_length);
	int Verify_Type2(const unsigned char *cipher, int length, 
    		     unsigned char *plain, int plainLength); 
				 
	unsigned long Sign_Type3(unsigned char *inBuffer,
					   unsigned long inBufferLen,
					   unsigned char **outSignature,
					   unsigned int *outSignatureLen );
	unsigned long Verify_Type3(unsigned char *inData,
							    unsigned long inDataLen,
							    unsigned char *pSignature,
								unsigned long pSigLen);
	unsigned long Sign_Type4( unsigned char *inBuffer,
                          unsigned long inBufferLen,
                          unsigned char **outSignature,
                          unsigned int *outSignatureLen );	
	
	unsigned long Verify_Type4(unsigned char *inData,
							    unsigned long inDataLen,
							    unsigned char *pSignature,
								unsigned long pSigLen);							
	void showError(int number, char* description);
	//    char *base64encode(const unsigned char *inputBuffer, int inputLen);	
public:
    Key *key;
private:
	int32 mSignedLen;
};

#endif /* defined(__openssl__MyRSA__) */
