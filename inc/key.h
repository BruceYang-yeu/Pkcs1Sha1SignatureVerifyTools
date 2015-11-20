#ifndef __openssl__Key__
#define __openssl__Key__

#include <stdio.h>
#include <string>
#include <openssl/rsa.h>

using namespace std;
class Key 
{
public:

    Key(unsigned num, unsigned long e);
    Key(string publicKeyFile, string privateKeyFile);
    Key(string privateKeyFile, short d1, short d2);
    Key(string publicKeyFile, short e);
    ~Key();
	
    void generateNewKey(string publicKeyFile, string privateKeyFile);
    void reload();
 
public:
    RSA *rsa;
    RSA *privateKey;
    RSA *publicKey;
private:
    string priName;
    string pubName;
    unsigned key_num;
    short d1, d2, e; 	        //for Overload
    unsigned long key_e; 	//key_e default: RSA_F4(65537)
};

#endif /* defined(__openssl__Key__) */
