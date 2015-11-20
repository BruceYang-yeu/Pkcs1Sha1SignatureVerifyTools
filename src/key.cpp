#include "key.h"
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

Key::Key(unsigned num, unsigned long e):key_num(2048), key_e(3)
{
    rsa = NULL;
    privateKey = NULL;
    publicKey = NULL;

    key_num = num;
    key_e = e;
}

Key::Key(string privateKeyFile, short d1, short d2):d1(1), d2(2)
{
    rsa = NULL;
    privateKey = NULL;
    priName = privateKeyFile;

    if (!privateKeyFile.empty()) 
    {
        FILE *fp = fopen(privateKeyFile.c_str(), "r");
        if (fp == NULL) {
            cout << "Private Key File Error!" << endl;
            exit(-1);
        }
        privateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    }
}

Key::Key(string publicKeyFile, short e):e(1)
{
    rsa = NULL;
    publicKey = NULL;
    pubName = publicKeyFile;

    if (!publicKeyFile.empty()) {
        FILE *fp = fopen(publicKeyFile.c_str(), "r");
        if (fp == NULL) {
            cout << "Public Key File Error!" << endl;
            return ;
        }
        //rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
        publicKey = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        fclose(fp);
        return ;
    }
}

Key::Key(string publicKeyFile, string privateKeyFile)
{
    rsa = NULL;
    privateKey = NULL;
    publicKey = NULL;
    priName = privateKeyFile;
    pubName = publicKeyFile;
    
    if (!privateKeyFile.empty()) {
        FILE *fp = fopen(privateKeyFile.c_str(), "r");
        if (fp == NULL) {
            cout << "Private Key File Error!" << endl;
            return ;
        }
        privateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    }
    if (!publicKeyFile.empty()) {
        FILE *fp = fopen(publicKeyFile.c_str(), "r");
        if (fp == NULL) {
            cout << "Public Key File Error!" << endl;
            return ;
        }
        //rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
        publicKey = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        fclose(fp);
        return ;
    }
    cout << "Error Open Private Key or Public Key!" << endl;
}

void Key::reload()
{
    if (!priName.empty()) {
        FILE *fp = fopen(priName.c_str(), "r");
        if (fp == NULL) {
            cout << "Private Key File Error!" << endl;
            return ;
        }
        privateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    }
    if (!pubName.empty()) {
        FILE *fp = fopen(pubName.c_str(), "r");
        if (fp == NULL) {
            cout << "Public Key File Error!" << endl;
            return ;
        }
        publicKey = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        fclose(fp);
        return ;
    }
}

void Key::generateNewKey(string publicKeyFile, string privateKeyFile)
{
    priName = privateKeyFile;
    pubName = publicKeyFile;

    RSA *rsa = RSA_generate_key(key_num, key_e, NULL, NULL);
    if (rsa == NULL) {
        cout << "RSA_generate_key Error!" << endl;
        return ;
    }
    
    if (!publicKeyFile.empty())
    {
        BIO *priBio = BIO_new_file(privateKeyFile.c_str(), "w");
        if (PEM_write_bio_RSAPrivateKey(priBio, rsa, NULL, NULL, 0, NULL, NULL) <= 0) {
            cout << "Save to private key file error!" << endl;
        }
       BIO_free(priBio);
    } else {
         cout << "PublicKeyfile is empty!" << endl;
    }
    
    if (!privateKeyFile.empty()) {
        BIO *pubBio = BIO_new_file(publicKeyFile.c_str(), "w");
        if (PEM_write_bio_RSAPublicKey(pubBio, rsa) <= 0) {
            cout << "Save to public key file error!" << endl;
        }
        BIO_free(pubBio);
    } else {
        cout << "privateKeyFile is empty" <<endl;
    }

    this->rsa = rsa;
    privateKey = RSAPrivateKey_dup(rsa);
    publicKey = RSAPublicKey_dup(rsa);
}

Key::~Key() {
    if (rsa != NULL)
        RSA_free(rsa);
    if (privateKey != NULL)
        RSA_free(privateKey);
    if (publicKey != NULL)
        RSA_free(publicKey);
}
