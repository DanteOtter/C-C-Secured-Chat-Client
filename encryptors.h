#ifndef ENCRYPTORS_H
#define ENCRYPTORS_H

#include <inttypes.h>
#include <string>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#pragma comment(lib,"libeay32MD.lib")

class encryptors
{
public:
    encryptors();
    void set_up();
    void aes_enc(std::string&);
    void aes_dec(std::string&);

    char* base64_encode(const unsigned char *input, int length);
    char* base64_decode(const char *input, int length);
    void test();

private:
    const int buffer = 1024;
    unsigned char aes_key[128],
         iv_key[AES_BLOCK_SIZE];
    bool initialized = false;
};

#endif // ENCRYPTORS_H
