#include "encryptors.h"
#include <cstring>
#include <iostream>
#include <ostream>
#include <fstream>

encryptors::encryptors()
{

}

void encryptors::set_up()
{
    std::ifstream key_stream("aes.key");
    std::ifstream iv_stream("iv.key");
    if(key_stream.good() || iv_stream.good())
    {
        key_stream >> aes_key;
        iv_stream >> iv_key;//Get our keys
        key_stream.close();
        iv_stream.close();
        initialized = true;
        std::cout << aes_key << std::endl;
        std::cout << iv_key << std::endl;
    }
    else
    {
        key_stream.close();
        iv_stream.close();
    }
}

void encryptors::aes_enc(std::string& dataa)
{
    if(initialized)
    {
        std::string data(dataa);
        // Need to copy our IV
        uint8_t iv_temp[AES_BLOCK_SIZE];
        std::copy(std::begin(iv_key), std::end(iv_key), std::begin(iv_temp));


        AES_KEY* key = new AES_KEY();//create the key structure
        AES_set_encrypt_key(aes_key, 256, key);//encrypt 256bit

        std::vector<unsigned char> pad(data.begin(), data.end());
        for(int i=0; i < (AES_BLOCK_SIZE - (data.length() % AES_BLOCK_SIZE)); i++)
        {//String length needs to be divisible by 16
            pad.push_back(0);
        }

        unsigned char * UserData = &pad[0];// last convert
        const int pad_size = (const int)pad.size();//requires const


        unsigned char encrypted[2048] = {0}; //Required output type
        AES_cbc_encrypt(UserData, encrypted, pad_size, (const AES_KEY*)key, iv_temp, AES_ENCRYPT);
        std::string dat(reinterpret_cast<char*>(encrypted));
        dataa = dat;
        std::cout << "AES Encrypt: " << dataa << "\n" << std::endl;
    }
}

void encryptors::aes_dec(std::string& dataa)
{
    if(initialized)
    {
        std::string data(dataa);
        // Need to copy our IV
        uint8_t iv_temp[AES_BLOCK_SIZE];
        std::copy(std::begin(iv_key), std::end(iv_key), std::begin(iv_temp));


        //Don't have to pad, since we get from padded source
        AES_KEY* key = new AES_KEY(); //create the key structure
        AES_set_decrypt_key((unsigned char*)aes_key, 256, key);//decrypt 256bit

        unsigned char *info=new unsigned char[2048];
        strcpy((char *)info,data.c_str());//copy our data to be used

        unsigned char decrypted[1024] = {0}; //Required output type
        AES_cbc_encrypt(info, decrypted, data.size(), (const AES_KEY*)key, iv_temp, AES_DECRYPT);

        std::string dat(reinterpret_cast<char*>(decrypted));
        dataa = dat;
        std::cout << "AES Decrypt: " << dataa << "\n" << std::endl;
    }
}

char *encryptors::base64_encode(const unsigned char *input, int data_len)
{
  const auto p_length = 4 * ((data_len+2) / 3);
  auto output = reinterpret_cast<char *>(calloc(p_length+1, 1)); //needs +1 extra for null terminator
  EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, data_len);
  std::cout << "Base64 Encode: " << output << "\n" << std::endl;
  return output;
}

char *encryptors::base64_decode(const char *input, int data_len)
{
  const auto p_length = 3*data_len/4;
  auto output = reinterpret_cast<char *>(calloc(p_length+1, 1)); //needs +1 extra for null terminator
  EVP_DecodeBlock(reinterpret_cast<unsigned char *>(output), reinterpret_cast<const unsigned char *>(input), data_len);
  std::cout << "Base64 Decode: " << output << "\n" << std::endl;
  return output;
}
