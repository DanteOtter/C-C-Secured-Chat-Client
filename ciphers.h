#ifndef CIPHERS_H
#define CIPHERS_H
#include <map>
#include <string>

class Ciphers
{
public:
    Ciphers();
    void set_up(std::string xor_key, bool XOR, bool ceaser, bool subs, bool rev, int rotn, std::string alpha);
    bool rotn(std::string&,int);
    bool rotn_decipher(std::string&,int);
    bool xor_crypt(std::string&, std::string);
    bool vigenere_encode(std::string&, std::string);
    bool vigenere_decipher(std::string&, std::string);
    bool reverse(std::string&);
    bool alberti_encode(std::string&);
    bool alberti_decode(std::string&);
    std::string gen_alpha();
    bool gen_alpha_maps(std::string);
    void cipher(std::string&);
    void decipher(std::string&);

private:
    //const std::string alpha{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    //const char padchar[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::map<char,char> encode_alpha_map;
    std::map<char,char> decode_alpha_map;

    bool XOR,
         ceaser,
         subs,
         rev,
         ssl;
    int rotn_count;
    std::string xor_key;
};

#endif // CIPHERS_H
