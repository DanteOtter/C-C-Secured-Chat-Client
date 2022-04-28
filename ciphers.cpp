#include "ciphers.h"
#include <cstring>
#include <cmath>
#include <iostream>
#include <algorithm>
#include <ctime>
#include <random>

std::mt19937 gen( time( 0 ) );//Generates pseudo-random values

Ciphers::Ciphers()
{
}


void Ciphers::set_up(std::string xor_key, bool XOR, bool ceaser, bool subs, bool rev, int rotn, std::string alpha)
{
    this->xor_key = xor_key;
    this->XOR = XOR;
    this->ceaser = ceaser;
    this->subs = subs;
    this->rev = rev;
    this->rotn_count = rotn;

    if(subs)
    {
        if(std::strlen(alpha.c_str()))
        {
            gen_alpha_maps(alpha);
        }
        else
        {
            gen_alpha_maps(gen_alpha());
        }
    }
}

void Ciphers::cipher(std::string& data)
{
    std::cout << "Original: " << data << "\n" << std::endl;
    if(rev)
    {
        reverse(data);
        std::cout << "Encode Reverse: " << data << "\n" << std::endl;
    }
    if(ceaser)
    {
        rotn(data, rotn_count);
        std::cout << "Encode Ceaser: " << data << "\n" << std::endl;
    }
    if(subs)
    {
        alberti_encode(data);
        std::cout << "Encode Substitute: " << data << "\n" << std::endl;
    }
    if(XOR)
    {
        xor_crypt(data,xor_key);
        std::cout << "Encode xor: " << data << "\n" << std::endl;
    }
}

void Ciphers::decipher(std::string& data)
{
    if(XOR)
    {
        xor_crypt(data,xor_key);
        std::cout << "Decode xor: " << data << "\n" << std::endl;
    }
    if(subs)
    {
        alberti_decode(data);
        std::cout << "Decode Substitute: " << data << "\n" << std::endl;
    }
    if(ceaser)
    {
        rotn_decipher(data, rotn_count);
        std::cout  << "Decode Ceaser: " << data << "\n" << std::endl;}
    if(rev)
    {
        reverse(data);
        std::cout << "Decode Reverse: " << data << "\n" << std::endl;
    }
}


bool Ciphers::reverse(std::string& data)
{
    if(!std::strlen(data.c_str()))
    {
        return false;
    }

    int n = data.length();

    // Swap characters
    // Switches 2 outers until reaches center
    for (int i = 0; i < n / 2; i++)
    {
        std::swap(data[i], data[n - i - 1]);
    }

    return true;
}

//Affects ascii values between 48(0) and 122(z)
//These are Uppercase, Lowercase, and Numerals
bool Ciphers::rotn(std::string& data,int rot)
{
    if(!std::strlen(data.c_str()))
    { //Don't bother if we don't have a string length
        return false;
    }

    for(int index=0; index<std::strlen(data.c_str()); index++)
    {//Loop through all indexes
        if(data[index] >= 48 && data[index] <= 122)
        {//Only operate on character in our range
            int temp = (int)data[index];
            //Possible for end of range to wrap back into our range
            //Reposition to match
            if(temp + rot > 122) temp += 48;
            temp = ((temp + rot) % 123);
            //Reposition characters that did not wrap back into range
            if (temp < 48) temp += 48;
            data[index] = (char)temp;
        }
    }
    return true;
}

bool Ciphers::rotn_decipher(std::string& data,int rot)
{
    if(!std::strlen(data.c_str()))
    { //Don't bother if we don't have a string length
        return false;
    }
    rot = 75 - rot; //Total rot size - rot that was applied

    for(int index=0; index<std::strlen(data.c_str()); index++)
    {
        if(data[index] >= 48 && data[index] <= 122)
        {//Only operate on character in our range
            int temp = (int)data[index];
            //Possible for end of range to wrap back into our range
            //Reposition to match
            if(temp + rot > 122) temp += 48;
            temp = ((temp + rot) % 123);
            //Reposition characters that did not wrap back into range
            if (temp < 48) temp += 48;
            data[index] = (char)temp;
        }
    }
    return true;
}

//Creates random order of alphabet
//Used to implement letter substitution() alberti_disk
std::string Ciphers::gen_alpha()
{
    std::string alpha{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    shuffle( alpha.begin(), alpha.end(), gen );
    return alpha;
}

bool Ciphers::gen_alpha_maps(std::string new_alpha)
{
    const std::string alpha{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    if(std::strlen(new_alpha.c_str()) != std::strlen(alpha.c_str()))
    {
        return false;
    }

    for (int i=0; i<std::strlen(alpha.c_str()); i++)
    {
        encode_alpha_map.insert(std::pair<char,char>(alpha[i], new_alpha[i]));
    }



    for (int i=0; i<std::strlen(alpha.c_str()); i++)
    {
        decode_alpha_map.insert(std::pair<char,char>(new_alpha[i], alpha[i]));
    }

    return true;
}

bool Ciphers::alberti_encode(std::string& data)
{
    if(!std::strlen(data.c_str()))
    { //Don't bother if we don't have a string length
        return false;
    }

    for (int index=0; index<std::strlen(data.c_str()); index++)
    {
        bool in_range = data[index] >= 65 && data[index] <= 122,
             is_excluded = data[index] >= 91 && data[index] <= 96;
        if(in_range && !is_excluded)
        {
            data[index] = encode_alpha_map[data[index]];
        }
    }

    return true;
}

bool Ciphers::alberti_decode(std::string& data)
{
    if(!std::strlen(data.c_str()))
    { //Don't bother if we don't have a string length
        return false;
    }

    for (int index=0; index<std::strlen(data.c_str()); index++)
    {
        bool in_range = data[index] >= 65 && data[index] <= 122,
             is_excluded = data[index] >= 91 && data[index] <= 96;
        if(in_range && !is_excluded)
        {
            data[index] = decode_alpha_map[data[index]];
        }
    }

    return true;
}

bool Ciphers::xor_crypt(std::string& data, std::string key)
{
    // calculate length of input string
    int msg_len = std::strlen(data.c_str());
    int key_len = std::strlen(key.c_str());

    if(!key_len)
    {
        return false;
    }

    for (int i = 0; i < msg_len; i++)
    {
        data[i] = data[i] ^ key[i % key_len];
    }
    return true;
}

bool Ciphers::vigenere_encode(std::string& msg, std::string key)
{
    // calculate length of input string
    int msg_len = std::strlen(msg.c_str());
    std::string new_key;

    for (int i = 0; ; i = ((i+1)%key.length()))
    {
        if (msg_len <= new_key.length())
            break;
        new_key.push_back(key[i]);
    }

    for (int i = 0; i < msg_len; i++)
    {
        // converting in range 0-25
        char x = (msg[i] + new_key[i]) %26;

        // convert into alphabets(ASCII)
        x += 'A';
        msg[i] = x;
    }
    return true;
}

bool Ciphers::vigenere_decipher(std::string& msg, std::string key)
{
    // calculate length of input string
    int msg_len = std::strlen(msg.c_str());
    std::string new_key;

    for (int i = 0; ; i = ((i+1)%key.length()))
    {
        if (msg_len == new_key.length())
            break;
        new_key.push_back(key[i]);
    }


    for (int i = 0 ; i < msg_len; i++)
    {
        // converting in range 0-25
        char x = (msg[i] - new_key[i] + 26) %26;

        // convert into alphabets(ASCII)
        x += 'A';
        msg[i] = x;

    }
    return true;
}
