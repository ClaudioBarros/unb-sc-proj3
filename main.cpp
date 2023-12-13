#include "rsa.h"
#include <iostream>
#include <sstream>
#include <random>
#include <ctime>

static std::default_random_engine rd{static_cast<unsigned>(time(0))};
static std::mt19937 random_generator(rd());

std::string gen_test_string(size_t len)
{
    const char* charset = 
        "!#$%&\'()*+,-./0123456789:;<=>?@[\\]^_{|}~`"
        "012345678910"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓ"
        "àáâãäåæçèéêëìíîïðñòó"
        "ÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïð";
    
    std::string str = charset;
    while(len > str.length()) 
        str += str;
    
    std::shuffle(str.begin(), str.end(), random_generator);
    return str.substr(0, len);
}

void rsa_random_test()
{
    std::cout << std::string(32, '-') 
              << "RSA Test Begin" 
              << std::string(32, '-')
              << "\n\n";

    mpz_class privKey(0);
    mpz_class pubKey(0);
    mpz_class exp(0);

    generateKeys(privKey, pubKey, exp);
    std::cout << "Private Key = " << privKey << "\n\n"
              << "Public Key =  " << pubKey << "\n\n"
              << "Exponent = " << exp << "\n\n";

    std::string str = gen_test_string(128);
    vec_u8 M = str_to_bytes(str);
    vec_u8 P(0);
    vec_u8 C(0);
    vec_u8 M2(0);

    RSA_OAEP_Enc(pubKey, exp, M, P, C);
    RSA_OAEP_Dec(pubKey, privKey, C, P, M2);

    std::cout << "Plaintext: \" " << bytes_to_str(M) << " \"\n\n";
    std::cout << "Encrypted: \" " << bytes_to_str(C) << " \"\n\n";
    std::cout << "Decrypted: \" " << bytes_to_str(M2) <<  "\"\n\n";
}

int main() 
{
    uint32_t num_tests;
    std::cout << "Enter the number of random RSA tests to be performed: ";
    std::cin >> num_tests; 
    std::cout << "\n\n";

    for(uint32_t i = 0; i < num_tests; i++)
        rsa_random_test();
}
