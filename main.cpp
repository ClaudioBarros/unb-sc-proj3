#include "rsa.h"
#include <iostream>
#include <sstream>

int main() {

    mpz_class privKey(0);
    mpz_class pubKey(0);
    mpz_class exp(0);

    generateKeys(privKey, pubKey, exp);
    std::cout << "Private Key = " << privKey << "\n"
              << "Public Key =  " << pubKey << "\n"
              << "Exponent = " << exp << "\n";

    std::string str = "It's just a flesh wound";

    vec_u8 M = str_to_bytes(str);
    vec_u8 P(0);
    vec_u8 C(0);
    vec_u8 M2(0);

    //mpz_import(M.get_mpz_t(), strdata.size(), 1, sizeof(strdata[0]), 0, 0, &strdata[0]);

    //RSA_OAEP_Enc(mpz_class &n, mpz_class &e, vec_u8 &M, vec_u8 &P, vec_u8 &C);
    RSA_OAEP_Enc(pubKey, exp, M, P, C);

    //RSA_OAEP_Dec(mpz_class &n, mpz_class &d, vec_u8 &C, vec_u8 &P, vec_u8 &M);
    RSA_OAEP_Dec(pubKey, privKey, C, P, M2);

    std::cout << "Plaintext: " << bytes_to_str(M) << "\n";
    std::cout << "Encrypted: " << bytes_to_str(C) << "\n";
    std::cout << "Decrypted: " << bytes_to_str(M2) << "\n";
}
