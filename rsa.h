#pragma once

#include <gmpxx.h>
#include <stdint.h>
#include <vector>
#include <string>

typedef std::vector<uint8_t> vec_u8;

bool comp_bytes(vec_u8& a, vec_u8& b);

mpz_class bytes_to_mpz(vec_u8& bytes);

vec_u8 mpz_to_bytes(mpz_class& m);

vec_u8 u32_to_bytes(uint32_t num);

vec_u8 str_to_bytes(std::string str);

std::string bytes_to_str(vec_u8 bytes);

vec_u8 concat_bytes(vec_u8& v1, vec_u8& v2);

void generateKeys(mpz_class& privateKey, mpz_class& publicKey, mpz_class& exponent);

int RSA_Enc(mpz_class& n, mpz_class& e, mpz_class& m, mpz_class& c);

int RSA_Dec(mpz_class& n, mpz_class& d, mpz_class& c, mpz_class& m);

int MGF1(vec_u8& output, vec_u8 &seed, uint64_t maskLen);

int OAEP_Enc(vec_u8& EM, vec_u8& M, vec_u8& P,  uint64_t len);

int OAEP_Dec(vec_u8& M, vec_u8& EM, vec_u8& P);

int RSA_OAEP_Enc(mpz_class& n, mpz_class& e, vec_u8& M, vec_u8& P, vec_u8& C);

int RSA_OAEP_Dec(mpz_class& n, mpz_class& d, vec_u8& C, vec_u8& P, vec_u8& M);

