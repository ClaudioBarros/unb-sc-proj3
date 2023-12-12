#include "rsa.h"
#include <chrono>
#include <sstream>
#include <iostream>
#include <cmath>
#include <openssl/sha.h>

#define HASH_LEN 20 //160 bits 

#define HASH_MAX_INPUT 2305843009213693951ull //2^61 - 1

bool comp_bytes(vec_u8& a, vec_u8& b)
{
    if(a.size() != b.size())
        return false;
    bool equal = false;
    for(size_t i = 0; i < a.size(); i++)
    {
        if(a[i] != b[i]) 
            return false; 
    }
    return true;
}

mpz_class bytes_to_mpz(vec_u8& bytes)
{
    mpz_class m(0);
    mpz_import(m.get_mpz_t(), bytes.size(), 1, sizeof(bytes[0]), 0, 0, &bytes[0]);
    return m;
}

vec_u8 mpz_to_bytes(mpz_class& m)
{
    size_t len = mpz_sizeinbase(m.get_mpz_t(), 2);
    vec_u8 bytes(len/8, 0);
    mpz_export(&bytes[0], 0, 1, sizeof(bytes[0]), 0, 0, m.get_mpz_t());
    return bytes;
}


vec_u8 u32_to_bytes(uint32_t num)
{
    vec_u8  bytes(4, 0);

    uint8_t* pnum = (uint8_t *) &num;
    bytes[0] = pnum[0];
    bytes[1] = pnum[1];
    bytes[2] = pnum[3];
    bytes[4] = pnum[4];

    return bytes;
}

vec_u8 str_to_bytes(std::string str)
{
    vec_u8 strdata(str.size(), 0);
    std::copy(str.begin(), str.end(), &strdata[0]);
    return strdata;
}

std::string bytes_to_str(vec_u8 bytes)
{
    return std::string(reinterpret_cast<char*>(&bytes[0]), bytes.size());
}

vec_u8 concat_bytes(vec_u8& v1, vec_u8& v2)
{
    vec_u8 out = v1;
    out.insert(out.end(), v2.begin(), v2.end());
    return out;
}

void generateKeys(mpz_class& privateKey, mpz_class& publicKey, mpz_class& exponent)
{
    std::chrono::time_point<std::chrono::system_clock>  now = std::chrono::system_clock::now();
    std::time_t seedValue = std::chrono::system_clock::to_time_t(now);

    gmp_randclass randclass(gmp_randinit_default);
    randclass.seed(seedValue);
    
    mpz_class p(0);
    mpz_class q(0);
    mpz_class tmp(0);

    mpz_class range(0);
    mpz_ui_pow_ui(range.get_mpz_t(), 2, 2048);

    //get p with at least 1024 bits
    tmp = randclass.get_z_range(range);
    while(mpz_sizeinbase(tmp.get_mpz_t(), 2) < 1024)
    {
        tmp = randclass.get_z_range(range);
    }
    mpz_nextprime(p.get_mpz_t(), tmp.get_mpz_t());

    std::cout << "P = " << p << "\n";

    //get q with at least 1024 bits
    tmp = randclass.get_z_range(range);
    while(mpz_sizeinbase(tmp.get_mpz_t(), 2) < 1024)
    {
        tmp = randclass.get_z_range(range);
    }
    mpz_nextprime(q.get_mpz_t(), tmp.get_mpz_t());

    mpz_class n = p * q;

    std::cout << "Q = " << q << "\n";
    std::cout << "N = " << n << "\n";

    //get Charmichael's totient function
    mpz_class lambdaP = p - 1;
    mpz_class lambdaQ = q - 1;
    mpz_class lambdaN = lcm(lambdaP, lambdaQ);

    mpz_class e(65537u);
    mpz_class d(0);

    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), lambdaN.get_mpz_t());

    publicKey = n;
    exponent = e;
    privateKey = d;
}

int RSA_Enc(mpz_class& n, mpz_class& e, mpz_class& m, mpz_class& c)
{
    if(m < 0 || m > (n-1)) 
    {
        std::cout << "message representative out of range\n";
        return 0;
    }

    mpz_powm_sec(c.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
    return 1;
}

int RSA_Dec(mpz_class& n, mpz_class& d, mpz_class& c, mpz_class& m)
{
    if(c < 0 || c > n-1)
    {
        std::cout << "ciphertext representative out of range\n";
        return 0;
    }

    mpz_powm_sec(m.get_mpz_t(), c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
    return 1;
}

int MGF1(vec_u8& output, vec_u8 &seed, uint64_t maskLen) 
{
    uint64_t maxLen = ((uint64_t)HASH_LEN) << 32; //2^32 * hLen
    if(maskLen > maxLen)
        return 0;        

    vec_u8 tmp;
    for(uint32_t i = 0; i < maskLen; i++)
    {
        vec_u8  i_bytes = u32_to_bytes(i);
        vec_u8 s = concat_bytes(seed, i_bytes);
        vec_u8 hashOut(HASH_LEN, 0);
        SHA1(&s[0], s.size(), &hashOut[0]);

        tmp = concat_bytes(tmp, hashOut);
    }
    
    output.resize(0);
    output.insert(output.end(), tmp.begin(), tmp.begin() + maskLen);
    return 1; 
}

int OAEP_Enc(vec_u8& EM, vec_u8& M, vec_u8& P,  uint64_t len)
{
    if(M.size() > (len - 2*HASH_LEN - 1))
    {
        std::cout << "[OAEP_Enc] message too long\n";
        return 0;
    }
    if(P.size() > HASH_MAX_INPUT)
    {
        std::cout << "[OAEP_Enc] parameter string too long\n";
        return 0;
    }
    
    int64_t psLen = len - M.size() - 2*HASH_LEN - 1;
    vec_u8 PS((psLen > 0 ? psLen : 0), 0);
    
    vec_u8 pHash(HASH_LEN, 0);
    SHA1(&PS[0], PS.size(), &pHash[0]);

    vec_u8 DB = concat_bytes(pHash, PS);
    DB.push_back(0x01);
    DB = concat_bytes(DB, M);

    gmp_randclass randclass(gmp_randinit_default);
    
    mpz_class seed = randclass.get_z_bits(HASH_LEN*8);
    
    vec_u8 seed_bytes(20, 0);
    //void * mpz_export (void *rop, size t *countp, int order, size t size, int
    //                   endian, size t nails, const mpz t op)
    mpz_export(&seed_bytes[0], 0, 1, sizeof(seed_bytes[0]), 0, 0, seed.get_mpz_t());
    
    vec_u8 dbMask(0);

    if(!MGF1(dbMask, seed_bytes, len - HASH_LEN))
        return 0;

    mpz_class maskedDB_mpz(0);
    mpz_class DB_mpz = bytes_to_mpz(DB);
    mpz_class dbMask_mpz = bytes_to_mpz(dbMask);
    
    mpz_xor(maskedDB_mpz.get_mpz_t(), DB_mpz.get_mpz_t(), dbMask_mpz.get_mpz_t());
    
    vec_u8 maskedDB = mpz_to_bytes(maskedDB_mpz);

    vec_u8 seedMask(0);
    if(!MGF1(seedMask, maskedDB, HASH_LEN))
        return 0;

    mpz_class maskedSeed_mpz(0);
    mpz_class seedMask_mpz = bytes_to_mpz(seedMask);
    mpz_xor(maskedSeed_mpz.get_mpz_t(), seed.get_mpz_t(), seedMask_mpz.get_mpz_t());
    
    vec_u8 maskedSeed = mpz_to_bytes(maskedSeed_mpz);

    EM = concat_bytes(maskedSeed, maskedDB);

    return 1;
}

int OAEP_Dec(vec_u8& M, vec_u8& EM, vec_u8& P)
{
    if(P.size() > HASH_MAX_INPUT)
    {
        std::cout << "[OAEP_Dec] decoding error: parameter length do not match hash length in bytes\n";
        return 0;
    }
    if(EM.size() < (2*HASH_LEN + 1)) 
    {
        std::cout << "[OAEP_Dec] EM length too short\n";
        return 0;
    }
    
    vec_u8 maskedSeed = vec_u8(EM.begin(), EM.begin() + HASH_LEN);
    vec_u8 maskedDB = vec_u8(EM.begin()+HASH_LEN, EM.end());
    vec_u8 seedMask(0);
    MGF1(seedMask, maskedDB, HASH_LEN);

    mpz_class seed_mpz(0); 
    mpz_xor(seed_mpz.get_mpz_t(),
            bytes_to_mpz(maskedSeed).get_mpz_t(),
            bytes_to_mpz(seedMask).get_mpz_t());
    vec_u8 seed = mpz_to_bytes(seed_mpz);
       
    vec_u8 dbMask(0);
    MGF1(dbMask, seed, (EM.size() - HASH_LEN));

    mpz_class DB_mpz(0);
    mpz_xor(DB_mpz.get_mpz_t(),
            bytes_to_mpz(maskedDB).get_mpz_t(),
            bytes_to_mpz(dbMask).get_mpz_t());

    vec_u8 DB = mpz_to_bytes(DB_mpz);

    vec_u8 pHash(HASH_LEN, 0);
    SHA1(&P[0], P.size(), &pHash[0]);

    vec_u8 pHashDB = vec_u8(DB.begin(), DB.begin()+HASH_LEN);
    
    if(comp_bytes(pHash, pHashDB) == false)
    {
        std::cout << "[OAEP_Dec] decoding error: hash values do not match\n";
        return 0;
    }

    vec_u8 PS(0);
    bool separatorFound = false;
    size_t MBegin = 0;
    for(size_t i = HASH_LEN; i < DB.size(); i++)
    {
        if(DB[i] == 0)
            continue;
        if(DB[i] == 1)
        {
            if(i != DB.size() - 1)
            {
                separatorFound = true;
                MBegin = i + 1;
            }
        }
    }

    if(separatorFound)
    {
        M = vec_u8(DB.begin() + MBegin, DB.end());
        return 1;
    }
    else
    {
        std::cout << "[OAEP_Dec] decoding error: 0x01 separator not found\n";
        return 0;
    }
}


int RSA_OAEP_Enc(mpz_class& n, mpz_class& e, vec_u8& M, vec_u8& P, vec_u8& C)
{
    vec_u8 EM(0);

    size_t modlen = mpz_sizeinbase(n.get_mpz_t(), 2)/8;
    if(!OAEP_Enc(EM, M, P, modlen-1))
        return 0;
    
    mpz_class M_mpz = bytes_to_mpz(EM);
    mpz_class C_mpz(0);

    if(!RSA_Enc(n, e, M_mpz, C_mpz))
        return 0;
    
    C.clear();
    C = mpz_to_bytes(C_mpz);
    return 1;
}

int RSA_OAEP_Dec(mpz_class& n, mpz_class& d, vec_u8& C, vec_u8& P, vec_u8& M)
{
    mpz_class clen(C.size());
    if(clen != n) 
    {
        std::cout << "[RSA_OAEP_Dec] ciphertext length in bytes does not match modulus length in bytes\n";
        return 0;
    } 

    mpz_class C_mpz = bytes_to_mpz(C);
    mpz_class EM_mpz(0);
    if(!RSA_Dec(n, d, C_mpz, EM_mpz))
    {
        std::cout << "[RSA_OAEP_Dec] decryption error\n";
        return 0;
    }

    vec_u8 EM = mpz_to_bytes(EM_mpz);
    if(!OAEP_Dec(M, EM, P))
    {
        std::cout << "[RSA_OAEP_Dec] decryption error\n";
        return 0;
    }

    return 1;
}
