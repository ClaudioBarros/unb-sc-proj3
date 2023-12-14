# RSA-OAEP 

This repository contains the code for a simple implementation of the RSA encryption algorithm with the OAEP padding scheme. 

## Overview

The project includes the following components:

    RSA Implementation:
        Key generation using large prime numbers.
        Encryption and decryption functions following the RSA algorithm.

    OAEP Padding:
        Implementation of the OAEP scheme to enhance the security of RSA.
        Use of hash functions and random masks to prevent vulnerabilities.


## Prerequisites

* **C++ Compiler** - needs to support at least the **C++11** standard, i.e. *MSVC*, *GCC*, *Clang*
* [**GNU MP (GMP)**](https://gmplib.org/) The project code relies on the  library for arbitrary precision arithmetic. Ensure that GMP is installed in your development environment.
* [**OpenSSL**](https://www.openssl.org/) for the hash function used.

## Building 

To build the project using **CMake**, all you need to do, assuming you have **CMake** installed and you're running in a linux machine, is run a similar routine to the the one below:

For a Debug build:
```bash
mkdir build/ && cd build/
cmake -B./ -S../ -DCMAKE_BUILD_TYPE=Debug
make
```
For a Release build:
```bash
mkdir build/ && cd build/
cmake -B./ -S../ -DCMAKE_BUILD_TYPE=Release
make
```
## Running the tests

Compile and execute the binary and you will be prompted for the number of random tests you want to perform.

## Authors

* **Cláudio Barros** - 190097591 - [@claudiobarros](https://github.com/claudiobarros) 