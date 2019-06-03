#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <windows.h>
#include <wincrypt.h>

#define _CRT_SECURE_NO_WARNINGS

#define CRYPTO_PROVIDER PROV_RSA_FULL
#define CRYPTO_HASH     CALG_SHA

#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "crypt32.lib")


#define MAX_RSA_KEY   8192     // in bits
#define MAX_RSA_BYTES MAX_RSA_KEY/8

#define RSA_PUBLIC_KEY  1
#define RSA_PRIVATE_KEY 2
#define RSA_SIGNATURE   3

typedef struct _RSA_CTX_t {
    HCRYPTPROV prov;
    HCRYPTKEY  privkey, pubkey;
    HCRYPTHASH hash;
    DWORD      error;
} RSA_CTX, PRSA_CTX;

RSA_CTX* RSA_open(void);
void RSA_close(RSA_CTX*);

int RSA_genkey(RSA_CTX*, int);

int RSA_read_key(RSA_CTX*, const char*, int);
int RSA_write_key(RSA_CTX*, const char*, int);

int RSA_verify_file(RSA_CTX*, const char*, const char*);
int RSA_sign_file(RSA_CTX*, const char*, const char*);

int RSA_encrypt_file(RSA_CTX* ctx, const char* ifile, const char* sfile);
int RSA_decrypt_file(RSA_CTX* ctx, const char* ifile, const char* sfile);

int RSA_encrypt(RSA_CTX* ctx, BYTE* inBuf,  \
            UINT inBufLen, BYTE* outBuf, UINT &outBufLen);
int RSA_decrypt(RSA_CTX* ctx, BYTE* inBuf,  \
            UINT inBufLen, BYTE* outBuf, UINT &outBufLen);

int SHA256_hash(RSA_CTX*, const char*);
int PEM_write_file(int, const char*, void*, int);
void* PEM_read_file(int, const char*, PDWORD);
void* Base642Bin(const char *in, int inLen, int flags, PDWORD outLen);

