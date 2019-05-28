/**
  Copyright (C) 2017 Odzhan. All Rights Reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:
  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.
  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
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

int SHA256_hash(RSA_CTX*, const char*);
int PEM_write_file(int, const char*, void*, int);
void* PEM_read_file(int, const char*, PDWORD);
void* Base642Bin(const char *in, int inLen, int flags, PDWORD outLen);

