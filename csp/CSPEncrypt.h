#pragma once

#include <iostream>
#define KEY_LEN 16
#define AES_BLOCK 1024    
class CSPEncrypt
{
public:
	CSPEncrypt();
	~CSPEncrypt();
    // ASE
    char*   AesEncrypt(char* in, size_t inLen);
    char*   AesDecrypt(char* in, size_t inLen);
    BYTE*   RsaEncrypt();
    BYTE*   RsaDecrypt();
    char*   base64Encode(char* in, size_t inLen);
    char*   base64Decode(char* in, size_t inLen);
    std::string RandString(int len);
    DWORD   GetBufferSize();

private:
    PVOID   SafeMalloc(size_t size);
    DWORD   CreateHash(const char* keyword);
    VOID    SafeFree();
    DWORD   GenerateAesKey(const char* keyword);
    BOOL    InitCSPEncrypt();
    BOOL    InitAesEncrypt();

private:
	HCRYPTPROV m_hAesProv;
    HCRYPTHASH m_hHash;
    PVOID      m_pOutBuffer = NULL;
    DWORD      m_dwOutBufferSize = 0;
    HCRYPTKEY  m_hAesKey;
    std::string m_cRandBuf;

// Singleton
private:
    static CSPEncrypt* instance;
public:
    static CSPEncrypt* getInstance();
};
