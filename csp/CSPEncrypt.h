#pragma once

#include <iostream>
#define KEY_LEN 16
class CSPEncrypt
{
public:
	CSPEncrypt();
	~CSPEncrypt();
    // ASE
    char*   AesEncrypt(char* in, size_t inLen);
    BYTE*   AesDecrypt(char* in, size_t inLen);
    BYTE*   RsaEncrypt();
    BYTE*   RsaDecrypt();
    char*   base64Encode(char* in, size_t inLen);
    char*   base64Decode(char* in, size_t inLen);
    std::string RandString(int len);

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
    PVOID      m_pOut = NULL;
    HCRYPTKEY  m_hAesKey;
    std::string m_cRandBuf;

// Singleton
private:
    static CSPEncrypt* instance;
public:
    static CSPEncrypt* getInstance();
};
