#pragma once

#include <iostream>
#define KEY_LEN 16
#define AES_BLOCK 1024    
class CSPMisc
{
public:
	CSPMisc();
	~CSPMisc();
    // AES
    char*   AesEncrypt(char* in, size_t inLen);
    char*   AesDecrypt(char* in, size_t inLen);
    char*   base64Encode(char* in, size_t inLen);
    char*   base64Decode(char* in, size_t inLen);
    std::string RandString(int len);
    DWORD   GetBufferSize();
    PVOID   GetBufferPtr();

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
    static CSPMisc* instance;
public:
    static CSPMisc* getInstance();
};


class CSPRsa
{
public:
    BOOL    RsaInitKey(const char* strPath);
    BOOL    RsaLoadKey(const char* strPath);
    BOOL    RsaGenerateKey();
    BYTE*   RsaEncrypt();
    BYTE*   RsaDecrypt();
    BOOL    RsaSignFile();
    BOOL    RsaVerifyFile();
};
