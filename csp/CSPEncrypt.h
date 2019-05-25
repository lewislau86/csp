#pragma once

class CSPEncrypt
{
public:
	CSPEncrypt();
	~CSPEncrypt();
    // ASE
    BYTE*   AseEncrypt();
    BYTE*   AesDecrypt();
    
    BYTE*   RsaEncrypt();
    BYTE*   RsaDecrypt();
    LPWSTR  Base64Encode(BYTE* in, DWORD inLen);
    LPWSTR  Base64Decode(LPVOID in, DWORD inLen);

private:
    PVOID   SafeMalloc(size_t size);
    DWORD   CreateHash();

private:
	HCRYPTPROV m_hProv;
    HCRYPTHASH m_hHash;
    PVOID      m_pOut = NULL;

// Singleton
private:
    static CSPEncrypt* instance;
public:
    static CSPEncrypt* getInstance();
};
