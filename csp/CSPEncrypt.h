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
    static  LPWSTR   Base64Encode(BYTE* in, DWORD inLen);
    static  DWORD   Base64Decode();

private:
	HCRYPTPROV m_hProv;
};
