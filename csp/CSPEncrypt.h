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
    LPVOID   Base64Encode(LPVOID in, DWORD inLen, DWORD flags);
    DWORD   Base64Decode();

private:
	HCRYPTPROV m_hProv;
};
