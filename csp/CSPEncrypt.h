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
    static  LPWSTR  Base64Encode(BYTE* in, DWORD inLen);
    static  LPWSTR  Base64Decode(BYTE* in, DWORD inLen);

private:
	HCRYPTPROV m_hProv;
};
