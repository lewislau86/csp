#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "CSPEncrypt.h"

#pragma comment(lib,"Crypt32.lib")

//////////////////////////////////////////////////////////////////////////
//
CSPEncrypt::CSPEncrypt()
{
	DWORD dwStatus = 0;
	m_hProv = NULL;
    WCHAR info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	if (!CryptAcquireContext(&m_hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) 
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %x\n", dwStatus);
		CryptReleaseContext(m_hProv, 0);
		system("pause");
	}
}

//////////////////////////////////////////////////////////////////////////
//
CSPEncrypt::~CSPEncrypt()
{
    if (NULL != m_hProv && FALSE == CryptReleaseContext(m_hProv, 0))
        OutputDebugString(TEXT("Construction Error!\r\n"));
}

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPEncrypt::AseEncrypt()
{
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPEncrypt::AesDecrypt()
{
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPEncrypt::RsaEncrypt()
{
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPEncrypt::RsaDecrypt()
{
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
//
LPWSTR CSPEncrypt::Base64Encode(BYTE* in, DWORD inLen)
{
    DWORD  outLen;
    LPWSTR out = NULL;

    // calculate space for string
    if (CryptBinaryToString(in, inLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, NULL, &outLen)) {
        out = (LPWSTR)malloc(outLen);

        // convert it
        if (out != NULL) {
            CryptBinaryToString(in, inLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, out, &outLen);
        }
    }
    return out;
}

//////////////////////////////////////////////////////////////////////////
//



// EOF
//////////////////////////////////////////////////////////////////////////