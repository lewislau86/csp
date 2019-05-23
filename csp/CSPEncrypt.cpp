#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include "CSPEncrypt.h"
CSPEncrypt::CSPEncrypt()
{
	DWORD dwStatus = 0;
	m_hProv = NULL;
    wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	if (!CryptAcquireContext(&m_hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) 
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %x\n", dwStatus);
		CryptReleaseContext(m_hProv, 0);
		system("pause");
	}
}

CSPEncrypt::~CSPEncrypt()
{
    if (NULL != m_hProv && FALSE == CryptReleaseContext(m_hProv, 0))
        OutputDebugString(TEXT("Construction Error!\r\n"));
}
