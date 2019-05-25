#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "CSPEncrypt.h"

#pragma comment(lib,"Crypt32.lib")


//////////////////////////////////////////////////////////////////////////
//
CSPEncrypt* CSPEncrypt::instance = NULL;

CSPEncrypt* CSPEncrypt::getInstance()
{
    if (instance == NULL) {
        instance = new CSPEncrypt();
    }
    return instance;
}
//////////////////////////////////////////////////////////////////////////
//
CSPEncrypt::CSPEncrypt()
{
	DWORD dwStatus = 0;
	m_hProv     = NULL;
    m_pOut      = NULL;
    WCHAR info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	if (!CryptAcquireContext(&m_hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) 
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %x\n", dwStatus);
		CryptReleaseContext(m_hProv, 0);
		system("pause");
	}
    CreateHash();
    
}

//////////////////////////////////////////////////////////////////////////
//
PVOID CSPEncrypt::SafeMalloc(size_t size)
{
    if (NULL != m_pOut) {
        free(m_pOut);
        m_pOut = NULL;
    }
    m_pOut = (PVOID)malloc(size);
    memset(m_pOut, 0, size);
    return m_pOut;
}


//////////////////////////////////////////////////////////////////////////
//
CSPEncrypt::~CSPEncrypt()
{
    if (NULL != m_pOut)
        free(m_pOut);

    if (NULL != m_hProv && FALSE == CryptReleaseContext(m_hProv, 0))
        OutputDebugString(TEXT("Construction Error!\r\n"));
}

//////////////////////////////////////////////////////////////////////////
//
DWORD CSPEncrypt::CreateHash()
{
    DWORD dwStatus=0;

    if (!CryptCreateHash(m_hProv, CALG_SHA_256, 0, 0, &m_hHash)) {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %x\n", dwStatus);
        CryptReleaseContext(m_hProv, 0);
    }
    return dwStatus;
}
//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPEncrypt::AseEncrypt()
{
    HCRYPTKEY   hKey;
    DWORD       dwStatus=0;
    DWORD       dwOutLen=0;
    BOOL        isFinal = FALSE;
    BYTE *pData;
    pData = (BYTE*)SafeMalloc(256);
    memcpy(pData, "lewislau", sizeof("lewislau"));
    if (!CryptDeriveKey(m_hProv, CALG_AES_128, m_hHash, 0, &hKey)) {
        dwStatus = GetLastError();
        printf("CryptDeriveKey failed: %x\n", dwStatus);
        CryptReleaseContext(m_hProv, 0);
        return NULL;
    }
    if (!CryptEncrypt(hKey, NULL, TRUE, 0, pData, &dwOutLen, 256))
    {
        printf("[-] CryptEncrypt failed\n");
    }

    if (!CryptDecrypt(hKey, NULL, TRUE, 0, pData, &dwOutLen)) {
        printf("[-] CryptEncrypt failed\n");
    }
    printf((char*)pData);
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
    HCRYPTPROV  hProv = NULL;
    HCRYPTKEY   hRSAKey = NULL;
/*
    // Acquire context for RSA key
    fResult = CryptAcquireContext(&hProv,
        lpszContainerName,
        MS_DEF_PROV,
        PROV_RSA_FULL,
        dwFlags);

    if (!fResult) {
        if (GetLastError() == NTE_BAD_KEYSET) {
            // Create a key container if one does not exist.
            fResult = CryptAcquireContext(&hProv,
                lpszContainerName,
                MS_DEF_PROV,
                PROV_RSA_FULL,
                CRYPT_NEWKEYSET | dwFlags);

            if (!fResult) {
                MyPrintf(_T("CryptAcquireContext (2) failed with %X\n"), GetLastError());
                __leave;
            }
        }
        else {
            MyPrintf(_T("CryptAcquireContext (1) failed with %X\n"), GetLastError());
            __leave;
        }
    }

    // Get the RSA key handle
    fResult = CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hRSAKey);

    if (!fResult) {
        if (GetLastError() == NTE_NO_KEY) {
            // Create a key if one does not exist.
            fResult = CryptGenKey(hProv,
                AT_KEYEXCHANGE,
                CRYPT_EXPORTABLE,
                &hRSAKey);

            if (!fResult) {
                MyPrintf(_T("CryptGenKey failed with %X\n"), GetLastError());
                __leave;
            }
        }
        else {
            MyPrintf(_T("CryptGetUserKey failed with %X\n"), GetLastError());
            __leave;
        }
    }
*/
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPEncrypt::RsaDecrypt()
{
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
//  Base64 Encode 
LPWSTR  CSPEncrypt::Base64Encode(BYTE* in, DWORD inLen )
{
    DWORD   outLen=0;
    // save tmp
    BYTE*   bufInTmp = (BYTE*)malloc(inLen);
    if (NULL!= bufInTmp)
        memcpy(bufInTmp, in, inLen);
    // calculate space for string
    if (CryptBinaryToString(bufInTmp, inLen, \
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, NULL, &outLen)) 
    {
        m_pOut = (LPWSTR)SafeMalloc(outLen*sizeof(TCHAR));
        // convert it
        if (m_pOut != NULL)
        {
            CryptBinaryToString(in, inLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, (LPWSTR)m_pOut, &outLen);
        }
    }
    if (NULL != bufInTmp)
        free(bufInTmp);

    return (LPWSTR)m_pOut;
}

//////////////////////////////////////////////////////////////////////////
// Base64Decode
LPWSTR  CSPEncrypt::Base64Decode(LPVOID in, DWORD inLen)
{
    DWORD   outLen=0;
    // save tmp
    LPVOID   bufInTmp = (LPVOID)malloc(inLen*sizeof(TCHAR));
    if (NULL != bufInTmp)
    {
        memset(bufInTmp, 0, inLen * sizeof(TCHAR));
        memcpy(bufInTmp, in, inLen * sizeof(TCHAR));

    }

    if (CryptStringToBinary((LPCWSTR)bufInTmp, inLen, \
            CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL)) 
    {
        m_pOut = (LPWSTR)SafeMalloc(outLen*sizeof(TCHAR));
        if (m_pOut != NULL)
        {
            // decode base64
            CryptStringToBinary((LPCWSTR)bufInTmp, inLen, \
                CRYPT_STRING_BASE64 , (BYTE*)m_pOut, &outLen, NULL, NULL);
        }
    }
    if (NULL != bufInTmp)
        free(bufInTmp);
    return (LPWSTR)m_pOut;
}


// EOF
//////////////////////////////////////////////////////////////////////////