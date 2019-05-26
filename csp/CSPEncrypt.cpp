#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "CSPEncrypt.h"
#include <winnt.h>
#include <stdlib.h> //rand srand
#include <stdio.h>
#include <time.h>
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
std::string CSPEncrypt::RandString(int len)
{
    std::string buffer;
    char a[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int n = sizeof(a);

    srand((unsigned int)time(NULL)); //随机种子
    for (int i = 0; i < len; i++) {
        buffer += a[rand()%n];
    }
    return buffer;
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
VOID CSPEncrypt::SafeFree()
{
    if (NULL != m_pOut) {
        free(m_pOut);
        m_pOut = NULL;
    }    
}
//////////////////////////////////////////////////////////////////////////
//
DWORD CSPEncrypt::GenerateAesKey(const char* keyword)
{
    DWORD       dwStatus = 0;
    if (NULL == keyword)
        return ERROR_INVALID_PARAMETER;

    CreateHash(keyword);
    if (!CryptDeriveKey(m_hAesProv, CALG_AES_128, m_hHash, 0, &m_hAesKey)) {
        dwStatus = GetLastError();

        printf("CryptDeriveKey failed: %x\n", dwStatus);
        CryptReleaseContext(m_hAesProv, 0);
    }

    return dwStatus;
}
//////////////////////////////////////////////////////////////////////////
// 
BOOL CSPEncrypt::InitAesEncrypt()
{
    DWORD       dwStatus = 0;
    WCHAR info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    if (!CryptAcquireContext(&m_hAesProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %x\n", dwStatus);
        CryptReleaseContext(m_hAesProv, 0);
        return FALSE;
    }


    m_cRandBuf = RandString(KEY_LEN);
    GenerateAesKey(m_cRandBuf.c_str());
    return FALSE;
}
//////////////////////////////////////////////////////////////////////////
//
BOOL CSPEncrypt::InitCSPEncrypt()
{
    return InitAesEncrypt();

}

//////////////////////////////////////////////////////////////////////////
//
CSPEncrypt::CSPEncrypt()
{
	DWORD dwStatus = 0;
	m_hAesProv     = NULL;
    m_pOut      = NULL;
    InitCSPEncrypt();

 
}


//////////////////////////////////////////////////////////////////////////
//
CSPEncrypt::~CSPEncrypt()
{
    SafeFree();
    if (NULL != m_hAesProv && FALSE == CryptReleaseContext(m_hAesProv, 0))
        OutputDebugString(TEXT("Construction Error!\r\n"));
}

//////////////////////////////////////////////////////////////////////////
//
DWORD CSPEncrypt::CreateHash(const char* keyword)
{
    DWORD dwStatus=0;
    if (NULL == keyword)
        return ERROR_INVALID_PARAMETER;

    if (!CryptCreateHash(m_hAesProv, CALG_SHA_256, 0, 0, &m_hHash)) {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %x\n", dwStatus);
        CryptReleaseContext(m_hAesProv, 0);
    }
    //對密鑰進行HASH計算
    if (!CryptHashData(m_hHash, (BYTE*)keyword, (DWORD)strlen("keyword"), 0))
    {
        dwStatus = GetLastError();
        printf("CryptHashData failed: %x\n", dwStatus);
        CryptReleaseContext(m_hAesProv, 0);
    }

    return dwStatus;
}
//////////////////////////////////////////////////////////////////////////
//
char* CSPEncrypt::AesEncrypt( char* in, size_t inLen)
{
    DWORD       dwDataLen= (DWORD)(inLen+1);
    BOOL        isFinal = FALSE;
    DWORD       dwBufLen = 1024;
    DWORD       dwStatus = 0;
    char    pData[1024];

    if (NULL == in)
        return NULL;

    strcpy_s(pData,in);

    if (!CryptEncrypt(m_hAesKey, NULL, TRUE, 0, (BYTE*)pData, &dwDataLen, dwBufLen))
    {
        printf("[-] CryptEncrypt failed\n");
    }
    //printf((char*)pData);
    //GenerateAesKey(m_cRandBuf.c_str());
    if (!CryptDecrypt(m_hAesKey, NULL, TRUE, 0, (BYTE*)pData, &dwDataLen)) {
        printf("[-] CryptEncrypt failed\n");
    }
    printf((char*)pData);
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPEncrypt::AesDecrypt(char* in, size_t inLen)
{
    char    pData[1024];
    DWORD       dwDataLen = (DWORD)(inLen + 1);

    if (NULL == in)
        return NULL;

    if (!CryptDecrypt(m_hAesKey, NULL, TRUE, 0, (BYTE*)pData, &dwDataLen)) {
        printf("[-] CryptEncrypt failed\n");
    }
    printf((char*)pData);
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
char*  CSPEncrypt::base64Encode(char* in, size_t inLen )
{
    DWORD   outLen=0;

    if (NULL == in)
        return NULL;

    // calculate space for string
    if (CryptBinaryToStringA((BYTE*)in, (DWORD)inLen, \
            CRYPT_STRING_BASE64 , NULL, &outLen)) 
    {
        m_pOut = (char*)SafeMalloc(outLen);
        // convert it
        if (m_pOut != NULL)
        {
            CryptBinaryToStringA((BYTE*)in, (DWORD)inLen, \
                CRYPT_STRING_BASE64 , (char*)m_pOut, &outLen);
        }
    }

    return (char*)m_pOut;
}

//////////////////////////////////////////////////////////////////////////
// Base64Decode
char*  CSPEncrypt::base64Decode(char* in, size_t inLen)
{
    DWORD   outLen=0;

    if (NULL == in)
        return NULL;

    if (CryptStringToBinaryA((LPCSTR)in, (DWORD)inLen, \
            CRYPT_STRING_BASE64 , NULL, &outLen, NULL, NULL))
    {
        m_pOut = (LPWSTR)SafeMalloc(outLen*sizeof(TCHAR));
        outLen *= sizeof(TCHAR);
        if (m_pOut != NULL)
        {
            // decode base64
            CryptStringToBinaryA((LPCSTR)in, (DWORD)inLen, \
                CRYPT_STRING_BASE64, (BYTE*)m_pOut, &outLen, NULL, NULL);
        }
    }
    return (char*)m_pOut;
}


// EOF
//////////////////////////////////////////////////////////////////////////