#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "CSPEncrypt.h"
#include <winnt.h>
#include <stdlib.h> //rand srand
#include <stdio.h>
#include <time.h>
#include <shlwapi.h>
#include "rsa.h"

#pragma comment(lib, "shlwapi.lib")
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
    if (NULL != m_pOutBuffer) {
        free(m_pOutBuffer);
        m_pOutBuffer = NULL;
    }
    m_pOutBuffer = (PVOID)malloc(size);
    memset(m_pOutBuffer, 0, size);
    return m_pOutBuffer;
}

//////////////////////////////////////////////////////////////////////////
VOID CSPEncrypt::SafeFree()
{
    if (NULL != m_pOutBuffer) {
        free(m_pOutBuffer);
        m_pOutBuffer = NULL;
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
    char info[] = "Microsoft Enhanced RSA and AES Cryptographic Provider";
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
    m_pOutBuffer      = NULL;
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
// 这里有个坑缓冲区大小的dwBufferLen
// 一般来说AES算法密文大小和字符集大小差不多一直，但是不知道为啥这里会多一点点。
char* CSPEncrypt::AesEncrypt( char* in, size_t inLen)
{
    DWORD       dwDataLen= (DWORD)(inLen+1);
    BOOL        isFinal = FALSE;
    DWORD       dwBufLen = inLen*2;
    DWORD       dwStatus = 0;
    

    m_pOutBuffer = (char*)SafeMalloc(dwBufLen);

    strcpy_s((char*)m_pOutBuffer, dwDataLen,in);

    if (!CryptEncrypt(m_hAesKey, NULL, TRUE, 0, (BYTE*)m_pOutBuffer, &dwDataLen, dwBufLen))
    {
        printf("[-] CryptEncrypt failed\n");
        return NULL;
    }

    /*
    if (!CryptDecrypt(m_hAesKey, NULL, TRUE, 0, (BYTE*)m_pOut, &dwDataLen)) {
        printf("[-] CryptEncrypt failed\n");
    }
    printf((char*)m_pOut);
    */
    m_dwOutBufferSize = dwDataLen;
    return (char*)m_pOutBuffer;
}

//////////////////////////////////////////////////////////////////////////
//
char* CSPEncrypt::AesDecrypt(char* in, size_t inLen)
{
    DWORD       dwDataLen = (DWORD)(inLen);

    if (NULL == in)
        return NULL;

    if (!CryptDecrypt(m_hAesKey, NULL, TRUE, 0, (BYTE*)m_pOutBuffer, &dwDataLen)) {
        printf("[-] CryptEncrypt failed\n");
    }
    m_dwOutBufferSize = dwDataLen;
    return (char*)m_pOutBuffer;
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
        m_pOutBuffer = (char*)SafeMalloc(outLen);
        // convert it
        if (m_pOutBuffer != NULL)
        {
            CryptBinaryToStringA((BYTE*)in, (DWORD)inLen, \
                CRYPT_STRING_BASE64 , (char*)m_pOutBuffer, &outLen);
        }
    }

    m_dwOutBufferSize = outLen;
    return (char*)m_pOutBuffer;
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
        m_pOutBuffer = (LPWSTR)SafeMalloc(outLen*sizeof(TCHAR));
        outLen *= sizeof(TCHAR);
        if (m_pOutBuffer != NULL)
        {
            // decode base64
            CryptStringToBinaryA((LPCSTR)in, (DWORD)inLen, \
                CRYPT_STRING_BASE64, (BYTE*)m_pOutBuffer, &outLen, NULL, NULL);
        }
    }
    m_dwOutBufferSize = outLen;
    return (char*)m_pOutBuffer;
}


//////////////////////////////////////////////////////////////////////////
//
DWORD CSPEncrypt::GetBufferSize()
{
    return m_dwOutBufferSize;
}

//////////////////////////////////////////////////////////////////////////
//
PVOID CSPEncrypt::GetBufferPtr()
{
    return m_pOutBuffer;
}

//////////////////////////////////////////////////////////////////////////
//
void xstrerror(const char *fmt, ...)
{
    char    *error = NULL;
    va_list arglist;
    char    buffer[2048];
    DWORD   dwError = GetLastError();

    va_start(arglist, fmt);
    wvnsprintf(buffer, sizeof(buffer) - 1, fmt, arglist);
    va_end(arglist);

    if (FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&error, 0, NULL))
    {
        printf("  [ %s : %s\n", buffer, error);
        LocalFree(error);
    }
    else {
        printf("  [ %s : %ld\n", buffer, dwError);
    } 
}

//////////////////////////////////////////////////////////////////////////
// generate RSA key pair
int genkey( const char *pubkey,
    const char *privkey,
    int bits)
{
    int     ok = 1;
    RSA_CTX *rsa;

    rsa = RSA_open();

    if (rsa != NULL) {
        if (RSA_genkey(rsa, bits)) {
            printf("  [ Saving public key to %s...\n", pubkey);
            ok = RSA_write_key(rsa, pubkey, RSA_PUBLIC_KEY);
            printf("  [ Saving private key to %s...\n", privkey);
            ok &= RSA_write_key(rsa, privkey, RSA_PRIVATE_KEY);
        }
        else xstrerror("RSA_genkey()");
        RSA_close(rsa);
    }
    return ok;
}


//////////////////////////////////////////////////////////////////////////
// verify a signature using RSA public key stored in PEM format
int verifyfile(
    const char *pubkey,
    const char *file,
    const char *signature)
{
    int ok = 0;
    RSA_CTX* ctx = RSA_open();

    if (ctx != NULL) {
        printf("  [ Reading public key from %s...\n", pubkey);
        if (RSA_read_key(ctx, pubkey, RSA_PUBLIC_KEY)) {
            printf("  [ Reading signature for %s from %s...\n",
                file, signature);

            ok = RSA_verify_file(ctx, file, signature);
        }
        else xstrerror("RSA_read_key()");
        RSA_close(ctx);
    }
    return ok;
}


//////////////////////////////////////////////////////////////////////////
// sign a file using RSA private key stored in PEM format
 
int signfile(
    const char *privkey,
    const char *file,
    const char *signature)
{
    int ok = 0;
    RSA_CTX* rsa = RSA_open();

    if (rsa != NULL) {
        printf("\n  [ Reading private key from %s...", privkey);
        if (RSA_read_key(rsa, privkey, RSA_PRIVATE_KEY)) {
            printf("\n  [ Writing signature for %s to %s...",
                file, signature);

            ok = RSA_sign_file(rsa, file, signature);
        }
        else xstrerror("RSA_read_key()");
        RSA_close(rsa);
    }
    return ok;
}



// EOF
//////////////////////////////////////////////////////////////////////////