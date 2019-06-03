#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "CSPMisc.h"
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
CSPMisc* CSPMisc::instance = NULL;

CSPMisc* CSPMisc::getInstance()
{
    if (instance == NULL) {
        instance = new CSPMisc();
    }
    return instance;
}
//////////////////////////////////////////////////////////////////////////
//
std::string CSPMisc::RandString(int len)
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
PVOID CSPMisc::SafeMalloc(size_t size)
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
VOID CSPMisc::SafeFree()
{
    if (NULL != m_pOutBuffer) {
        free(m_pOutBuffer);
        m_pOutBuffer = NULL;
    }    
}
//////////////////////////////////////////////////////////////////////////
//
DWORD CSPMisc::GenerateAesKey(const char* keyword)
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
BOOL CSPMisc::InitAesEncrypt()
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
BOOL CSPMisc::InitCSPEncrypt()
{
    return InitAesEncrypt();

}

//////////////////////////////////////////////////////////////////////////
//
CSPMisc::CSPMisc()
{
	DWORD dwStatus = 0;
	m_hAesProv     = NULL;
    m_pOutBuffer      = NULL;
    InitCSPEncrypt();

 
}


//////////////////////////////////////////////////////////////////////////
//
CSPMisc::~CSPMisc()
{
    SafeFree();
    if (NULL != m_hAesProv && FALSE == CryptReleaseContext(m_hAesProv, 0))
        OutputDebugString(TEXT("Construction Error!\r\n"));
}

//////////////////////////////////////////////////////////////////////////
//
DWORD CSPMisc::CreateHash(const char* keyword)
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
char* CSPMisc::AesEncrypt( char* in, size_t inLen)
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
char* CSPMisc::AesDecrypt(char* in, size_t inLen)
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
//  Base64 Encode 
char*  CSPMisc::base64Encode(char* in, size_t inLen )
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
char*  CSPMisc::base64Decode(char* in, size_t inLen)
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
DWORD CSPMisc::GetBufferSize()
{
    return m_dwOutBufferSize;
}

//////////////////////////////////////////////////////////////////////////
//
PVOID CSPMisc::GetBufferPtr()
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

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPRsa::RsaEncrypt()
{

    return NULL;
}
//////////////////////////////////////////////////////////////////////////
//
BOOL CSPRsa::RsaInitKey(const char* strPath)
{

    BOOL    bRet = FALSE;
    do 
    {
        if (NULL==strPath)
        {
        }
        else
        {
            RsaLoadKey(strPath);
        } 

    } while (0);
    
    return bRet;
}

//////////////////////////////////////////////////////////////////////////
//
BOOL CSPRsa::RsaLoadKey(const char* strPath)
{
    char    path[MAX_PATH] = { 0 };
    int     inBufLen = 0;
    do 
    {
        inBufLen = strlen(strPath);
        if (inBufLen == 0 || inBufLen > MAX_PATH)
            break;
    } while (0);
    return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//
BYTE* CSPRsa::RsaDecrypt()
{
    return NULL;
}


// EOF
//////////////////////////////////////////////////////////////////////////