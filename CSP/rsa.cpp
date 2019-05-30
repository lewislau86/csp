#include "rsa.h"

//////////////////////////////////////////////////////////////////////////
//
void bin2hex(void *in, int len) {
    DWORD  outlen = 0;
    int    ofs = 0;
    LPTSTR out;

    if (ofs == 0) printf("\n");

    ofs += len;

    if (CryptBinaryToString(
        (BYTE*)in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
        NULL, &outlen))
    {
        out = (LPTSTR)malloc(outlen);
        if (out != NULL)
        {
            if (CryptBinaryToString(
                (BYTE*)in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
                out, &outlen))
            {
                printf("%s", out);
            }
            free(out);
        }
    }
    putchar('\n');
}

//////////////////////////////////////////////////////////////////////////
// used to convert digital signature from big-endian to little-endian
void byte_swap(void *buf, int len) {
    int     i;
    uint8_t t, *p = (uint8_t*)buf;

    for (i = 0; i < len / 2; i++) {
        t = p[i];
        p[i] = p[len - 1 - i];
        p[len - 1 - i] = t;
    }
}


//////////////////////////////////////////////////////////////////////////
// open CSP and return pointer to RSA object
RSA_CTX* RSA_open(void)
{
    RSA_CTX      *ctx = NULL;
    HCRYPTPROV prov = 0;

    if (CryptAcquireContext(&prov,
        NULL, NULL, CRYPTO_PROVIDER,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        ctx = (RSA_CTX*)malloc(sizeof(RSA_CTX));
        if (ctx != NULL) {
            ctx->prov = prov;
        }
    }
    return ctx;
}


//////////////////////////////////////////////////////////////////////////
// close CSP and release memory for RSA_CTX object
void RSA_close(RSA_CTX *ctx) {
    if (ctx->hash != 0) {
        CryptDestroyHash(ctx->hash);
        ctx->hash = 0;
    }

    // release private key
    if (ctx->privkey != 0) {
        CryptDestroyKey(ctx->privkey);
        ctx->privkey = 0;
    }

    // release public key
    if (ctx->pubkey != 0) {
        CryptDestroyKey(ctx->pubkey);
        ctx->pubkey = 0;
    }

    // release csp
    if (ctx->prov != 0) {
        CryptReleaseContext(ctx->prov, 0);
        ctx->prov = 0;
    }

    // release object
    free(ctx);
}

//////////////////////////////////////////////////////////////////////////
// generate new key pair of keyLen-bits
int RSA_genkey(RSA_CTX* ctx, int keyLen) {
    int ok = 0;
    if (ctx == NULL) return 0;

    // 1. release public if already allocated
    if (ctx->pubkey != 0) {
        CryptDestroyKey(ctx->pubkey);
        ctx->pubkey = 0;
    }

    // 2. release private if already allocated
    if (ctx->privkey != 0) {
        CryptDestroyKey(ctx->privkey);
        ctx->privkey = 0;
    }

    // 3. generate key pair for digital signatures
    ok = CryptGenKey(ctx->prov, AT_SIGNATURE,
        (keyLen << 16) | CRYPT_EXPORTABLE,
        &ctx->privkey);
    return ok;
}

//////////////////////////////////////////////////////////////////////////
// convert string to binary
void* Base642Bin(
    const char *in,
    int        inLen,
    int        flags,
    PDWORD     outLen)
{
    void* out = NULL;

    // calculate how much space required
    if (CryptStringToBinary(in, inLen,
        flags, NULL, (PDWORD)outLen, NULL, NULL))
    {
        out = malloc(*outLen);

        if (out != NULL) {
            // decode base64    
            CryptStringToBinary(in, inLen,
                flags, (BYTE*)out, (PDWORD)outLen, NULL, NULL);
        }
    }
    return out;
}

//////////////////////////////////////////////////////////////////////////
// convert binary to string
const char* Bin2Base64(LPVOID in, DWORD inLen, DWORD flags)
{
    DWORD  outLen;
    LPVOID out = NULL;

    // calculate space for string
    if (CryptBinaryToString((BYTE*)in, inLen,
        flags, NULL, &outLen))
    {
        out = malloc(outLen);

        // convert it
        if (out != NULL) {
            CryptBinaryToString((BYTE*)in, inLen,
                flags, (LPSTR)out, &outLen);
        }
    }
    return (char*)out;
}


//////////////////////////////////////////////////////////////////////////
// write binary to file encoded in PEM format
// ifile   : name of file to write PEM encoded key
// pemType : type of key being saved
// RSA_CTX     : RSA_CTX object with public and private keys
int PEM_write_file(int pemType, const char* ofile, \
                   void* data, int dataLen)
{
    const char *s = NULL, *e = NULL, *b64 = NULL;
    FILE       *out;
    int        ok = 0;

    if (pemType == RSA_PRIVATE_KEY) {
        s = "-----BEGIN PRIVATE KEY-----\n";
        e = "-----END PRIVATE KEY-----\n";
    }
    else if (pemType == RSA_PUBLIC_KEY) {
        s = "-----BEGIN PUBLIC KEY-----\n";
        e = "-----END PUBLIC KEY-----\n";
    }
    else if (pemType == RSA_SIGNATURE) {
        s = "-----BEGIN RSA SIGNATURE-----\n";
        e = "-----END RSA SIGNATURE-----\n";
    }
    // crypto API uses little endian convention.
    // we need to swap bytes for signatures
    // since there's no standard storage format
    if (pemType == RSA_SIGNATURE) {
        byte_swap(data, dataLen);
    }

    b64 = Bin2Base64(data, dataLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR);

    if (b64 != NULL) {
        fopen_s(&out ,ofile, "wb");

        if (out != NULL) {
            fwrite(s, strlen(s), 1, out);
            fwrite(b64, strlen(b64), 1, out);
            fwrite(e, strlen(e), 1, out);
            fclose(out);
            ok = 1;
        }
    }
    return ok;
}


//////////////////////////////////////////////////////////////////////////
// read public or private key in PEM format
// ifile   : name of file to write PEM encoded key
// pemType : type of key being saved
// RSA_CTX : RSA_CTX object with public and private keys
void* PEM_read_file( int pemType, \
        const char* ifile, PDWORD binLen)
{
    FILE        *in;
    struct stat st;
    char        *pem = NULL, *bin = NULL;

    stat(ifile, &st);

    if (st.st_size == 0) {
        return NULL;
    }

    // open PEM file
    //in = fopen(ifile, "rb");
    fopen_s(&in, ifile, "rb");
    if (in != NULL) {
        // allocate memory for data
        pem = (char *)malloc(st.st_size + 1);
        if (pem != NULL) {
            // read data
            fread(pem, 1, st.st_size, in);

            bin = (char*)Base642Bin(pem, strlen(pem),
                CRYPT_STRING_ANY, binLen);

            if (bin != NULL) {
                // crypto API uses little endian convention
                // swap bytes for signatures
                // since there's no standard storage format  
                if (pemType == RSA_SIGNATURE) {
                    byte_swap(bin, *binLen);
                }
            }
            free(pem);
        }
        fclose(in);
    }
    return bin;
}


//////////////////////////////////////////////////////////////////////////
// read public or private key from PEM format
// ifile   : name of file to read PEM encoded key from
// pemType : type of key being read
// RSA_CTX : RSA_CTX object to hold keys
int RSA_read_key(RSA_CTX* ctx, const char* ifile, int pemType)
{
    int                         ok = 0;
    LPVOID                    derData, keyData;
    PCRYPT_PRIVATE_KEY_INFO   pki = 0;
    DWORD                     pkiLen, derLen, keyLen;
    //CRYPT_DIGEST_BLOB         keyBlob;
    //CRYPT_PKCS8_IMPORT_PARAMS param;

    // decode base64 string
    derData = PEM_read_file(pemType, ifile, &derLen);

    if (derData != NULL) {
        // decode DER
        // is it a public key?
        if (pemType == RSA_PUBLIC_KEY) {
            // 1. convert DER to RSA public key info
            if (CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO, (BYTE*)derData, derLen,
                CRYPT_DECODE_ALLOC_FLAG, NULL,
                &keyData, &keyLen))
            {
                // 2. import public key blob
                ok = CryptImportPublicKeyInfo(ctx->prov,
                    X509_ASN_ENCODING,
                    (PCERT_PUBLIC_KEY_INFO)keyData, &ctx->pubkey);

                // 3. release allocated memory
                LocalFree(keyData);
            }
        }
        else {
            // 1. convert PKCS8 data to private key info
            if (CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                PKCS_PRIVATE_KEY_INFO,
                (BYTE*)derData, derLen,
                CRYPT_DECODE_ALLOC_FLAG,
                NULL, &pki, &pkiLen))
            {
                // 2. convert private key info to RSA private key blob
                if (CryptDecodeObjectEx(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    PKCS_RSA_PRIVATE_KEY,
                    pki->PrivateKey.pbData,
                    pki->PrivateKey.cbData,
                    CRYPT_DECODE_ALLOC_FLAG,
                    NULL, &keyData, &keyLen))
                {
                    // 3. import private key blob
                    ok = CryptImportKey(
                        ctx->prov,
                        (BYTE*)keyData, keyLen, 0,
                        CRYPT_EXPORTABLE,
                        &ctx->privkey);

                    LocalFree(keyData);
                }
                LocalFree(pki);
            }
        }
        free(derData);
    }
    return ok;
}


//////////////////////////////////////////////////////////////////////////
// save public or private key to PEM format
// ofile   : name of file to write PEM encoded key
// pemType : type of key being saved
// RSA_CTX : RSA_CTX object with public and private keys
int RSA_write_key(RSA_CTX* ctx, const char* ofile, int pemType)
{
    int      ok = 0;
    DWORD  pkiLen, derLen;
    LPVOID pki, derData;

    // public key?
    if (pemType == RSA_PUBLIC_KEY) {
        // 1. get size of public key info
        if (CryptExportPublicKeyInfo(ctx->prov,
            AT_SIGNATURE,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            NULL, &pkiLen))
        {
            // 2. allocate memory
            pki = malloc(pkiLen);

            // 3. export public key info
            if (CryptExportPublicKeyInfo(ctx->prov,
                AT_SIGNATURE,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
               (PCERT_PUBLIC_KEY_INFO) pki, &pkiLen))
            {
                // 4. get size of DER encoding
                if (CryptEncodeObjectEx(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    X509_PUBLIC_KEY_INFO, pki, 0,
                    NULL, NULL, &derLen))
                {
                    derData = malloc(derLen);
                    if (derData) {
                        // 5. convert to DER format
                        ok = CryptEncodeObjectEx(
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            X509_PUBLIC_KEY_INFO, pki, 0,
                            NULL, derData, &derLen);

                        // 6. write to PEM file
                        if (ok) {
                            PEM_write_file(RSA_PUBLIC_KEY,
                                ofile, derData, derLen);
                        }
                    }
                    free(derData);
                }
            }
        }
    }
    else {

        // 1. calculate size of PKCS#8 structure
        if (CryptExportPKCS8(
            ctx->prov, AT_SIGNATURE, (LPSTR)szOID_RSA_RSA,
            0, NULL, NULL, &pkiLen))
        {
            pki = malloc(pkiLen);

            if (pki != NULL) {
                // 2. export PKCS#8 structure to memory
                ok = CryptExportPKCS8(
                    ctx->prov, AT_SIGNATURE, (LPSTR)szOID_RSA_RSA,
                    0, NULL, (BYTE*)pki, &pkiLen);
                if (ok) {
                    // 3. write memory to file in PEM format
                    PEM_write_file(RSA_PRIVATE_KEY,
                        ofile, pki, pkiLen);
                }
                free(pki);
            }
        }
    }
    return ok;
}


//////////////////////////////////////////////////////////////////////////
//  calculate sha256 hash of file
// ifile : contains data to generate hash for
// RSA_CTX   : RSA_CTX object with HCRYPTHASH object
int SHA256_hash(RSA_CTX* ctx, const char* ifile)
{
    FILE *fd;
    BYTE buf[BUFSIZ];
    int  len, ok = 0;

    // 1. destroy hash object if already created
    if (ctx->hash != 0) {
        CryptDestroyHash(ctx->hash);
        ctx->hash = 0;
    }

    // 2. try open the file for reading
    //fd = fopen(ifile, "rb");
    fopen_s( &fd, ifile, "rb");
    if (fd == NULL) return 0;

    // 3. create hash object
    if (CryptCreateHash(ctx->prov,
        CRYPTO_HASH, 0, 0, &ctx->hash))
    {
        // 4. hash file contents
        for (;;) {
            len = fread(buf, 1, BUFSIZ, fd);
            if (len == 0) break;

            ok = CryptHashData(ctx->hash, buf, len, 0);
            if (!ok) break;
        }
    }
    fclose(fd);

    return ok;
}

//////////////////////////////////////////////////////////////////////////
// create a signature for file using RSA private key
// sfile   : output file of RSA signature
// ifile   : input file of data to generate signature for
// RSA_CTX : RSA_CTX object with private key
int RSA_sign_file(RSA_CTX* ctx, const char* ifile, const char* sfile)
{
    int      ok = 0;
    DWORD  sigLen = 0;
    LPVOID sig;
    FILE   *out;

    // 1. try open file for signature
    //out = fopen(sfile, "wb");  
    fopen_s(&out, sfile, "wb");
    if (out != NULL) {
        // 2. calculate sha256 hash for file
        if (SHA256_hash(ctx, ifile)) {
            // 3. acquire length of signature
            if (CryptSignHash(ctx->hash,
                AT_KEYEXCHANGE, NULL, 0,
                NULL, &sigLen)) {
                sig = malloc(sigLen);
                if (sig != NULL) {
                    // 4. obtain signature
                    if (CryptSignHash(ctx->hash,
                        AT_KEYEXCHANGE, NULL, 0,
                        (BYTE*)sig, &sigLen))
                    {
                        // 5. convert signature to big-endian format
                        byte_swap(sig, sigLen);
                        ok = 1;
                        // 6. save signature to file
                        fwrite(sig, 1, sigLen, out);
                    }
                    free(sig);
                }
            }
        }
        fclose(out);
    }
    return ok;
}

//////////////////////////////////////////////////////////////////////////
// verify a signature using public key
// sfile   : file with signature
// ifile   : file with data to verify signature for
// RSA_CTX : RSA_CTX object with public key
int RSA_verify_file(
    RSA_CTX*    ctx,
    const char* ifile,
    const char* sfile)
{
    int    ok = 0;
    DWORD  sigLen;
    BYTE   sig[MAX_RSA_BYTES];
    FILE   *in;

    // 1. read signature from file
    //in = fopen(sfile, "rb");
    fopen_s(&in, sfile, "rb");
    if (in == NULL) return 0;
    sigLen = fread(sig, 1, MAX_RSA_BYTES, in);
    fclose(in);

    // 2. convert signature from big-endian to little-endian format
    byte_swap(sig, sigLen);

    // 3. calculate sha256 hash of file
    if (SHA256_hash(ctx, ifile)) {
        // 4. verify signature using public key
        ok = CryptVerifySignature(ctx->hash, sig,
            sigLen, ctx->pubkey, NULL, 0);
    }
    return ok;
}

//////////////////////////////////////////////////////////////////////////
// Public Key Encrypt 
int RSA_encrypt_file(RSA_CTX* ctx, const char* ifile, const char* sfile)
{
    int     ok = 0;
    DWORD   dwBufLen = 0;
    FILE    *in, *out;
    void    *fileBuf = NULL;
    struct  stat st;
    BOOL    bStatus;


    // get file size
    stat(ifile, &st);
    if (st.st_size == 0) {
        return NULL;
    }

    // 1. try open file for signature 
    fopen_s(&in, ifile, "wb");
    fopen_s(&out, sfile, "wb");
        
    // read file
    do 
    {
        if (NULL==out || NULL==in)
            break;
        
        fileBuf = malloc(st.st_size + 1);
        if (NULL == fileBuf)
            break;
     
        dwBufLen = fread(fileBuf, 1, st.st_size, in);
        bStatus = CryptEncrypt(ctx->pubkey, NULL, TRUE, \
            0, (BYTE*)fileBuf, &dwBufLen, (DWORD)st.st_size + 1);
        if (!bStatus)
        {
            printf("CryptEncrypt failed with error 0x%.8X\n", GetLastError());
            break;
        }
        
        dwBufLen = fwrite(fileBuf, 1, (size_t)dwBufLen, out);
    } while (0);


    if (NULL != fileBuf)
        free(fileBuf);
    fclose(out);
    fclose(in);
    return dwBufLen;
}


//////////////////////////////////////////////////////////////////////////
// Private Key Decrypt
int RSA_decrypt_file(RSA_CTX* ctx, const char* ifile, const char* sfile)
{
    int     ok = 0;
    DWORD   dwBufLen = 0;
    FILE    *in, *out;
    void    *fileBuf = NULL;
    struct  stat st;
    BOOL    bStatus;


    // get file size
    stat(ifile, &st);
    if (st.st_size == 0) {
        return NULL;
    }

    // 1. try open file for signature 
    fopen_s(&out, sfile, "wb");
    fopen_s(&in, ifile, "wb");
    // read file
    do
    {
        if (NULL == out)
            break;

        fileBuf = malloc(st.st_size + 1);
        if (NULL == fileBuf)
            break;

        dwBufLen = fread(fileBuf, 1, st.st_size, in);
        bStatus = CryptDecrypt(ctx->privkey, NULL, TRUE,\
                                0,(BYTE*)fileBuf, &dwBufLen);
        if (!bStatus)
        {
            printf("CryptDecrypt failed with error 0x%.8X\n", GetLastError());
            break;
        }

        dwBufLen = fwrite(fileBuf, 1, (size_t)dwBufLen, out);
    } while (0);


    if (NULL != fileBuf)
        free(fileBuf);
    fclose(out);
    fclose(in);
    return dwBufLen;
}


//////////////////////////////////////////////////////////////////////////
//
int RSA_encrypt(RSA_CTX* ctx, BYTE* inBuf, \
            UINT inBufLen, BYTE* outBuf, UINT &outBufLen)
{
    PVOID buffer = NULL;
    BOOL    bStatus;
    DWORD  bufLen = inBufLen * 2;

    do 
    {
        if (NULL == inBuf)
            break;

        buffer = malloc(bufLen);
        if (NULL == buffer)
            break;

        memcpy(buffer, inBuf, inBufLen);

        bStatus = CryptEncrypt(ctx->pubkey, NULL, TRUE, \
            0, (BYTE*)buffer, &bufLen, inBufLen);
        if (!bStatus)
        {
            printf("CryptEncrypt failed with error 0x%.8X\n", GetLastError());
            break;
        }
        
        outBuf = (BYTE*)malloc(bufLen);
        if (NULL != outBuf)
        {
            memcpy(outBuf, buffer, bufLen);
            outBufLen = bufLen;
        }
    } while (0);

    if (NULL != buffer)
        free(buffer);
    return bufLen;
}

//////////////////////////////////////////////////////////////////////////
//
int RSA_decrypt(RSA_CTX* ctx, BYTE* inBuf, \
            UINT inBufLen, BYTE* outBuf, UINT &outBufLen)
{
    PVOID buffer = NULL;
    BOOL    bStatus;
    DWORD  bufLen = inBufLen * 2;

    do
    {
        if (NULL == inBuf)
            break;

        buffer = malloc(bufLen);
        if (NULL == buffer)
            break;

        memcpy(buffer, inBuf, inBufLen);

        bStatus = CryptDecrypt(ctx->privkey, NULL, TRUE, \
                0, (BYTE*)buffer, &bufLen);
        if (!bStatus)
        {
            printf("CryptEncrypt failed with error 0x%.8X\n", GetLastError());
            break;
        }

        outBuf = (BYTE*)malloc(bufLen);
        if (NULL != outBuf)
        {
            memcpy(outBuf, buffer, bufLen);
            outBufLen = bufLen;
        }
    } while (0);

    if (NULL != buffer)
        free(buffer);
    return bufLen;
}
// EOF
//////////////////////////////////////////////////////////////////////////