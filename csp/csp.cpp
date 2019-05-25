// csp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "CSPEncrypt.h"
int main()
{
    LPWSTR out;
    static char data[] = "lewislau86";

    out=CSPEncrypt::getInstance()->Base64Encode((BYTE*)data, strlen(data));
    wprintf(out);
    out =CSPEncrypt::getInstance()->Base64Decode((BYTE*)out, wcslen(out));
    wprintf(out);

    CSPEncrypt::getInstance()->AseEncrypt();
    getchar();
}