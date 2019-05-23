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

    out=CSPEncrypt::Base64Encode((BYTE*)data, sizeof(data));
    wprintf(out);
}