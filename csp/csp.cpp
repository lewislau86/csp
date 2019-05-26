// csp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "CSPEncrypt.h"
int main()
{
    char* out;
    char buffer[1024] = { 0 };
    static char data[] = "lewislau86";


    printf("\nBase65 Encode\r\n");
    out=CSPEncrypt::getInstance()->base64Encode(data, strlen(data));
 
    strcpy_s(buffer, out);
    printf(buffer);

    printf("\nBase65 Decode\r\n");
    out =CSPEncrypt::getInstance()->base64Decode(buffer, strlen(out));
    strcpy_s(buffer, out);
    printf(buffer);

    printf("\nAse Encrypt\r\n");
    out = CSPEncrypt::getInstance()->AesEncrypt(buffer,strlen(buffer));

    CSPEncrypt::getInstance()->AesEncrypt(out, strlen(buffer));
    getchar();


}