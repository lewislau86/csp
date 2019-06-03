// csp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "CSPMisc.h"
int main()
{
    char* out;
    size_t  len;
    char buffer[1024] = { 0 };
    static char data[] = "lewislau86";
    CSPMisc* cspPtr = CSPMisc::getInstance();

    printf("\nBase65 Encode\r\n");
    out= cspPtr->base64Encode(data, strlen(data));
 
    strcpy_s(buffer, out);
    printf(buffer);

    printf("\nBase65 Decode\r\n");
    out =cspPtr->base64Decode(buffer, strlen(out));
    strcpy_s(buffer, out);
    printf(buffer);

    printf("\nAse Encrypt\r\n");
    out = CSPMisc::getInstance()->AesEncrypt(buffer,strlen(buffer));
    len = cspPtr->GetBufferSize();
    memcpy(buffer, out, len);
    out = CSPMisc::getInstance()->AesDecrypt(buffer, len);
    strcpy_s(buffer, out);
    printf(buffer);
    getchar();


}