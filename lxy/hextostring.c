#include <stdio.h>
#include <stdlib.h>
typedef unsigned char   uint8_t;
char hexToch (uint8_t old);
uint8_t HexToChar(uint8_t temp);

int main(){
    int i = 0;
    uint8_t data[5]={0x4d,0x34,0x56,0xab,0xef};
    uint8_t str[10];
    uint8_t dst[10];
    for(i = 0; i<5;i++)
    {
        str[2*i] = data[i]>>4;
        str[2*i+1] = data[i]&0xf;
    }
        for(i = 0; i<10;i++)
    {
        dst[i] = HexToChar(str[i]);
    }
    for(i = 0; i<10;i++)
    {
         printf("%c\n",dst[i]);
    }
     return 0;
}

uint8_t HexToChar(uint8_t temp)
{
    uint8_t dst;
    if (temp < 10){
        dst = temp + '0';
    }else{
        dst = temp -10 +'A';
    }
    return dst;
}