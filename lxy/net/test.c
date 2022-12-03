#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


int main()
{
    uint32_t  a = 0x12345678;
    uint32_t  d = 0x78654321;
    uint32_t  s1 = 0x43672892;
    uint32_t  s2 = 0x92286743;
    uint32_t  b = 0;
    uint32_t  c = 0;
    b = ntohl(s1);
    printf("b:%x\n",b);
    c = htonl(b);
   // printf("s1:%p,%x\n",c,c);
   // printf("%x\n",b);
    printf("c:%x\n",c);
    
    
}
