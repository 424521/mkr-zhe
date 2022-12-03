#include <stdio.h>
 
int main()
{
    char buf1[6]={0x11,0x22,0x33,0x44,0x55,0x66};

    char buf2[20];

    memset(buf2,0,20);

    for(int i=0;i<sizeof(buf1);i++)
    {
        sprintf(buf2 + strlen(buf2),"%02X",buf1[i]);
    }

    printf("buf2:%s\n",buf2);
}