#include <stdio.h>
#include <string.h>



int main()
{
	char *p1 = "abcdefg";
	char *p2 = p1;
	int  len = 0;
	printf("p1:%s\np2:%s\n",p1, p2);

	len = strlen(p1);
	if (len == 0) {
		printf("长度不对！\n");
		return 0;
	}
	for (int i = 0; i < (len / 2); i++) {
		p2++;
	}

	printf("p2:%s\n", p2);
	printf("中间字符:%c\n", p2[0]);
}