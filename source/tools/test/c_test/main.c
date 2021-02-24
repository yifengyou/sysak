#include <stdio.h>

extern void test_func(void);
int main()
{
	printf("hello world\n");
	test_func();
	return 0;
}

