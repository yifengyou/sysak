#include <iostream>
using namespace std;

extern void test_func(void);
int main()
{
	cout << "hello world" <<endl;
	test_func();
	return 0;
}

