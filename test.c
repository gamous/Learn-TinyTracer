#include <stdio.h>
#include<unistd.h>
int func1()
{
    printf("A");
}

void func2()
{
    printf("B");
}

void func3()
{
}

int main()
{
    func1();
    func3();
    func2();
    func2();
    func3();
    return 0;
}          