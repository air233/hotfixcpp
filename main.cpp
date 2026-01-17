#include <iostream>
#include "hotfix.h"

void test()
{
    std::cout << "test form main" << std::endl;
}

int main()
{
    HotFixMgr mgr;
    std::cout << "热更新前:" << std::endl;
    test();

    std::cout << "热更新1后:" << std::endl;
    mgr.fixFunc("_Z4testv", "_Z4testv", "./libhotfunc.so");
    test();

    std::cout << "热更新2后:" << std::endl;
    mgr.fixFunc("_Z4testv","_Z6test_2v", "./libhotfunc.so");
    test();

    std::cout << "还原后:" << std::endl;
    mgr.restoreFunc("_Z4testv");
    test();

    std::cout << "热更新3后:" << std::endl;
    mgr.fixFunc("_Z4testv", "_Z4testv", "./libhotfunc.so");
    test();

    return 0;
}
