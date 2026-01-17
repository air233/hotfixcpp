#include <iostream>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>
#include <atomic>
#include <dlfcn.h> 
#include <memory>

int install_hotpatch(void* target, void* replacement) {
    size_t page_size = sysconf(_SC_PAGESIZE);

    // 平台特定的代码注入
    #if defined(__x86_64__)
    unsigned char code[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, replacement
        0xFF, 0xE0                                                  // jmp rax
    };
    size_t instruction_size = sizeof(code);
    *(void**)(code + 2) = replacement;

    #elif defined(__aarch64__)
    // ARM64代码: 需要更复杂的处理，因为指令是4字节对齐
    // 简单的相对跳转可能不够，这里使用绝对跳转
    unsigned char code[] = {
        0x50, 0x00, 0x00, 0x58,  // ldr x16, #8 (加载地址到x16)
        0x00, 0x02, 0x1F, 0xD6,  // br x16 (跳转到x16)
        0x00, 0x00, 0x00, 0x00,  // 占位符：地址低位
        0x00, 0x00, 0x00, 0x00   // 占位符：地址高位
    };
    size_t instruction_size = sizeof(code);
    *(void**)(code + 8) = replacement;

    #elif defined(__arm__)
    // ARM32代码
    unsigned char code[] = {
        0x04, 0xF0, 0x1F, 0xE5,  // ldr pc, [pc, #-4] (加载地址到pc)
        0x00, 0x00, 0x00, 0x00   // 占位符：函数地址
    };
    size_t instruction_size = sizeof(code);
    *(void**)(code + 4) = replacement;

    #else
    #error "Unsupported architecture"
    #endif

    // 计算需要修改的内存页范围
    uintptr_t target_addr = reinterpret_cast<uintptr_t>(target);
    uintptr_t start_page = target_addr & ~(page_size - 1);

    // 计算结束地址，确保包含整个指令
    uintptr_t end_addr = target_addr + instruction_size;
    uintptr_t end_page = (end_addr + page_size - 1) & ~(page_size - 1);

    size_t protect_len = end_page - start_page;

    std::cout << "Debug info:" << std::endl;
    std::cout << "  Target address: 0x" << std::hex << target_addr << std::dec << std::endl;
    std::cout << "  Instruction size: " << instruction_size << " bytes" << std::endl;
    std::cout << "  Page size: " << page_size << " bytes" << std::endl;
    std::cout << "  Start page: 0x" << std::hex << start_page << std::dec << std::endl;
    std::cout << "  Protect length: " << protect_len << " bytes" << std::endl;

    // 修改内存保护为可读写可执行
    if (mprotect(reinterpret_cast<void*>(start_page), protect_len, 
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        std::cerr << "mprotect failed: " << strerror(errno) << std::endl;
        return -1;
    }

    // 保存原始指令（用于可能的恢复）
    unsigned char* original_code = new unsigned char[instruction_size];
    memcpy(original_code, target, instruction_size);

    // 内存屏障确保写入顺序
    //std::atomic_thread_fence(std::memory_order_release);

    // 写入跳转代码
    memcpy(target, code, instruction_size);

    // 内存屏障确保所有处理器看到更新
    //std::atomic_thread_fence(std::memory_order_seq_cst);

    // 清除指令缓存（确保CPU执行新代码）
    __builtin___clear_cache(
        reinterpret_cast<char*>(target),
        reinterpret_cast<char*>(target) + instruction_size
    );

    // 可选：恢复内存保护为只读可执行
    // mprotect(reinterpret_cast<void*>(start_page), protect_len, PROT_READ | PROT_EXEC);

    std::cout << "Hotpatch installed successfully!" << std::endl;

    // 清理（在实际应用中，需要保留original_code以便恢复）
    delete[] original_code;

    return 0;
}

// 恢复原始代码的函数（如果需要）
int restore_hotpatch(void* target, unsigned char* original_code, size_t code_size) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t target_addr = reinterpret_cast<uintptr_t>(target);
    uintptr_t start_page = target_addr & ~(page_size - 1);
    uintptr_t end_page = (target_addr + code_size + page_size - 1) & ~(page_size - 1);
    size_t protect_len = end_page - start_page;

    // 修改内存保护
    if (mprotect(reinterpret_cast<void*>(start_page), protect_len, 
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }

    // 恢复原始代码
    memcpy(target, original_code, code_size);

    // 清除指令缓存
    __builtin___clear_cache(
        reinterpret_cast<char*>(target),
        reinterpret_cast<char*>(target) + code_size
    );

    // 恢复内存保护
    mprotect(reinterpret_cast<void*>(start_page), protect_len, PROT_READ | PROT_EXEC);

    return 0;
}

uintptr_t getFuncAddr(const std::string& strFucName, const std::string& strSoPath)
{
    void* handle = nullptr;

    if(strSoPath.empty())
    {
        handle = dlopen(NULL, RTLD_LAZY);
    }
    else
    {
        handle = dlopen(strSoPath.c_str(), RTLD_LAZY);
    }

    if (!handle)
    {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 0;
    }

    void* func_ptr = dlsym(handle, strFucName.c_str());
    if(func_ptr == nullptr)
    {
        dlclose(handle);
        return 0;
    }

    return reinterpret_cast<uintptr_t>(func_ptr);
}

bool hotfix(const std::string& strBugFuc, const std::string& strNewFuc, const std::string& strSoPath)
{
    //获取原始函数地址
    uintptr_t target = getFuncAddr(strBugFuc, "");
    if(target == 0) return false;

    uintptr_t replacement = getFuncAddr(strNewFuc, strSoPath);
    if(replacement == 0) return false;

    return 0 == install_hotpatch((void*)target, (void*)replacement);
}

void test()
{
    std::cout << "test form main" << std::endl;
}

#include "hotfix.h"
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
