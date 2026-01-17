#include "hotfix.h"

#include <iostream>
#include <dlfcn.h> 
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>

HotFixMgr::HotFixMgr()
{

}

HotFixMgr::~HotFixMgr()
{

}

void HotFixMgr::init()
{

}

void HotFixMgr::uninit()
{
    m_mFunc.clear();

    for(auto iter : m_mOpenHandle)
    {
        std::shared_ptr<void> lockPtr = iter.second.lock();
        if(lockPtr != nullptr)
        {
            //close handle
            lockPtr.reset();
        }
    }
}

bool HotFixMgr::fixFunc(const std::string& strOldFuc, const std::string& strNewFuc, const std::string& strSoPath)
{
    return _fixFunc(strOldFuc, strNewFuc, strSoPath);
}

bool HotFixMgr::restoreFunc(const std::string& strFucName)
{
    return _restoreFunc(strFucName);
}

std::shared_ptr<void> HotFixMgr::_createHandle(const std::string& strSoPath)
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
     
    if(handle == nullptr)
    {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return nullptr;
    }

    //new handle
    std::shared_ptr<void> handlePtr(handle, [strSoPath](void* handle){
        //std::cout << "auto close handle:" << strSoPath << std::endl;
        dlclose(handle);//引用计数为0时 close hanlde
    });

    //Replace or Create
    m_mOpenHandle[strSoPath] = handlePtr;
    return handlePtr;
}

std::shared_ptr<void> HotFixMgr::_getHandle(const std::string& strSoPath)
{
    auto iter = m_mOpenHandle.find(strSoPath);
    if(iter != m_mOpenHandle.end())
    {
        //存在时 检测handle是否还有效，无效时返回nullptr 进行createHandle
        return iter->second.lock();
    }

    return nullptr;
}

uintptr_t HotFixMgr::_getFuncAddrFromHandle(std::shared_ptr<void> pHanlde, const std::string& strFucName)
{
    if(pHanlde == nullptr)
    {
        fprintf(stderr, "get func addr  handle is NULL, func name: %s\n", strFucName.c_str());
        return 0;
    }

    void* pFuncPtr = dlsym(pHanlde.get(), strFucName.c_str());

    if(pFuncPtr == nullptr)
    {
        fprintf(stderr, "get func addr  fial. func name: %s\n", strFucName.c_str());
        return 0;
    }
    return reinterpret_cast<uintptr_t>(pFuncPtr);
}

bool HotFixMgr::_install_hotpatch(sFuncPatch& stPatch)
{   
    void* target = reinterpret_cast<void*>(stPatch.OldFuncAddr);
    void* replacement = reinterpret_cast<void*>(stPatch.NewFuncAddr);

    // 代码注入
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
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t target_addr = reinterpret_cast<uintptr_t>(target);
    uintptr_t start_page = target_addr & ~(page_size - 1);
    // 计算结束地址，确保包含整个指令
    uintptr_t end_addr = target_addr + instruction_size;
    uintptr_t end_page = (end_addr + page_size - 1) & ~(page_size - 1);
    size_t protect_len = end_page - start_page;
#if 0
    std::cout << "Debug info:" << std::endl;
    std::cout << "  Target address: 0x" << std::hex << target_addr << std::dec << std::endl;
    std::cout << "  Instruction size: " << instruction_size << " bytes" << std::endl;
    std::cout << "  Page size: " << page_size << " bytes" << std::endl;
    std::cout << "  Start page: 0x" << std::hex << start_page << std::dec << std::endl;
    std::cout << "  Protect length: " << protect_len << " bytes" << std::endl;
#endif

    // 修改内存保护为可读写可执行
    if (mprotect(reinterpret_cast<void*>(start_page), protect_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) 
    {
        std::cerr << "mprotect failed: " << strerror(errno) << std::endl;
        return false;
    }

    if(stPatch.strBaseAssesmly.empty())
    {
        unsigned char* original_code = new unsigned char[instruction_size];
        memcpy(original_code, target, instruction_size);
        //保存还原汇编
        stPatch.strBaseAssesmly.assign(reinterpret_cast<const char*>(original_code), instruction_size);
        delete[] original_code;
    }

    // 内存屏障确保写入顺序
    //std::atomic_thread_fence(std::memory_order_release);

    // 写入跳转代码
    memcpy(target, code, instruction_size);

    // 内存屏障确保所有处理器看到更新
    //std::atomic_thread_fence(std::memory_order_seq_cst);

    // 清除指令缓存（确保CPU执行新代码）
    __builtin___clear_cache(reinterpret_cast<char*>(target), reinterpret_cast<char*>(target) + instruction_size);
    mprotect(reinterpret_cast<void*>(start_page), protect_len, PROT_READ | PROT_EXEC);

    //std::cout << "Hotpatch installed successfully!" << std::endl;
    return true;
}

bool HotFixMgr::_restoreFunc(const std::string& strFucName)
{
    auto iter = m_mFunc.find(strFucName);
    if(iter == m_mFunc.end())
    {
        std::cout << "func not replace." << std::endl;
        return false;
    }

    if(false == _uninstall_hotpatch(iter->second))
    {
        return false;
    }

    //delete stFuncPath
    m_mFunc.erase(strFucName);
    //std::cout << "restore func:" << strFucName << std::endl;
    return true;
}

bool HotFixMgr::_uninstall_hotpatch(sFuncPatch& stPatch)
{
    void* target = reinterpret_cast<void*>(stPatch.OldFuncAddr);
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t target_addr = reinterpret_cast<uintptr_t>(target);
    uintptr_t start_page = target_addr & ~(page_size - 1);
    uintptr_t end_page = (target_addr + stPatch.strBaseAssesmly.size() + page_size - 1) & ~(page_size - 1);
    size_t protect_len = end_page - start_page;

#if 0
    std::cout << "Debug info:" << std::endl;
    std::cout << "  Target address: 0x" << std::hex << target << std::dec << std::endl;
    std::cout << "  Instruction size: " << stPatch.strBaseAssesmly.size() << " bytes" << std::endl;
    std::cout << "  Page size: " << page_size << " bytes" << std::endl;
    std::cout << "  Start page: 0x" << std::hex << start_page << std::dec << std::endl;
    std::cout << "  Protect length: " << protect_len << " bytes" << std::endl;
#endif

    // 修改内存保护
    if (mprotect(reinterpret_cast<void*>(start_page), protect_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) 
    {
        std::cerr << "mprotect failed: " << strerror(errno) << std::endl;
        return false;
    }
    
    // 恢复原始代码
    memcpy(target, stPatch.strBaseAssesmly.c_str(), stPatch.strBaseAssesmly.size());
    
    // 清除指令缓存
    __builtin___clear_cache(reinterpret_cast<char*>(target), reinterpret_cast<char*>(target) + stPatch.strBaseAssesmly.size());
    
    // 恢复内存保护
    mprotect(reinterpret_cast<void*>(start_page), protect_len, PROT_READ | PROT_EXEC);
    //std::cout << "Hotpatch _restoreFunc successfully!" << std::endl;
    return true;
}

bool HotFixMgr::_fixFunc(const std::string& strOldFuc, const std::string& strNewFuc, const std::string& strSoPath)
{
    //只要存在funcpatch就会存在thisHandle
    auto thisHandle = _getHandle("");
    if(thisHandle == nullptr)
    {
        thisHandle = _createHandle("");
    }
    
    auto NewHandle = _getHandle(strSoPath);
    if(NewHandle == nullptr)
    {
        NewHandle = _createHandle(strSoPath);
    }

    uintptr_t oldFuncPtr = _getFuncAddrFromHandle(thisHandle, strOldFuc);
    uintptr_t newFuncPtr = _getFuncAddrFromHandle(NewHandle, strNewFuc);
    if(oldFuncPtr == 0 || newFuncPtr == 0)
    {
        return false;
    }

    sFuncPatch stNewPatch;
    {
        auto iter = m_mFunc.find(strOldFuc);
        if(iter != m_mFunc.end())
        {
            stNewPatch = iter->second;

            //编辑
            stNewPatch.strNewFuncName = strNewFuc;
            stNewPatch.NewFuncAddr = newFuncPtr;
            stNewPatch.strSoPathName = strSoPath;
            stNewPatch.NewHandle = NewHandle;
        }
        else
        {
            stNewPatch.strBaseFucName = strOldFuc;
            stNewPatch.OldHandle = thisHandle;
            stNewPatch.OldFuncAddr = oldFuncPtr;
            stNewPatch.strNewFuncName = strNewFuc;
            stNewPatch.NewFuncAddr = newFuncPtr;
            stNewPatch.strSoPathName = strSoPath;
            stNewPatch.NewHandle = NewHandle;
        }
    }

    if(false == _install_hotpatch(stNewPatch))
    {
        return false;
    }
    
    //auto iter = m_mFunc.find(strOldFuc);
    m_mFunc.erase(strOldFuc);//尝试触发close

    //Record
    m_mFunc[strOldFuc] = stNewPatch;
    //std::cout << "fixFunc:" << strOldFuc << ", newFunc:" << strNewFuc  << ", path:" << strSoPath << std::endl;
    return true;
}
