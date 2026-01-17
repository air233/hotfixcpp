#include<string>
#include<map>
#include<memory>

struct sFuncPatch
{
    std::string strBaseFucName; //原始函数
    uintptr_t OldFuncAddr;
    std::string strBaseAssesmly;//原始汇编代码,用于还原
    std::shared_ptr<void> OldHandle;//原引用的handle

    std::string strNewFuncName; //替换函数名
    uintptr_t NewFuncAddr;//函数地址
    std::string strSoPathName;  //更新的So路径
    std::shared_ptr<void> NewHandle;//引用的handle
};


//打开的so文件handle 通过share_ptr引用计数,当没有引用时自动close

//非线程安全的
class HotFixMgr
{
public:
    HotFixMgr();
    ~HotFixMgr();

    void init();
    void uninit();

    bool fixFunc(const std::string& strOldFuc, const std::string& strNewFuc, const std::string& strSoPath);
    bool restoreFunc(const std::string& strFucName);
    
 private:
    bool _fixFunc(const std::string& strOldFuc, const std::string& strNewFuc, const std::string& strSoPath);
    bool _restoreFunc(const std::string& strFucName);
    bool _install_hotpatch(sFuncPatch& stPatch);
    bool _uninstall_hotpatch(sFuncPatch& stPatch);
    
    std::shared_ptr<void> _createHandle(const std::string& strSoPath);
    std::shared_ptr<void> _getHandle(const std::string& strSoPath);
    uintptr_t _getFuncAddrFromHandle(std::shared_ptr<void> pHanlde, const std::string& strFucName);
private:
    //fuc_name -> sFuncPatch
    std::map<std::string, sFuncPatch> m_mFunc;
    //so_path -> handle
    std::map<std::string, std::weak_ptr<void>> m_mOpenHandle;
};

