cmake_minimum_required(VERSION 3.1)
project(HotFixDemo CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 一定要使用-rdynamic将内部符号导出
add_compile_options(-rdynamic)

add_executable(main main.cpp hotfix.cpp)

target_include_directories(main PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/*.h      # 项目头文件
)

target_link_libraries(main PRIVATE dl)

#==============================================================================

# ==================== 创建动态库文件 ====================
add_library(hotfunc SHARED
    hotfunc.cpp 
)

# 设置输出名称
set_target_properties(hotfunc PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
)

# 编译选项
target_compile_options(hotfunc PRIVATE
    -fPIC  # 位置无关代码（共享库必须）
    -Wall
    -Wextra
)