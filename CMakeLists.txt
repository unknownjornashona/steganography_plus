cmake_minimum_required(VERSION 3.10)
project(TextSteganography)

set(CMAKE_CXX_STANDARD 11)

# 查找OpenSSL库
find_package(OpenSSL REQUIRED)

# 添加可执行文件
add_executable(TextSteganography main.cpp text_steganography.cpp)

# 链接OpenSSL库
target_link_libraries(TextSteganography OpenSSL::SSL OpenSSL::Crypto)

# 设置C++标准
set_target_properties(TextSteganography PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
)
