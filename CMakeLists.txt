cmake_minimum_required(VERSION 3.14)
project(file_encryptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig QUIET)
find_package(sodium QUIET)

set(SODIUM_LIB "")

if (sodium_FOUND)
    message(STATUS "Found libsodium via find_package")
    set(SODIUM_LIB sodium::sodium)
elseif (PKG_CONFIG_FOUND)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(SODIUM_LIB PkgConfig::SODIUM)
else()
    message(FATAL_ERROR "Could not locate libsodium (neither CMake package nor pkg-config).")
endif()

add_executable(file_encryptor
    src/main.cpp
    src/FileEncryptor.cpp
    src/KeyManager.cpp
)

target_include_directories(file_encryptor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(file_encryptor PRIVATE ${SODIUM_LIB})

if (MSVC)
    target_compile_options(file_encryptor PRIVATE /W4 /permissive-)
else()
    target_compile_options(file_encryptor PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()
