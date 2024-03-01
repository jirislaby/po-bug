cmake_minimum_required(VERSION 3.5.0)

# C needed for LLVM -> terminfo
project(po-bug VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall)

find_package(LLVM REQUIRED CONFIG)

include(AddLLVM)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

set(LLVM_LINK_COMPONENTS core support)

add_llvm_library(po-bug MODULE po-bug.cpp)
