#!/bin/sh

# sudo apt install clang clang-tidy

export CC=clang
export CXX=clang++
rm -rf build
mkdir build
cd build
cmake .. -DCOSE_C_RUN_CLANG_TIDY=ON
make
