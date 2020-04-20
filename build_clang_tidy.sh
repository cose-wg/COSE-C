#!/bin/sh

export CC=clang-10
export CXX=clang++-10
rm -rf build
mkdir build
cd build
cmake .. -DCOSE_C_RUN_CLANG_TIDY=ON
make
