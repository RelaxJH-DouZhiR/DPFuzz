#!/bin/bash
# Environment variable

export mjs=/home/a/fuzz/DPfuzz/dataset/mjs
#
export DPFuzz=/home/a/fuzz/DPfuzz/DPFuzz
#
export fuzzfile=/home/a/fuzz/DPfuzz
export CC=$DPFuzz/afl-clang-fast
export CXX=$DPFuzz/afl-clang-fast++
export LDFLAGS=-lpthread
export py38=/home/a/anaconda3/envs/py38/bin/python
export testtime=3600
