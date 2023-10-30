#!/bin/bash

cores=$1

if [ -z "$cores" ]
then
    echo "Usage: build_kernel.sh cores"
    exit
fi

# cd vmshare/linux-5.1
# cp CHIPMUNK_CONFIG .config 
# make -j $cores

cp CHIPMUNK_CONFIG vmshare/linux-6.3/.config 
cd vmshare/linux-6.3
make LLVM=-14 -j $cores
