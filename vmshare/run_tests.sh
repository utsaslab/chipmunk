#!/bin/bash

TESTNUM=$1

cd syzkallerBinaries/linux_amd64
for f in tests/seq$1/*.so
do 
    ./ace-executor_cc -v -f hayleyfs $f
done