#!/bin/sh


mount -t 9p -o trans=virtio,version=9p2000.L hostshare /root/tmpdir/
# TODO: take file system name as an argument
for FILE in /ace_tests/*
do
    /ace-executor_cc -c -v -O / -L / $FILE
done