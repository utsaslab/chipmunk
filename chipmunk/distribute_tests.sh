#!/bin/bash

test_dir=$1
num_vms=$2

if [ -z $test_dir ] || [ -z $num_vms ]
then
    echo "Usage: distribute_tests.sh test_dir num_vms"
    exit 1
fi

# create directories to move
for (( i=0; i<$num_vms; i++ ))
do

    mkdir -p bin/linux_amd64/tests/"tests$i" 
done

# divide up tests equally and distribute them amongst the test dirs
num_tests=$(ls bin/linux_amd64/tests/$test_dir | wc -l)
echo $num_tests

remainder=$(($num_tests%10))
tests_per_vm=$(($num_tests/10))
echo $tests_per_vm
echo $remainder

base=1
for (( i=0; i<$num_vms; i++))
do 
    for (( j=0; j<$tests_per_vm; j++))
    do 
        echo "Move j-lang$(($base+$j)) to bin/linux_amd64/tests/tests$i"
        mv bin/linux_amd64/tests/$test_dir/j-lang$(($base+$j)).so bin/linux_amd64/tests/tests$i
    done
    base=$(($base+$tests_per_vm))
done

# move remainder to the last folder
for (( i=0; i<$remainder; i++))
do 
    echo "Move j-lang$(($base+$i)) to bin/linux_amd64/tests/tests$(($num_vms-1))"
    mv bin/linux_amd64/tests/$test_dir/j-lang$(($base+$i)).so bin/linux_amd64/tests/tests$(($num_vms-1))
done 

