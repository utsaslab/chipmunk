#!/bin/bash

sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev gcc-8 g++-8 debootstrap qemu-system python3-pip 
sudo update-alternatives --install /usr/bin/gcc gcc  /usr/bin/gcc-8 1
pip3 install progress
