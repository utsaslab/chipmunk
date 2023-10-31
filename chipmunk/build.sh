#!/bin/bash

make clean
make
rm -r ../vmshare/syzkallerBinaries/*
cp -r bin/* ../vmshare/syzkallerBinaries