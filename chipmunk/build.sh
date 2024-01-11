#!/bin/bash

make
rm -rf ../vmshare/syzkallerBinaries/*
cp -r bin/* ../vmshare/syzkallerBinaries