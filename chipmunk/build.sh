#!/bin/bash

make
rm -r ../vmshare/syzkallerBinaries/*
cp -r bin/* ../vmshare/syzkallerBinaries