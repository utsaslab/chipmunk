# Chipmunk: Investigating Crash-Consistency in Persistent-Memory File Systems (EuroSys 2023)

Chipmunk is a framework for testing persistent-memory (PM) file systems for crash consistency bugs. Using Chipmunk, we found 23 new bugs in 5 PM file systems. This repository includes the Chipmunk test harness, the Syzkaller fuzzer, and the ACE systematic workload generator. 

## System requirements
- Ubuntu 20.04

Chipmunk does *not* require real PM hardware.

## Repository contents
- `chipmunk/` includes all testing infrastructure. 
    - `chipmunk/executor/ace/` includes our modified version of the ACE workload generator. See the setup instructions for information on how to run ACE.
    - `chipmunk/executor/harness/` includes most of Chipmunk's test harness code.
        - `chipmunk/executor/harness/test_harness.cpp` compiles to the executable that runs ACE tests.
    - `chipmunk/executor/executor_cc.cc` compiles to the executable that runs Syzkaller-generated tests.
    - `chipmunk/loggers/` includes system-specific logger modules.
- `scripts/` includes setup scripts.
- `vmshare/` includes files that are shared with the VM running the tests.
    - `vmshare/linux-5.1` includes the source code for the Linux kernel, including file system code.
    - `vmshare/crashConsistencyProgs` is used to store Syzkaller-generated workloads.
    - `vmshare/logs` is used to store logs and bug reports from failing tests.

## Setup instructions

### 1. Compiling
1. Run `scripts/dependencies.sh` to install the dependencies for Chipmunk, Syzkaller, and ACE. 
2. Install Go: https://go.dev/doc/install
3. Run `scripts/build_kernel.sh <cores>` to automatically configure and compile the kernel.

**Troubleshooting**

- If you encounter this error: `error: '-mindirect-branch' and '-fcf-protection' are not compatible`, install gcc-8 and run `sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 1`.
- Compiling Chipmunk involves building some kernel modules against the kernel you will run them on. The kernel must be compiled before Chipmunk can be compiled.

### 2. Setting up VM
1. `cd` to `chipmunk/tools/` and run the `create-image.sh` script. This creates a VM called stretch.img in the top-level directory and a key pair (`stretch.id_rsa*`) in .ssh.

This will create a VM image called stretch.img and a public and private key for ssh-ing into the VMs. 


## Results
Instructions to reproduce bugs found by Chipmunk can be found in [bugs.md](bugs.md).

## Notes
This version of Chipmunk does not currently support testing SplitFS; we are working on merging this support in. 


