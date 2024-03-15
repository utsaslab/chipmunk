# Chipmunk: Investigating Crash-Consistency in Persistent-Memory File Systems (EuroSys 2023)

Chipmunk is a framework for testing persistent-memory (PM) file systems for crash consistency bugs. Using Chipmunk, we found 23 new bugs in 5 PM file systems. This repository includes the Chipmunk test harness, the Syzkaller fuzzer, and the ACE systematic workload generator. 

Please cite the following paper if you use Chipmunk:
```
@inproceedings {chipmunk-eurosys23,
    author = {Hayley LeBlanc and Shankara Pailoor and Om Saran and Isil Dillig and James Bornholt and Vijay Chidambaram}
    title = "{Chipmunk: Investigating Crash-Consistency in Persistent-Memory File Systems}",
    booktitle = {EuroSys '23: Eighteenth European Conference on Computer Systems},
    year = {2023},
    month = may,
 }
```

## System requirements
- Ubuntu 20.04
- At least 8GB of RAM

Chipmunk does *not* require real PM hardware.

## Repository contents
- `chipmunk/` includes all testing infrastructure. 
    - `chipmunk/executor/ace/` includes our modified version of the ACE workload generator. See the setup instructions for information on how to run ACE.
    - `chipmunk/executor/harness/` includes most of Chipmunk's test harness code.
        - `chipmunk/executor/harness/test_harness.cpp` compiles to the executable that runs ACE tests.
    - `chipmunk/executor/tests/` contains ACE-generated workloads.
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
4. `cd` to `chipmunk/` and run `make` to build the testing infrastructure. It make take several minutes to build. 

**Troubleshooting**

- If you encounter this error: `error: '-mindirect-branch' and '-fcf-protection' are not compatible`, install gcc-8 and run `sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 1`.
- Compiling Chipmunk involves building some kernel modules against the kernel you will run them on. The kernel must be compiled before Chipmunk can be compiled.

### 2. Setting up VM
1. Run `scripts/create-image.sh` script. This creates an image called stretch.img in the top-level directory and a key pair in `$HOME/.ssh/`.
2. Boot the VM using `scripts/boot-vm.sh`. The VM can be accessed directly in this terminal, but to avoid visual glitches, we recommend sshing into the VM using `ssh root@localhost -p 2222 -i ~/.ssh/stretch.id_rsa`.
3. The scripts should automatically share the `vmshare/` directory with the VM. To confirm that this and the PM emulation worked, try loading the NOVA file system module with `insmod tmpdir/linux-5.1/fs/nova/nova.ko` and mount it at `/mnt/pmem` with `mount -t NOVA -o init /dev/pmem0 /mnt/pmem`. This should succeed, and running `df` should show that `/dev/pmem0` is mounted at `/mnt/pmem`. The VM can now be shut down.

## 3. Building and running Chipmunk with Syzkaller
1. In `chipmunk/`, create a copy of `config.template` named `config` and edit it so that:
    - "workdir" is set to the absolute path to `chipmunk/syzkaller/workdir`
    - "kernel_obj" is set to the absolute path to `chipmunk/vmshare/linux-5.1`
    - "image" is set to the absolute path to `stretch.img`
    - "sshkey" is set to the absolute path to the `stretch.id_rsa` file created by the `create-image.sh` script. It should have been placed in `$HOME/.ssh/` by this script.
    - "syzkaller" is set to the absolute path to `chipmunk/syzkaller`
    - "tester_dir" is set to the absolute path to `chipmunk/`
    - "filesystem" and "logger" reflect the file system you would like to test
    - in the VM options, "kernel" is set to the absolute path to the bzImage for the kernel and "share_dir" is set to the absolute path to `chipmunk/vmshare`. You can also update the number of VMs for Syzkaller to spawn and the amount of memory and number of CPUs to allocate for each VM here.
2. Run `sudo ./bin/syz-manager -config config`. To run in debug mode with extra output, add `-debug`. This generates a significant amount of output, so you should redirect the output to files.
3. As Chipmunk runs, it will create a set of directories with names like `vmshare-#` (one for each VM) and store output from that VM's fuzzing instance there. It also stores some data in `chipmunk/syzkaller/workdir`.
4. While the fuzzer runs, a dashboard listing bug reports and statistics about the run is accessible via your web browser at the IP address of the host.

## 4. Building and running manual tests
1. Run `cd chipmunk; cp -r bin/* ../vmshare/syzkallerBinaries` to copy the binaries for the Chipmunk files into the shared directory. 
2. Boot the VM and copy the contents of `/root/tmpdir/syzkallerBinaries/` into another directory `/root/syzkallerBinaries` - this is necessary because some of the memory management that code from Syzkaller does will not work if it is run from within the shared directory. 
3. `cd` to `/root/syzkallerBinaries/linux_amd64` and run `./syz-execprog -crashConsistency -mountCov <program name>`. The program name should just be the hexadecimal name of a file produced by the fuzzer and placed in the `vmshare-#/crashConsistencyProgs` and syz-execprog will automatically look in `/root/tmpdir/crashConsistencyProgs` for it. You may need to move the program from an instance-specific vmshare directory to the main one. 
    - By default, execprog tests NOVA. To test a different file system, add the arguments `-fs=<fs name> -fs_path=<absolute path to FS .ko file on the VM> -logger=<absolute path to logger .ko file on the VM>`. If the FS under test is built into the kernel, pass the empty string "" to `-fs_path`.
    - syz-execprog mocks some of the fuzzing infrastructure that the executor expects, but otherwise runs the exact same code as the fuzzer when testing the file system.

## 5. Building and running ACE tests
1. `cd` to `chipmunk/executor/ace`. Run `python3 ace.py -l <seq length> -n false -d false -t <fs type>` to generate tests. 
    - The sequence length option can be 1, 2, or 3. 
    - The test type options supported by Chipmunk are `pm` and `crashmonkey`. The default option is `crashmonkey`; these tests are placed in `chipmunk/executor/tests/dax_seq#` and should be used only with EXT4-DAX or XFS-DAX. To test NOVA, PMFS, WineFS, or other PM-specific file systems, use the `pm` option. These tests are placed in `chipmunk/executor/tests/seq#`.
3. Move back to the top-level directory and compile tests by running `make <test dir>_tests` where `<test dir>` is the location of the test you'd like to build. 
    - For example, compiling seq2 tests generated using `pm` mode would be `make seq2_tests`. Seq1 `pm` tests are compiled along with Chipmunk and don't need to be compiled with a specific command.
4. Run `cp -r bin/* chipmunk/vmshare/syzkallerBinaries` to copy the testing infrastructure and compiled tests to a directory that is shared with the VM.
5. Boot the VM and `cd` to `tmpdir/syzkallerBinaries`.
6. To run an individual ACE test, use the command `./ace-executor_cc -v -f <fs type> tests/seq1/j-lang1.so`, replacing `seq1/j-lang1.so` with the relative path to the test you want to run. If the FS type is not provided, the tester defaults to NOVA.


## Results
Instructions to reproduce bugs found by Chipmunk can be found in [bugs.md](bugs.md).

## Notes
This version of Chipmunk does not currently support testing SplitFS; we are working on merging this support in. 


