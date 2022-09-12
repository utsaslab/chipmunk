# Setting up Chipmunk

## 1. Dependencies and directory setup
1. Run the following commands to install and properly set up Chipmunk's dependencies:
```
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev gcc-8 g++-8 debootstrap qemu-system python3-pip 
sudo update-alternatives --install /usr/bin/gcc gcc  /usr/bin/gcc-8 1
pip3 install progress
```
2. Install Golang using the instructions here: https://go.dev/doc/install

## 2. Compiling the kernel
From now on we assume that the kernel source directory is at `Chipmunk/vmshare/linux-5.1`.
1. `cd` to `chipmunk/vmshare/linux-5.1`
2. Set up the kernel to use the `chipmunk/vmshare/linux-5.1/NOVA_CONFIG` as its configuration file. One way to do this and make sure the configuration file is set up properly is to load NOVA_CONFIG in menuconfig and then save it as .config. 
3. Run `make`

### Troubleshooting

If you encounter this error: `error: '-mindirect-branch' and '-fcf-protection' are not compatible`, make sure that you have installed gcc-8 and run `sudo update-alternatives --install /usr/bin/gcc gcc  /usr/bin/gcc-8 1`.

**NOTE:** Compiling Chipmunk involves building some kernel modules against the kernel you will run them on. The kernel must be compiled before compiling Chipmunk.

## 3. Setting up VMs
1. `cd` to `chipmunk/syzkaller/tools/` and run the `create-image.sh` script. This will create a VM image called stretch.img and a public and private key for ssh-ing into the VMs. Move stretch.img into the top-level `chipmunk/` directory and the keys to `~/.ssh/`. 
2. Boot the VM with the 5.1.0+ kernel and emulated PM. A script that boots the VM with the suggested arguments is provided at `boot-vm.sh`. The VM is set up for passwordless root access; log in with username `root`. It should not ask for a password.
3. To confirm that the emulated PM is working correctly, check that `/dev/` contains `pmem0` and `pmem1` devices. 
4. In the VM, create directories `/root/tmpdir`, `/mnt/pmem`, and `/mnt/pmem_replay`. Chipmunk expects these directories in these exact locations, so don't rename or move them. 
5. Add the line `mount -t 9p -o trans=virtio,version=9p2000.L hostshare /root/tmpdir` to `~/.profile` in the VM. This mounts a shared directory between the host and guest. Source the .profile file and `ls ~/tmpdir` to confirm that this works; you should see the kernel source directory there. 
6. Try loading the NOVA file system module with `insmod tmpdir/linux-5.1/fs/nova/nova.ko` and mount it at `/mnt/pmem` with `mount -t NOVA -o init /dev/pmem0 /mnt/pmem`. This should succeed, and running `df` should show that `/dev/pmem0` is mounted at `/mnt/pmem`. The VM can now be shut down.

## 4. Building and running Chipmunk with Syzkaller
1. `cd` to `chipmunk/` and run `make`.
2. Create a directory `workdir` in `chipmunk`.
3. Create a copy of `config.template` named `config` and edit it so that:

    - "workdir" is set to the absolute path to `chipmunk/syzkaller/workdir`
    - "kernel_obj" is set to the absolute path to `chipmunk/vmshare/linux-5.1`
    - "image" is set to the absolute path to `stretch.img`
    - "sshkey" is set to the absolute path to the `stretch.id_rsa` file created by the `create-image.sh` script. `stretch.id_rsa.pub` should be located in the same directory.
    - "syzkaller" is set to the absolute path to `chipmunk/syzkaller`
    - "filesystem" and "logger" are set to reflect the correct file system
    - "tester_dir" is set to the absolute path to `chipmunk/`
    - "filesystem" and "logger" reflect the file system you would like to test
    - in the VM options, "kernel" is set to the absolute path to the bzImage for the kernel and "share_dir" is set to the absolute path to `chipmunk/vmshare`. You can also update the number of VMs for Syzkaller to spawn and the amount of memory and number of CPUs to allocate for each VM here.
4. Run `sudo ./bin/syz-manager -config config`. To run in debug mode with extra output, add `-debug`. This generates a significant amount of output, so you should redirect the output to files.
5. As Chipmunk runs, it will create a set of directories with names like `vmshare-#` (one for each VM) and store output from that VM's fuzzing instance there. It also stores some data in `chipmunk/syzkaller/workdir`.

## 5. Building and running manual tests

1. Make sure you have compiled Chipmunk
2. Run `cd chipmunk; cp -r bin/* chipmunk/vmshare/syzkallerBinaries` to copy the binaries for the Chipmunk files into the shared directory. 
3. Boot the VM and copy the contents of `/root/tmpdir/syzkallerBinaries/` into another directory `/root/syzkallerBinaries` - this is necessary because some of the memory management that code from Syzkaller does will not work if it is run from within the shared directory. 
4. `cd` to `/root/syzkallerBinaries/linux_amd64` and run `./syz-execprog -crashConsistency -mountCov <program name>`. The program name should just be the hexadecimal name of a file produced by the fuzzer and placed in the `vmshare-#/crashConsistencyProgs` and syz-execprog will automatically look in `/root/tmpdir/crashConsistencyProgs` for it. You may need to move the program from an instance-specific vmshare directory to the main one. 
    - By default, execprog tests NOVA. To test a different file system, add the arguments `-fs=<fs name> -fs_path=<absolute path to FS .ko file on the VM> -logger=<absolute path to logger .ko file on the VM>`. If the FS under test is built into the kernel, pass the empty string "" to `-fs_path`.
    - syz-execprog mocks some of the fuzzing infrastructure that the executor expects, but otherwise runs the exact same code as the fuzzer when testing the file system.

## 6. Building and running ACE tests
1. `cd` to `chipmunk/` and run `make`.
2. `cd` to `chipmunk/executor/ace`. Run `python3 ace.py -l <seq length> -n false -d false -t <fs type>` to generate tests. The sequence length option can be 1, 2, or 3. The test type options supported by Chipmunk are `pm` and `crashmonkey`. The default option is `crashmonkey`; these tests are placed in `chipmunk/executor/tests/dax_seq#` and should be used only with EXT4-DAX or XFS-DAX. To test NOVA, PMFS, WineFS, or other PM-specific file systems, use the `pm` option. These tests are placed in `chipmunk/executor/tests/seq#`.
3. Compile tests by running `make <test dir>_tests` where `<test dir>` is the location of the test you'd like to build. For example, compiling seq2 tests generated using `pm` mode would be `make seq2_tests`. Seq1 `pm` tests are compiled along with Chipmunk and don't need to be compiled with a specific command.
4. Run `cp -r bin/* chipmunk/vmshare/syzkallerBinaries` to copy the testing infrastructure and compiled tests to a directory that is shared with the VM.
5. Boot the VM and run `cd tmpdir/syzkallerBinaries`.
6. To run an individual ACE test, use the command `./ace-executor_cc -v -f <fs type> tests/seq1/j-lang1.so`, replacing `seq1/j-lang1.so` with the relative path to the test you want to run. If the FS type is not provided, the tester defaults to NOVA. There are additional arguments for providing information like the size and location of PM devices if they are not the defaults set by the `boot-vm.sh` script.
