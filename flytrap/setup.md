# Setting up FlyTrap

## 1. Dependencies and directory setup
1. Create a directory `flytrap/` and a directory `flytrap/vmshare/`. 
2. `cd` into `flytrap/` and clone https://github.com/shankarapailoor/syzkaller there. 
3. `cd` into `flytrap/vmshare/` and clone https://github.com/hayley-leblanc/nova there.
4. Run `sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev gcc-8 g++-8 debootstrap qemu-system` to install libraries for compiling the Linux kernel and building/running virtual machines. Run `sudo update-alternatives --install /usr/bin/gcc gcc  /usr/bin/gcc-8 1` to ensure that the compilation uses the correct version of GCC for our version of the kernel.
5. Install Golang using the instructions here: https://go.dev/doc/install

## 2. Compiling the kernel
From now on we assume that the kernel source directory is at `flytrap/vmshare/linux-5.1`.
1. `cd` to `flytrap/vmshare/linux-5.1`
2. Set up the kernel to use the `flytrap/vmshare/linux-5.1/NOVA_CONFIG` as its configuration file. One way to do this and make sure the configuration file is set up properly is to load NOVA_CONFIG in menuconfig and then save it as .config. 
3. Run `make`

### Troubleshooting

If you encounter this error: `error: '-mindirect-branch' and '-fcf-protection' are not compatible`, make sure that you have installed gcc-8 and run `sudo update-alternatives --install /usr/bin/gcc gcc  /usr/bin/gcc-8 1`.

## 3. Setting up VMs
1. `cd` to `flytrap/syzkaller/tools/` and run the `create-image.sh` script. This will create a VM image called stretch.img and a public and private key for ssh-ing into the VMs. These can be moved out of the `tools/` directory; their locations will be specified in a configuration file later.
2. Boot the VM with the 5.1.0+ kernel and emulated PM. The suggested command for booting it is:
    ```
    set +H; sudo qemu-system-x86_64 -boot c -m 4096 -hda <path to stretch.img> -enable-kvm -nographic -kernel <path to flytrap/vmshare>/linux-5.1/arch/x86/boot/bzImage -append "root=/dev/sda console=ttyS0 earlyprintk=serial memmap=128M!4G memmap=128M!4224M" -fsdev local,security_model=passthrough,id=fsdev0,path=<absolute path to flytrap/vmshare> -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare -smp 1 -net nic -net user,hostfwd=tcp::2222-:22 -cpu host
    ```
    The VM is set up for passwordless root access; log in with username `root`. It should not ask for a password.
3. To confirm that the emulated PM is working correctly, check that `/dev/` contains `pmem0` and `pmem1` devices. 
4. In the VM, create directories `~/tmpdir`, `/mnt/pmem`, and `/mnt/pmem_replay`. FlyTrap expects these directories in these exact locations, so don't rename or move them. 
5. Add the line `mount -t 9p -o trans=virtio,version=9p2000.L hostshare /root/tmpdir` to `~/.profile` in the VM. This mounts a shared directory between the host and guest. Source the .profile file and `ls ~/tmpdir` to confirm that this works; you should see the kernel source directory there. 
6. Try loading the NOVA file system module with `insmod tmpdir/linux-5.1/fs/nova/nova.ko` and mount it at `/mnt/pmem` with `mount -t NOVA -o init /dev/pmem0 /mnt/pmem`. This should succeed, and running `df` should show that `/dev/pmem0` is mounted at `/mnt/pmem`. The VM can now be shut down.

## 4. Building and running FlyTrap with Syzkaller
1. `cd` to `flytrap/syzkaller/` and run `make` twice. The first run will fail due to a missing file; this file is created during compilation, so the second `make` command should succeed.
2. Create a directory `workdir` in `flytrap/syzkaller`.
3. In `flytrap/syzkaller/`, edit the config file so that:

    - "workdir" is set to the absolute path to `flytrap/syzkaller/workdir`
    - "kernel_obj" is set to the absolute path to `flytrap/vmshare/linux-5.1`
    - "image" is set to the absolute path to `stretch.img`
    - "sshkey" is set to the absolute path to the `stretch.id_rsa` file created by the `create-image.sh` script. `stretch.id_rsa.pub` should be located in the same directory.
    - "syzkaller" is set to the absolute path to `flytrap/syzkaller`
    - "filesystem" and "logger" are set to reflect the correct file system
    - "tester_dir" is set to the absolute path to `flytrap/`
    - in the VM options, "kernel" is set to the absolute path to the bzImage for the kernel and "share_dir" is set to the absolute path to `flytrap/vmshare`. You can also update the number of VMs for Syzkaller to spawn and the amount of memory and number of CPUs to allocate for each VM here.
4. In `flytrap/syzkaller/`, run `sudo ./bin/syz-manager -config config`. To run in debug mode with extra output, add `-debug`. This generates a significant amount of output, so you should redirect the output to files.
5. As FlyTrap runs, it will create a set of directories with names like `vmshare-#` (one for each VM) and store output from that VM's fuzzing instance there. It also stores some data in `flytrap/syzkaller/workdir`.

## 5. Building and running manual tests

1. Make sure you have compiled FlyTrap
2. Run `cd flytrap; cp -r bin/* flytrap/vmshare/syzkallerBinaries` to copy the binaries for the FlyTrap files into the shared directory. 
3. Boot the VM and copy the contents of `/root/tmpdir/syzkallerBinaries/` into another directory `/root/syzkallerBinaries` - this is necessary because some of the memory management that code from Syzkaller does will not work if it is run from within the shared directory. 
