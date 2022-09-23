# Bugs found by Chipmunk

The version of Linux in `vmshare/` has been modified with kernel configuration options that allow bugs that were found by Chipmunk and fixed to be re-added to the kernel. Each bug configuration option looks like `CONFIG_FSNAME_BUGX` where `FSNAME` is the name of the affected file system and `X` is a number identifying the bug. Bugs can be injected into the file systems by setting their corresponding config option to `Y` and re-compiling. Using `make menuconfig`, these options can be found under `File Systems > PM file system bugs`.

Note that multiple bugs may be built into the kernel at a time, but some bugs cause kernel panics. The consequence of each bug is listed below and in the `help` section of its configuration option in `make menuconfig`. If a bug that causes a kernel panic is compiled together with multiple other bugs from the same file system, the panicking bug may be hit first, preventing other bugs from being reproduced. 

A brief description of each bug is included below. 

- `NOVA_BUG1`: Reproducible with ACE seq1 tests. Can only be reproduced on a machine or VM with 1 CPU. Caused by an out-of-bounds access to an array during recovery, resulting in a kernel panic.
    - Example reproducing test: seq1/j-lang1
- `NOVA_BUG2`: Reproducible with ACE seq1 tests. Caused by a missing cache line flush. Causes an inode to be incorrectly marked invalid after a crash, leaving files in an inaccessible state. 
    - Example reproducing test: seq1/j-lang1
- `NOVA_BUG3`: Reproducible with ACE seq1 tests. Caused by incorrect handling of inode log pointers during recovery. Causes a kernel panic.
    - Example reproducing test: seq1/j-lang10
- `NOVA_BUG4`: Reproducible with ACE seq1 tests. Caused by deleting existing dentry in place during rename `rename()`. Causes file loss if the system crashes during `rename()`.
    - Example reproducing test: seq1/j-lang36
- `NOVA_BUG5`: Reproducible with ACE seq1 tests. Caused by excluding information about whether a file has been moved to a new directory from log entries. Causes a file do become inaccesible if the system crashes during `rename()`. In Chipmunk, this manifests as a bug report that the renamed file's parent directory cannot be deleted, even though Chipmunk recursively deletes all deletable files during its consistency checks.
    - Example reproducing test: seq1/j-lang39
- `NOVA_BUG6`: Reproducible with ACE seq2 tests. Caused by unsafe in-place update. Causes a target's link count to be incorrect after a crash.
- `NOVA_BUG7`: Reproducible only with fuzzer. Caused by incorrect log entry ordering when a file is modified via multiple file descriptors. Causes incorrect file size and potential data loss after a crash.
- `NOVA_BUG8`: Reproducible only with fuzzer. Caused by incorrect block number calcluation logic after modifying a file with `ftruncate` and `fallocate` via multiple file descriptors. Causes data loss.
- `NOVA_FORTIS_BUG1`: Reproducible with ACE seq1 tests. Caused by a missing fence that allows updates to primary and backup logs to be reordered incorrectly. Can manifest in multiple ways, depending on the crashing operation. For example, a crash during `unlink` or `rmdir` may leave a directory in a corrupted state where the `..` dentry is missing. 
    - Example reproducing test: seq1/j-lang26
- `NOVA_FORTIS_BUG2`: Reproducible with ACE seq1 tests. Caused by incorrect handling of primary and backup inode logs. Initializing these logs is not atomic with respect to crashes. If the system crashes with the primary initialized and the backup uninitialized, operations that require adding to the logs fail.
    - Example reproducing test: seq1/j-lang10
- `NOVA_FORTIS_BUG3`: Not fixed yet(?)
- `NOVA_FORTIS_BUG4`: Not fixed yet(?)
- `PMFS_BUG1`: Reproducible with ACE seq1 tests. Occurs because of a logic error where files that were being truncated during a crash are resolved before scanning FS metadata during recovery. This results in an access to lost volatile data, causing a null pointer dereference during recovery. Causes a kernel panic.
    - Example reproducing test: seq1/j-lang52 (TODO: I THINK! DOUBLE CHECK)
- `PMFS_BUG2`: TODO: requires seq2.
- `PMFS_BUG3`: Not fixed yet
- `PMFS_BUG4`: TODO: requires fuzzer.
- `WINEFS_BUG1`: Reproducible with ACE seq1 tests. Occurs because journals are not read correctly during recovery, resulting in corrupted directories or incorrect link counts.
    - Example reproducing test: seq1/j-lang1
- `WINEFS_BUG2`: TODO: requires seq2
- `WINEFS_BUG3`: TODO: requires fuzzer
- `WINEFS_BUG4`: Reproducible with ACE seq1 tests. Writing to a file may not be atomic with respect to crashes in strict mode. 
    - Example reproducing test: seq1/j-lang11
