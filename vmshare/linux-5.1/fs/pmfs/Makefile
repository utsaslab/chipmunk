#
# Makefile for the linux pmfs-filesystem routines.
#

obj-$(CONFIG_PMFS) += pmfs.o
MY_CFLAGS += -g -DDEBUG -O1
ccflags-y = ${MY_CFLAGS}
CC += ${MY_CFLAGS}

pmfs-y := bbuild.o balloc.o dir.o file.o inode.o namei.o super.o symlink.o ioctl.o pmfs_stats.o journal.o xip.o wprotect.o

#all:
#	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

#clean:
#	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
