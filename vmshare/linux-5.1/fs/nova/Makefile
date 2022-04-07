#
# Makefile for the linux NOVA filesystem routines.
#

# can build nova from top level kernel directory using `make fs/nova/nova.ko`

obj-$(CONFIG_NOVA_FS) += nova.o
MY_CFLAGS += -g -DDEBUG -O1
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

nova-y := balloc.o bbuild.o checksum.o dax.o dir.o file.o gc.o inode.o ioctl.o \
	journal.o log.o mprotect.o namei.o parity.o rebuild.o snapshot.o stats.o \
	super.o symlink.o sysfs.o perf.o
