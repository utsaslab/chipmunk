#
# Makefile for the linux NOVA filesystem routines.
#

obj-$(CONFIG_NOVA_FS) += nova.o
MY_CFLAGS += -g -DDEBUG -O1
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

nova-y := balloc.o bbuild.o checksum.o dax.o dir.o file.o gc.o inode.o ioctl.o \
	journal.o log.o mprotect.o namei.o parity.o rebuild.o snapshot.o stats.o \
	super.o symlink.o sysfs.o perf.o

# obj-m += nova.o
# MY_CFLAGS += -g -DDEBUG -O1
# ccflags-y += ${MY_CFLAGS}
# CC += ${MY_CFLAGS}

# nova-m := balloc.o bbuild.o checksum.o dax.o dir.o file.o gc.o inode.o ioctl.o \
# 	journal.o log.o mprotect.o namei.o parity.o rebuild.o snapshot.o stats.o \
# 	super.o symlink.o sysfs.o perf.o

# all:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
# 	EXTRA_CFLAGS="$(MY_CFLAGS)"


# clean:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean