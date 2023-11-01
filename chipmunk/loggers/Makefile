KERNEL_VERSION := $(shell uname -r)

GCC = gcc
DEBUG_FLAGS += -g -DDEBUG
GOPTS = -std=c++11
GOTPSSO = -shared -fPIC

# TODO: maybe build the loggers in the same location as other syzkaller binaries
# instead of in their own build directory. that will also require updating where 
# we look for the built module in the code
BUILD_DIR = $(CURDIR)/../bin/linux_amd64/loggers

MODULES = logger-nova logger-pmfs logger-ext4 logger-winefs logger-squirrelfs
obj-m := $(addsuffix .o, $(MODULES))

# THIS SHOULD BE THE PATH TO YOUR LOCAL LINUX SOURCE
# it must have been built
KDIR := $(CURDIR)/../../vmshare/linux-6.3/
# KDIR := $(HOME)/shared/linux-5.1/
.PHONY: all clean

all: \
	$(foreach MOD, $(MODULES), $(addsuffix .c, $(MOD))) \
		$(BUILD_DIR)/Makefile
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) src=$(CURDIR) LLVM=-14 modules
	EXTRA_CFLAGS="$(CFLAGS)"

clean: \
	rm -rf build

$(BUILD_DIR)/Makefile:
	mkdir -p $(BUILD_DIR)
	touch "$@"
