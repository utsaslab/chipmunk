#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/irqflags.h>
#include <linux/delay.h>
#include <asm/io.h>
#include "logger.h"
#include "../executor/ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hayley LeBlanc");

struct kprobe_node* kp_memcpy_head = NULL;
struct kprobe_node* kp_flush_buffer_head = NULL;
struct kprobe_node* kp_persistent_barrier_head = NULL;
struct kprobe_node* kp_memset_nt_head = NULL;

unsigned long pm_start = 0x100000000;
unsigned long pm_size = 0x7ffffff;


module_init(logger_init);
module_exit(logger_exit);