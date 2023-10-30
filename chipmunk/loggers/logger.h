#ifndef LOGGER_H
#define LOGGER_H

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
#include "../executor/ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hayley LeBlanc");

#define CACHELINE_SIZE 64 // TODO: set dynamically?
#define FAIL -1
#define SUCCESS 0
#define DEVICE_NAME "ioctl_dummy"
#define NUM_KPROBE_ADDRS 32
static int major_num = 0;
static DEFINE_SPINLOCK(kprobe_lock);

unsigned long pm_start = 0x100000000;
unsigned long pm_size = 0x7ffffff;

int kprobe_fail = 0;

struct kprobe_node {
    struct kprobe_node* next;
    struct kprobe* kp;
};

int set_up_kprobes(
    unsigned long* kprobe_addrs, 
    struct kprobe_node* kp_head, 
    int (*pre_handler)(struct kprobe*, struct pt_regs*), 
    void (*post_handler)(struct kprobe*, struct pt_regs*, unsigned long flags));
int logger_ioctl(struct block_device* bdev, fmode_t mode, unsigned int cmd, unsigned long arg);
void log_dequeue(void);
void remove_from_tail(void);
int insert_mount_mark(void);
int insert_mark_sys(unsigned int sys, int end, long ret);
int insert_checkpoint(void);

struct ioctl_device {
    struct gendisk* ioctl_gd;
} ioctl_dev;

static const struct block_device_operations blkdev_ops = {
    .owner = THIS_MODULE,
    .ioctl = logger_ioctl,
};

struct write_log {
    struct write_op* head;
    struct write_op* tail;
    bool logging_on;
    bool undo;
} Log;

void free_kprobe_list(struct kprobe_node* kp_head) {
    struct kprobe_node* kp_cur;
    struct kprobe_node* kp_temp;

    kp_cur = kp_head;
    while (kp_cur) {
        kp_temp = kp_cur->next;
        unregister_kprobe(kp_cur->kp);
        kfree(kp_cur->kp);
        kfree(kp_cur);
        kp_cur = kp_temp;
    }
}

#endif
