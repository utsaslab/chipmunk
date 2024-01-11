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

unsigned long long pm_start = 0x100000000;
unsigned long long pm_size = 0x7ffffff;

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

static int check_failure(void) {
    if (kprobe_fail) {
        printk(KERN_INFO "A memcpy from userspace failed, so this test is unreliable\n");
        return -1;
    }
    return 0;
}

int set_up_kprobes(unsigned long* kprobe_addrs, struct kprobe_node* kp_head, int (*pre_handler)(struct kprobe*, struct pt_regs*), void (*post_handler)(struct kprobe*, struct pt_regs*, unsigned long flags)) {
    int i;
    int ret;
    struct kprobe_node* cur = NULL;

    // go through the list of addresses and register a kprobe for each one
    for (i = 0; i < NUM_KPROBE_ADDRS; i++) {
        if (kprobe_addrs[i] != 0) {
            // if kp_head is null, fill it in
            if (kp_head->kp == NULL) {
                kp_head->kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
                if (kp_head->kp == NULL) {
                    printk(KERN_ALERT "logger: unable to allocate space for kprobe node head\n");
                    return -ENOMEM;
                }
                kp_head->next = NULL;
                kp_head->kp->addr = (kprobe_opcode_t*)kprobe_addrs[i];
                kp_head->kp->pre_handler = pre_handler;
                kp_head->kp->post_handler = post_handler;

                ret = register_kprobe(kp_head->kp);
                if (ret < 0) {
                    printk(KERN_ALERT "logger: register_kprobe failed, returned %d\n", ret);
                    return ret;
                }
                cur = kp_head;
            }   
            // else, create a new kprobe node
            else {
                // allocate new kprobe node
                struct kprobe_node* new_kp = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
                if (new_kp == NULL) {
                    printk(KERN_ALERT "logger: unable to allocate space for new kprobe node\n");
                    return -ENOMEM;
                }
                // allocate space for its kprobe
                new_kp->kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
                if (new_kp->kp == NULL) {
                    printk(KERN_ALERT "logger: unable to allocate space for new kprobe\n");
                    return -ENOMEM;
                }
                new_kp->kp->addr = (kprobe_opcode_t*)kprobe_addrs[i];
                new_kp->kp->pre_handler = pre_handler;
                new_kp->kp->post_handler = NULL;

                ret = register_kprobe(new_kp->kp);
                if (ret < 0) {
                    printk(KERN_ALERT "logger: register_kprobe failed, returned %d\n", ret);
                    return ret;
                }
                cur->next = new_kp;
                cur = new_kp;
                new_kp->next = NULL;
            }
        }
    }
    
    return SUCCESS;
}

int logger_ioctl(struct block_device* bdev, fmode_t mode, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    unsigned int missed = 0;
    unsigned int not_copied;
    unsigned int offset;
    struct write_op* cur;
    struct write_op* temp;

    switch (cmd) {
        // pass the metadata about an operation (source and destination addresses, address where the module stored the data) to the user
        case LOGGER_GET_OP:
            // printk(KERN_ALERT "log get op\n");
            // printk(KERN_ALERT "log head 1: %p", Log.head);
            // update_nmissed();
            spin_lock(&kprobe_lock);
            // ensure that we have an operation to give the user process
            if (Log.head == NULL) {
                // printk(KERN_ALERT "log head 2: %p", Log.head);
                printk(KERN_ALERT "logger: no logged data available\n");
                spin_unlock(&kprobe_lock);
                return -ENODATA;
            }
            // check that the provided user address to copy the metadata to is valid
            if (!access_ok((void*)arg, sizeof(struct op_metadata))) {
                printk(KERN_ALERT "logger: invalid user address\n");
                spin_unlock(&kprobe_lock);
                return -EFAULT;
            }
            // copy data to the user process
            not_copied = sizeof(struct op_metadata);
            while (not_copied != 0) {
                offset = sizeof(struct op_metadata) - not_copied;
                not_copied = copy_to_user((void*)(arg+offset), Log.head->metadata + offset, not_copied);
            }
            spin_unlock(&kprobe_lock);
        ret = sizeof(struct op_metadata);
            break;

        // pass data associated with current copy operation to the user
        case LOGGER_GET_DATA:
            spin_lock(&kprobe_lock);
            if (Log.head == NULL) {
                printk(KERN_ALERT "logger: no logged data available\n");
                spin_unlock(&kprobe_lock);
                return -ENOENT;
            }
            if (!access_ok((void*)arg, Log.head->metadata->len)) {
                printk(KERN_ALERT "logger: invalid user address\n");
                spin_unlock(&kprobe_lock);
                return -EFAULT;
            }
            not_copied = Log.head->metadata->len;
            if (Log.head != NULL) {
                while(not_copied != 0) {
                    offset = Log.head->metadata->len - not_copied;
                    not_copied = copy_to_user((void*)(arg+offset), Log.head->data+offset, not_copied);
                }
                ret = Log.head->metadata->len;
            }
            else {
                ret = -ENODATA;
            }
            spin_unlock(&kprobe_lock);
            break;
        case LOGGER_NEXT_OP:
            // printk(KERN_ALERT "Logger next op\n");
            spin_lock(&kprobe_lock);
            if (Log.head == NULL) {
                printk(KERN_ALERT "No logged data available\n");
                spin_unlock(&kprobe_lock);
                return -ENODATA;
            }
            // printk(KERN_ALERT "log still has stuff in it %p\n", Log.head);
            // dequeue and free the log head, moving the log head to the next operation 
            log_dequeue();
            if (Log.head == NULL) {
                printk(KERN_INFO "logger: reached end of log\n");
                spin_unlock(&kprobe_lock);
                return -ENODATA;
            }
            else {
                // printk(KERN_ALERT "log still has stuff in it %p\n", Log.head);
            }
            spin_unlock(&kprobe_lock);
            break;
        case LOGGER_LOG_ON:
            printk(KERN_INFO "logger: turning logging on\n");
            Log.logging_on = true;
            break;
        case LOGGER_LOG_OFF:
            printk(KERN_INFO "logger: turning logging off\n");
            Log.logging_on = false;
            break;
        case LOGGER_CHECKPOINT:
            ret = insert_checkpoint();
            break;
        case LOGGER_FREE_LOG:
            // TODO: check that logging is off before doing this?
            // free all the logged writes in the log. does NOT unregister 
            // kprobes or free any data associated with them 
            spin_lock(&kprobe_lock);
            cur = Log.head;
            while (cur) {
                temp = cur->next;
                kfree(cur->metadata);
                kfree(cur->data);
                kfree(cur);
                cur = temp;
            }
            Log.head = NULL;
            Log.tail = NULL;
            spin_unlock(&kprobe_lock);
            break;
        case LOGGER_CHECK_MISSED:
            // if something went wrong in a probe (it was missed, or there was a fault 
            // that prevented us from copying data in from the file system), tell the 
            // test harness so it can handle it appropriately
            missed = check_failure();
            kprobe_fail = 0; // reset kprobe_fail to 0 so we can continue without reloading the module
            return missed;
        case LOGGER_MARK_SYS:
            ret = insert_mark_sys(arg, 0, 1);
            break;
        case LOGGER_MARK_SYS_END:
            ret = insert_mark_sys(0, 1, (long) arg);
            break;
        case LOGGER_MARK:
            ret = insert_mount_mark();
            break;
        case LOGGER_UNDO_ON:
            Log.undo = true;
            break;
        case LOGGER_UNDO_OFF:
            Log.undo = false;
            break;
        case LOGGER_SET_PM_START:
            pm_start = arg;
            break;
    }
    return ret;
}

void log_dequeue(void) {
    struct write_op* temp;
    // lock is already held
    temp = Log.head;
    Log.head = Log.head->next;
    kfree(temp->data);
    kfree(temp->metadata);
    kfree(temp);
}


void remove_from_tail(void) {
    struct write_op* temp;
    temp = Log.tail;
    Log.tail = temp->prev;
    Log.tail->next = NULL;
    kfree(temp->data);
    kfree(temp->metadata);
    kfree(temp);
}


int insert_mount_mark(void) {
    struct write_op* new_op;

    if (Log.logging_on) {
        // printk(KERN_INFO "BEGINNING OF TESTED SYSTEM CALL\n");
        new_op = kzalloc(sizeof(struct write_op), GFP_KERNEL);
        // new_kp->kp = kzalloc(sizeof(struct kprobe), GFP_NOWAIT);
        if (new_op == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry\n");
            goto out;
        }
        new_op->next = NULL;
        new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_KERNEL);
        // new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
        if (new_op->metadata == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
            kfree(new_op);
            goto out;
        }

        // no data is logged here 
        // just need to take note that the FS has been mounted
        new_op->metadata->dst = 0;
        new_op->metadata->src = 0;
        new_op->metadata->len = 0;
        new_op->metadata->type = MARK;
        new_op->metadata->pid = current->pid;

        spin_lock(&kprobe_lock);
        if (Log.tail != NULL) {
            Log.tail->next = new_op;
            Log.tail = new_op;
        }
        else {
            Log.tail = new_op;
        }
        if (Log.head == NULL) {
            Log.head = new_op;
        }
        spin_unlock(&kprobe_lock);
    }

    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed to record checkpoint in log\n");
        return FAIL;
}

int insert_mark_sys(unsigned int sys, int end, long ret) {
    struct write_op* new_op;

    if (Log.logging_on) {
        new_op = kzalloc(sizeof(struct write_op), GFP_KERNEL);
        if (new_op == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry\n");
            goto out;
        }
        new_op->next = NULL;
        new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_KERNEL);

        if (new_op->metadata == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
            kfree(new_op);
            goto out;
        }

        // no data is logged here 
        // just need to take note that the FS has been mounted
        new_op->metadata->dst = 0;
        new_op->metadata->src = 0;
        new_op->metadata->len = 0;
        new_op->metadata->type = (end > 0) ? MARK_SYS_END : MARK_SYS;
	if (!end)
		new_op->metadata->sys = sys;
	if (end)
		new_op->metadata->sys_ret = ret;
        new_op->metadata->pid = current->pid;

        spin_lock(&kprobe_lock);
        if (Log.tail != NULL) {
            Log.tail->next = new_op;
            Log.tail = new_op;
        }
        else {
            Log.tail = new_op;
        }
        if (Log.head == NULL) {
            Log.head = new_op;
            if (Log.head == NULL) {
            }
        }
        spin_unlock(&kprobe_lock);
    }

    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed to record checkpoint in log\n");
        return FAIL;
}

int insert_checkpoint(void) {
    struct write_op* new_op;

    if (Log.logging_on) {
        // printk(KERN_INFO "CHECKPOINT\n");
        new_op = kzalloc(sizeof(struct write_op), GFP_KERNEL);
        // new_kp->kp = kzalloc(sizeof(struct kprobe), GFP_NOWAIT);
        if (new_op == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry\n");
            goto out;
        }
        new_op->next = NULL;
        new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_KERNEL);
        // new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
        if (new_op->metadata == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
            kfree(new_op);
            goto out;
        }

        // no data is logged here 
        // just need to take note that this is a checkpoint
        new_op->metadata->dst = 0;
        new_op->metadata->src = 0;
        new_op->metadata->len = 0;
        new_op->metadata->type = CHECKPOINT;
        new_op->metadata->pid = current->pid;

        spin_lock(&kprobe_lock);
        if (Log.tail != NULL) {
            Log.tail->next = new_op;
            Log.tail = new_op;
        }
        else {
            Log.tail = new_op;
        }
        if (Log.head == NULL) {
            Log.head = new_op;
        }
        spin_unlock(&kprobe_lock);
    }

    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed to record checkpoint in log\n");
        return FAIL;

    // return SUCCESS;
}

#endif
