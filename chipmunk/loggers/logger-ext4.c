#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/init.h>
#include <linux/genhd.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/irqflags.h>
#include <linux/delay.h>
#include <linux/uio.h>
#include "logger.h"
#include "../executor/ioctl.h"

// #define FAIL -1
// #define SUCCESS 0
// #define DEVICE_NAME "ioctl_dummy"
// #define NUM_KPROBE_ADDRS 32
// static int major_num = 0;
// // static DEFINE_SPINLOCK(kprobe_lock);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hayley LeBlanc");

struct kprobe_node* kp_write_pmem_head = NULL;
struct kprobe_node* kp_nvdimm_flush_head = NULL;
struct kprobe_node* kp_cache_wb_head = NULL;
struct kprobe_node* kp_pmem_copy_head = NULL;

unsigned long pm_start = 0x100000000;
unsigned long pm_end = 0x107ffffff;


unsigned long* kp_write_pmem_addrs;
unsigned long* kp_nvdimm_flush_addrs;
unsigned long* kp_cache_wb_addrs;
unsigned long* kp_pmem_copy_addrs;

static int __kprobes kp_write_pmem_pre_handler(struct kprobe* p, struct pt_regs *regs) {
    struct write_op* new_op;
    unsigned int ret, len, off, chunk;
    struct page *page;
    void *mem, *pmem_addr;
    struct stack_trace trace;
    // add an entry to the write log
    
    if (Log.logging_on && (unsigned long long)(virt_to_phys((void*)regs->di)) >= pm_start && (unsigned long long)(virt_to_phys((void*)regs->di)) < pm_end) {
        // imitate the loop that write_pmem does, since there isn't a good way to get all the data otherwise
        pmem_addr = (void*)regs->di;
        page = (struct page*)regs->si;
        off = (unsigned int)regs->dx;
        len = (unsigned int)regs->cx;
        while (len) {
            new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
            if  (new_op == NULL) {
                printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                kprobe_fail = 1;
                goto out;
            }

            new_op->next = NULL;
            new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
            if (new_op->metadata == NULL) {
                printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }

            // save call stack so we can determine where in the FS code the kprobe was hit
            trace.nr_entries = 0;
            trace.entries = &(new_op->metadata->trace_entries[0]);
            trace.max_entries = TRACE_SIZE;
            trace.skip = TRACE_SKIP;
            save_stack_trace(&trace);
            new_op->metadata->nr_entries = trace.nr_entries;

            // metadata takes a little work to get from write_pmem, but it's better to kprobe 
            // write_pmem than memcpy_flushcache (what it wraps) because memcpy_flushcache is always 
            // inlined (i.e. hard to probe correctly) and I don't think we want to make people go in and 
            // mess with parts of the kernel that aren't part of their fs if we can avoid it
            mem = kmap_atomic(page);
            chunk = min_t(unsigned int, len, PAGE_SIZE - off); 

            new_op->metadata->len = chunk;
            new_op->metadata->dst = (unsigned long long)pmem_addr;
            new_op->metadata->src = (unsigned long long)(mem + off);
            new_op->metadata->type = NT;

            // allocate space for the data
            new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
            if (new_op->data == NULL) {
                printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                kunmap_atomic(mem);
                kfree(new_op->metadata);
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }
            // copy the data to the log
            // this function ensures that faults are handled correctly when reading data 
            // that may be coming from user space
            ret = probe_kernel_read(new_op->data, (void*)new_op->metadata->src, new_op->metadata->len);
            if (ret < 0) {
                kunmap_atomic(mem);
                kfree(new_op->metadata);
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }
            kunmap_atomic(mem);

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

            // update the variables that let us read stuff
            len -= chunk;
            off = 0;
            page++;
            pmem_addr += chunk;
        }
    }

    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed during Kprobe handling of write_pmem\n");
        return SUCCESS; // not really a success but we probably don't want to stop the operation entirely
    
}

static int __kprobes kp_nvdimm_flush_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct write_op* new_op;
    struct stack_trace trace;

    if (Log.logging_on) {
        new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
        if (new_op == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry\n");
            kprobe_fail = 1;
            goto out;
        }

        new_op->next = NULL;
        new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
        if (new_op->metadata == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
            kfree(new_op);
            kprobe_fail = 1;
            goto out;
        }

        // save call stack so we can determine where in the FS code the kprobe was hit
        trace.nr_entries = 0;
        trace.entries = &(new_op->metadata->trace_entries[0]);
        trace.max_entries = TRACE_SIZE;
        trace.skip = TRACE_SKIP;
        save_stack_trace(&trace);
        new_op->metadata->nr_entries = trace.nr_entries;

        // no data is logged here 
        // just need to take note that this is an SFENCE instruction
        new_op->metadata->dst = 0;
        new_op->metadata->src = 0;
        new_op->metadata->len = 0;
        new_op->metadata->type = SFENCE;

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
        printk(KERN_INFO "logger: failed during Kprobe handling of nvdimm_flush\n");
        return SUCCESS;
}

static int __kprobes kp_cache_wb_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct write_op* new_op;
    int ret;
    struct stack_trace trace;
    unsigned long long mod64, start, len;
    start = (unsigned long long)(virt_to_phys((void*)regs->di));
    if (Log.logging_on && start >= pm_start && start < pm_end) {
        len = regs->si;
        // if the start address is not on a cacheline boundary, move it back to 
        // one and increase the length of the write accordingly
        mod64 = start % CACHELINE_SIZE;
        if (mod64 != 0) {
            start -= mod64;
            len += mod64;
        }
        // if the length of the write is not divisible by the cache line size, 
        // we need to make sure we copy out the whole last cache line that it touches
        if (len % CACHELINE_SIZE != 0) {
            len += CACHELINE_SIZE - (len % CACHELINE_SIZE);
        }
        new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
        if (new_op == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry\n");
            kprobe_fail = 1;
            goto out;
        }

        new_op->next = NULL;
        new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
        if (new_op->metadata == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
            kfree(new_op);
            kprobe_fail = 1;
            goto out;
        }

        // save call stack so we can determine where in the FS code the kprobe was hit
        trace.nr_entries = 0;
        trace.entries = &(new_op->metadata->trace_entries[0]);
        trace.max_entries = TRACE_SIZE;
        trace.skip = TRACE_SKIP;
        save_stack_trace(&trace);
        new_op->metadata->nr_entries = trace.nr_entries;

        // copy metadata to log entry
        // here, source and destination are the same
        new_op->metadata->len = len;
        new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)regs->di));
        new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)regs->di));
        new_op->metadata->type = CLWB;


        // allocate space for the data
        new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
        if (new_op->data == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
            kfree(new_op->metadata);
            kfree(new_op);
            kprobe_fail = 1;
            goto out;
        }

        // copy the data to the log
        ret = probe_kernel_read(new_op->data, (void*)regs->di, new_op->metadata->len);
        if (ret < 0) {
            printk(KERN_ALERT "logger: could not read data\n");
            kprobe_fail = 1;
            goto out;
        }

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
        printk(KERN_INFO "logger: failed during Kprobe handling of arch_wb_cache_pmem\n");
        return SUCCESS;
}

static int __kprobes kp_pmem_copy_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct write_op* new_op;
    int ret;
    struct stack_trace trace;
    struct iov_iter iter;

    // TODO: this one might be more correct to be in a loop as well
    
    if (Log.logging_on && (unsigned long long)(virt_to_phys((void*)regs->dx)) >= pm_start && (unsigned long long)(virt_to_phys((void*)regs->dx)) < pm_end) {
        
        new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
        if (new_op == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry\n");
            kprobe_fail = 1;
            goto out;
        }

        new_op->next = NULL;
        new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
        if (new_op->metadata == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
            kfree(new_op);
            kprobe_fail = 1;
            goto out;
        }

        new_op->metadata->type = NT;

        // save call stack so we can determine where in the FS code the kprobe was hit
        trace.nr_entries = 0;
        trace.entries = &(new_op->metadata->trace_entries[0]);
        trace.max_entries = TRACE_SIZE;
        trace.skip = TRACE_SKIP;
        save_stack_trace(&trace);
        new_op->metadata->nr_entries = trace.nr_entries;

        new_op->metadata->len = regs->cx;
        new_op->metadata->dst = regs->dx; 


        // allocate space for the data
        new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
        if (new_op->data == NULL) {
            printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
            kfree(new_op->metadata);
            kfree(new_op);
            kprobe_fail = 1;
            goto out;
        }

        ret = probe_kernel_read(&iter, (void*)regs->r8, sizeof(struct iov_iter));
        if (ret < 0) {
            kprobe_fail = 1;
            goto out;
        }
        ret = copy_from_iter_flushcache(new_op->data, new_op->metadata->len, &iter);
        if (ret < 0) {
            kprobe_fail = 1;
            goto out;
        }

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
        printk(KERN_INFO "logger: failed during Kprobe handling of pmem_copy\n");
        return SUCCESS;
}

void free_addrs(void) {
    kfree(kp_write_pmem_addrs);
    kfree(kp_nvdimm_flush_addrs);
    kfree(kp_cache_wb_addrs);
    kfree(kp_pmem_copy_addrs);
}

static int kp_write_pmem_index = 0;
static int find_write_pmem_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "write_pmem", strlen("write_pmem")) == 0) {
        ((unsigned long*)data)[kp_write_pmem_index] = address;
        kp_write_pmem_index++;
    }
    return 0;
}

static int kp_nvdimm_flush_index = 0;
static int find_nvdimm_flush_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "nvdimm_flush", strlen("nvdimm_flush")) == 0) {
        ((unsigned long*)data)[kp_nvdimm_flush_index] = address;
        kp_nvdimm_flush_index++;
    }
    return 0;
}

static int kp_cache_wb_index = 0;
static int find_cache_wb_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "arch_wb_cache_pmem", strlen("arch_wb_cache_pmem")) == 0) {
        ((unsigned long*)data)[kp_cache_wb_index] = address;
        kp_cache_wb_index++;
    }
    return 0;
}

static int kp_pmem_copy_index = 0;
static int find_pmem_copy_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "pmem_copy_from_iter", strlen("pmem_copy_from_iter")) == 0) {
        ((unsigned long*)data)[kp_pmem_copy_index] = address;
        kp_pmem_copy_index++;
    }
    return 0;
}

static int __init logger_init(void) {
    struct write_op* first = NULL;
    int ret;

    kp_write_pmem_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (kp_write_pmem_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory for kprobe addresses\n");
        return -1;
    }

    kp_nvdimm_flush_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (kp_nvdimm_flush_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory for kprobe addresses\n");
        kfree(kp_write_pmem_addrs);
        return -1;
    }

    kp_cache_wb_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (kp_cache_wb_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory for kprobe addresses\n");
        kfree(kp_write_pmem_addrs);
        kfree(kp_nvdimm_flush_addrs);
        return -1;
    }

    kp_pmem_copy_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (kp_pmem_copy_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory for kprobe addresses\n");
        kfree(kp_write_pmem_addrs);
        kfree(kp_nvdimm_flush_addrs);
        kfree(kp_cache_wb_addrs);
        return -1;
    }

    kallsyms_on_each_symbol(find_write_pmem_addrs, kp_write_pmem_addrs);
    kallsyms_on_each_symbol(find_nvdimm_flush_addrs, kp_nvdimm_flush_addrs);
    kallsyms_on_each_symbol(find_cache_wb_addrs, kp_cache_wb_addrs);
    kallsyms_on_each_symbol(find_pmem_copy_addrs, kp_pmem_copy_addrs);

    kp_write_pmem_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_write_pmem_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_addrs();
        return -ENOMEM;
    }
    ret = set_up_kprobes(kp_write_pmem_addrs, kp_write_pmem_head, kp_write_pmem_pre_handler, NULL
    );
    if (ret < 0) {
        free_kprobe_list(kp_write_pmem_head);
        free_addrs();
        return ret;
    }

    kp_nvdimm_flush_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_nvdimm_flush_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_write_pmem_head);
        // free_kprobe_list(kp_nvdimm_flush_head);
        free_addrs();
        return -ENOMEM;
    }
    ret = set_up_kprobes(kp_nvdimm_flush_addrs, kp_nvdimm_flush_head, kp_nvdimm_flush_pre_handler, NULL);
    if (ret < 0) {
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        free_addrs();
        return ret;
    }

    kp_cache_wb_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_cache_wb_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        // free_kprobe_list(kp_cache_wb_head);
        free_addrs();
        return -ENOMEM;
    }
    ret = set_up_kprobes(kp_cache_wb_addrs, kp_cache_wb_head, kp_cache_wb_pre_handler, NULL);
    if (ret < 0) {
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        free_kprobe_list(kp_cache_wb_head);
        free_addrs();
        return ret;
    }

    kp_pmem_copy_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_pmem_copy_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        free_kprobe_list(kp_cache_wb_head);
        free_addrs();
        return -ENOMEM;
    }
    ret = set_up_kprobes(kp_pmem_copy_addrs, kp_pmem_copy_head, kp_pmem_copy_pre_handler, NULL);
    if (ret < 0) {
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        free_kprobe_list(kp_cache_wb_head);
        free_kprobe_list(kp_pmem_copy_head);
        free_addrs();
        return ret;
    }


    spin_lock(&kprobe_lock);
    Log.head = NULL;
    Log.tail = NULL;
    spin_unlock(&kprobe_lock);
    Log.logging_on = true; // TODO: change to false when done testing

    // create device for user processes to interact with this module via IOCTL
    // register the device
    major_num = register_blkdev(major_num, DEVICE_NAME);
    if (major_num <= 0) {
        printk(KERN_ALERT "logger: unable to register IOCTL device\n");
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        free_kprobe_list(kp_cache_wb_head);
        free_addrs();
        return FAIL;
    }
    // note to self: this device does NOT wrap anything because we can't wrap /dev/pmem0; it's just a standalone dummy device for communication 
    // w/ user processes
    
    ioctl_dev.ioctl_gd = alloc_disk(1);
    if (!ioctl_dev.ioctl_gd) {
        printk(KERN_ALERT "logger: failed to allocate gendisk\n");
        unregister_blkdev(major_num, DEVICE_NAME);
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        free_kprobe_list(kp_cache_wb_head);
        free_addrs();
        return FAIL;
    }

    // set up other stuff in the device
    // this may or may not be necessary since this device isn't actually going to do much
    ioctl_dev.ioctl_gd->private_data = &ioctl_dev;
    ioctl_dev.ioctl_gd->major = major_num;
    ioctl_dev.ioctl_gd->fops = &blkdev_ops;
    strcpy(ioctl_dev.ioctl_gd->disk_name, DEVICE_NAME);

    // get a request queue and set it up
    ioctl_dev.ioctl_gd->queue = blk_alloc_queue(GFP_KERNEL);
    if (ioctl_dev.ioctl_gd->queue == NULL) {
        printk(KERN_ALERT "logger: unable to allocate device request queue\n");
        del_gendisk(ioctl_dev.ioctl_gd);
        unregister_blkdev(major_num, DEVICE_NAME);
        free_kprobe_list(kp_write_pmem_head);
        free_kprobe_list(kp_nvdimm_flush_head);
        free_kprobe_list(kp_cache_wb_head);
        free_addrs();
        return FAIL;
    }
    // TODO: do we have to set a custom queue request function if we won't actually be using the queue?
    ioctl_dev.ioctl_gd->queue->queuedata = &ioctl_dev;

    // actually add the disk
    add_disk(ioctl_dev.ioctl_gd);

    return SUCCESS;
}

static void __exit logger_exit(void) {
    struct write_op* cur;
    struct write_op* temp;

    printk(KERN_INFO "logger exit\n");

    free_kprobe_list(kp_write_pmem_head);
    free_kprobe_list(kp_nvdimm_flush_head);
    free_kprobe_list(kp_cache_wb_head);
    free_kprobe_list(kp_pmem_copy_head);
    free_addrs();

    printk(KERN_INFO "freed kprobes and addrs\n");

    spin_lock(&kprobe_lock);
    // clean up log
    cur = Log.head;
    while (cur) {
        temp = cur->next;
        kfree(cur->metadata);
        kfree(cur->data);
        kfree(cur);
        cur = temp;
    }
    spin_unlock(&kprobe_lock);

    printk(KERN_INFO "freed log\n");

    // delete and unregister the dummy device used for ioctl
    del_gendisk(ioctl_dev.ioctl_gd);
    put_disk(ioctl_dev.ioctl_gd);
    unregister_blkdev(major_num, DEVICE_NAME);
}

static void log_dequeue(void) {
    struct write_op* temp;
    // lock is already held
    temp = Log.head;
    Log.head = Log.head->next;
    kfree(temp->data);
    kfree(temp->metadata);
    kfree(temp);
    
}

static int insert_mount_mark(void) {
    struct write_op* new_op;

    if (Log.logging_on) {
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

        new_op->metadata->nr_entries = 0;

        // no data is logged here 
        // just need to take note that the FS has been mounted
        new_op->metadata->dst = 0;
        new_op->metadata->src = 0;
        new_op->metadata->len = 0;
        new_op->metadata->type = MARK;

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

// this function will NOT be combined with the other pre-handlers because it needs to be handled separately
// even though it looks very similar to them
static int insert_checkpoint(void) {
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

static int logger_ioctl(struct block_device* bdev, fmode_t mode, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    unsigned int failed = 0;
    unsigned int not_copied;
    unsigned int offset;
    struct write_op* cur;
    struct write_op* temp;

    switch (cmd) {
        // pass the metadata about an operation (source and destination addresses, address where the module stored the data) to the user
        case LOGGER_GET_OP:
            // update_nmissed();
            spin_lock(&kprobe_lock);
            // ensure that we have an operation to give the user process
            if (Log.head == NULL) {
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
                return -ENODATA;
            }
            if (!access_ok((void*)arg, Log.head->metadata->len)) {
                printk(KERN_ALERT "logger: invalid user address\n");
                spin_unlock(&kprobe_lock);
                return -EFAULT;
            }
            not_copied = Log.head->metadata->len;
            while(not_copied != 0) {
                offset = Log.head->metadata->len - not_copied;
                not_copied = copy_to_user((void*)(arg+offset), Log.head->data+offset, not_copied);
            }
            ret = Log.head->metadata->len;
            spin_unlock(&kprobe_lock);
            break;
        case LOGGER_NEXT_OP:
            spin_lock(&kprobe_lock);
            if (Log.head == NULL) {
                printk(KERN_ALERT "No logged data available\n");
                spin_unlock(&kprobe_lock);
                return -ENODATA;
            }
            // dequeue and free the log head, moving the log head to the next operation 
            log_dequeue();
            if (Log.head == NULL) {
                printk(KERN_INFO "logger: reached end of log\n");
                spin_unlock(&kprobe_lock);
                return -ENODATA;
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
            // this is wrong - there's a dummy at the head isn't there
            Log.head = NULL;
            Log.tail = NULL;
            spin_unlock(&kprobe_lock);
            break;
        case LOGGER_CHECK_MISSED:
            // if something went wrong in a probe (it was missed, or there was a fault 
            // that prevented us from copying data in from the file system), tell the 
            // test harness so it can handle it appropriately
            failed = check_failure();
            return failed;
        case LOGGER_MARK:
            ret = insert_mount_mark();
            break;
    }
    return ret;
}

module_init(logger_init);
module_exit(logger_exit);
