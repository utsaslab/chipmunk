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
#include "logger.h"
#include "../executor/ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hayley LeBlanc");

struct kprobe_node* kp_memcpy_head = NULL;
struct kprobe_node* kp_flush_buffer_head = NULL;
struct kprobe_node* kp_persistent_barrier_head = NULL;
struct kprobe_node* kp_memset_nt_head = NULL;

unsigned long long seq_num;

// unsigned long pm_start = 0x100000000;
// // unsigned long pm_end = 0x13fffffff;
// unsigned long pm_end = 0x107ffffff;
unsigned long pm_start = 0x100000000;
// unsigned long pm_end = 0x13fffffff;
// unsigned long pm_end = 0x107ffffff;
unsigned long pm_size = 0x7ffffff;

module_param(pm_start, long, 0);
MODULE_PARM_DESC(pm_start, "pm_start is an unsigned long indicating the physical address of the beginning of the PM device\n");
module_param(pm_size, long, 0);
MODULE_PARM_DESC(pm_size, "pm_size is an unsigned long indicating the size of the PM device\n");


// TODO: IMPORTANT!! if the system has CLWB support,
// THIS FUNCTION CALLS FLUSH BUFFER. qemu does not seem 
// to have CLWB support but if this could ever run somewhere 
// that does, you need to be aware of it
// static int __kprobes memcpy_to_nvmm_pre_handler(struct kprobe *p, struct pt_regs *regs) {
//     int ret;
//     unsigned long long len, to_write, offset, start, data_offset;
//     struct stack_trace trace;
//     struct write_op* new_op;
//     offset = regs->si;
//     start = (unsigned long long)(virt_to_phys((void*)regs->di));
//     len = (unsigned long long)regs->cx;
//     // we won't break this write up into cache lines,
//     // because this function is only used for data writes
//     // in PMFS
    
//     if (Log.logging_on && (start+offset) >= pm_start && (start+offset) < pm_end) {
//         data_offset = 0;

//         // if len is greater than the size of the start address to the end of the 
//         // PM device, reduce it to that size. This will prevent weird errors
//         // if the fuzzer provides a super big buffer or file write count
//         // start address - end of PM address = amount of data we can write 
//         // without overflowing the PM device
//         unsigned long long bytes_left = start - (pm_start+pm_size);
//         if (bytes_left < len) {
//             len = bytes_left;
//         }
            

//         // printk(KERN_ALERT "memcpy to nvmm\n");
//         while (len > 0) {
//             new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
//             if  (new_op == NULL) {
//                 printk(KERN_ALERT "logger: could not allocate space for log entry\n");
//                 kprobe_fail = 1;
//                 goto out;
//             }

//             new_op->next = NULL;
//             new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
//             if (new_op->metadata == NULL) {
//                 printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
//                 kfree(new_op);
//                 kprobe_fail = 1;
//                 goto out;
//             }

//             // save call stack so we can determine where in the FS code the kprobe was hit
//             trace.nr_entries = 0;
//             trace.entries = &(new_op->metadata->trace_entries[0]);
//             trace.max_entries = TRACE_SIZE;
//             trace.skip = TRACE_SKIP;
//             save_stack_trace(&trace);
//             new_op->metadata->nr_entries = trace.nr_entries;

//             // to_write = len < 4096 ? len : 4096;
//             // len -= to_write;
//             to_write = len < (4 << 20) ? len : (4 << 20);
//             len -= to_write;

//             // copy metadata to the log entry
//             // new_op->metadata->len = (unsigned long long)regs->cx;
//             new_op->metadata->len = to_write;
//             // printk(KERN_ALERT "len: %lu\n", regs->cx);
//             // printk(KERN_ALERT "len: %llu\n", new_op->metadata->len);
//             new_op->metadata->dst = start + offset + data_offset;
//             new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)regs->dx)) + data_offset;
//             new_op->metadata->type = NT;
//             new_op->metadata->likely_data = 1;
//             new_op->metadata->seq_num = seq_num;

//             // allocate space for the data
//             new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
//             if (new_op->data == NULL) {
//                 printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
//                 kfree(new_op->metadata);
//                 kfree(new_op);
//                 kprobe_fail = 1;
//                 goto out;
//             }

//             // // copy the data to the log
//             // // this function ensures that faults are handled correctly when reading data from user space
//             ret = probe_kernel_read(new_op->data, (void*)(regs->dx), new_op->metadata->len);
//             if (ret < 0) {
//                 // if the write is less than the size of a page,
//                 // just try again
//                 if (new_op->metadata->len < 4096) {
//                     ret = probe_kernel_read(new_op->data, (void*)(regs->dx), new_op->metadata->len);
//                     if (ret < 0) {
//                         // if it still fails, fail the test
//                             printk(KERN_ALERT "A PROBE KERNEL READ IN MEMCPY FAILED\n");
//                             printk(KERN_ALERT "could not read data in memcpy_to_nvmm\n");
//                             kprobe_fail = 1;
//                             goto out;
//                     }
//                 }
//                 else {
//                     unsigned long long offset2 = 0;
//                     unsigned long long len2 = new_op->metadata->len;
//                     unsigned long long to_write2 = 0;
//                     while (len2 > 0) {
//                         to_write2 = len2 < 4096 ? len2 : 4096;
//                         len2 -= to_write2;

//                         ret = probe_kernel_read(new_op->data+offset2, (void*)(regs->dx + offset2), to_write2);
//                         if (ret < 0) {
//                             // try one more time
//                             ret = probe_kernel_read(new_op->data+offset2, (void*)(regs->dx + offset2), to_write2);
//                             // TODO: what to do if it fails a second time?
//                         }
//                         offset2 += to_write2;
//                     }
//                 }
//             }

//             data_offset += to_write;

//             spin_lock(&kprobe_lock);
//             if (Log.tail != NULL) {
//                 Log.tail->next = new_op;
//                 Log.tail = new_op;
//             }
//             else {
//                 Log.tail = new_op;
//             }
//             if (Log.head == NULL) {
//                 Log.head = new_op;
//             }
//             spin_unlock(&kprobe_lock);
//         }
//     }

//     seq_num++;

//     return SUCCESS;

//     out:
//         printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
//         printk(KERN_INFO "logger: failed during Kprobe handling of memcpy_to_nvmm\n");
//         return SUCCESS; // not really a success but we probably don't want to stop the memcpy operation entirely
// }


// 1st arg: part of dst addr - di
// 2nd arg: part of dst addr. Dst is 1st arg + 2nd arg - si
// 3rd arg: source buffer - dx
// 4th arg: size - cx
static int __kprobes memcpy_to_nvmm_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    int ret;
    short likely_data = 0;
    unsigned long long len, to_write, data_offset;
    unsigned long long offset = regs->si;
    struct write_op* new_op;
    struct stack_trace trace;
    unsigned long long start = (unsigned long long)(virt_to_phys((void*)regs->di));
    unsigned long long dest = start + offset;
    printk(KERN_ALERT "memcpy to nvmm pre handler\n");
    // add an entry to the write log
    if (Log.logging_on && start >= pm_start && start < (pm_start + pm_size)) {
        len = regs->cx;
        printk(KERN_ALERT "MEMCPY OF SIZE %lld\n", len);
        data_offset = 0;

        // if len is greater than the size of the start address to the end of the 
        // PM device, reduce it to that size. This will prevent weird errors
        // if the fuzzer provides a super big buffer or file write count
        // start address - end of PM address = amount of data we can write 
        // without overflowing the PM device
        unsigned long long bytes_left = start - (pm_start+pm_size);
        if (bytes_left < len) {
            len = bytes_left;
        }

        // underlying implementation uses cached copy for writes less than 4 bytes
        if (len < 4 && !Log.undo) {
            return 0;
        }

        // if dst addr is not 8 byte aligned, underlying implementation uses 
        // cache copy to align it. we want to skip those bytes
        int remainder = dest % 8;
        if (remainder != 0) {
            int cached_copy_size = 8 - remainder;
            dest += cached_copy_size;
        }

        // if size is not 4 byte aligned, last few bytes will be copied via cache
        // so we want to skip them too
        remainder = len % 4;
        len -= remainder;
            

        // offset = 0;
        // offset = 0;
        // don't break up very large data writes (for now)
        if (!Log.undo) {
            if (len > CACHELINE_SIZE * 10) {
                while (len > 0) {
                    // printk(KERN_INFO "Skipping large memcpy of size %lld\n", len);
                    // goto skip;
                    likely_data = 1;

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

                    // to_write = len < 4096 ? len : 4096;
                    // 4MB (4 << 20) is maximum kzalloc size
                    to_write = len < (4 << 20) ? len : (4 << 20);
                    len -= to_write;

                     // copy metadata to the log entry
                    // new_op->metadata->len = (unsigned long long)regs->cx;
                    new_op->metadata->len = to_write;
                    // printk(KERN_ALERT "len: %lu\n", regs->cx);
                    // printk(KERN_ALERT "len: %llu\n", new_op->metadata->len);
                    new_op->metadata->dst = dest + data_offset;;
                    new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)regs->dx)) + data_offset;
                    new_op->metadata->type = NT;
                    new_op->metadata->likely_data = 1;
                    new_op->metadata->seq_num = seq_num;

                    data_offset += to_write;

                    // allocate space for the data
                    new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
                    if (new_op->data == NULL) {
                        printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                        kfree(new_op->metadata);
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    // if len is greater than a page, we may need to read in page-sized
                    // chunks and stop if we reach a point where we get faults, 
                    // because it's possible that the len value passed to the function
                    // could be greater than the amount of memory allocated for the buffer

                    ret = probe_kernel_read(new_op->data, (void*)(regs->dx), new_op->metadata->len);
                    if (ret < 0) {
                        // if the write is less than the size of a page, just try again
                        if (new_op->metadata->len < 4096) {
                            ret = probe_kernel_read(new_op->data, (void*)(regs->dx), new_op->metadata->len);
                            if (ret < 0) {
                                // if it still fails, fail the test
                                printk(KERN_ALERT "1\n");
                                printk(KERN_ALERT "A PROBE KERNEL READ IN MEMCPY FAILED\n");
                                printk(KERN_ALERT "could not read data in memcpy_to_pmem\n");
                                kprobe_fail = 1;
                                goto out;
                            }
                        }
                        // it's possible that part of the buffer isn't allocated, so go 
                        // through in 4KB chunks and try to read. if we fail twice, 
                        // skip that part of the buffer
                        // TODO: could you just skip the rest of the buffer if 
                        // you start seeing failures?
                        else {
                            unsigned long long offset2 = 0;
                            unsigned long long len2 = new_op->metadata->len;
                            unsigned long long to_write2 = 0;
                            while (len2 > 0) {
                                to_write2 = len2 < 4096 ? len2 : 4096;
                                len2 -= to_write2;
                                ret = probe_kernel_read(new_op->data+offset2, (void*)(regs->dx + offset2), to_write2);
                                if (ret < 0) {
                                    // try one more time
                                    ret = probe_kernel_read(new_op->data+offset2, (void*)(regs->dx + offset2), to_write2);
                                    // TODO: what should we do if it fails the second time?
                                    if (ret < 0) {
                                        // if it still fails, fail the test
                                        printk(KERN_ALERT "2\n");
                                        printk(KERN_ALERT "A PROBE KERNEL READ IN MEMCPY FAILED\n");
                                        printk(KERN_ALERT "could not read data in memcpy_to_nvmm\n");
                                        kprobe_fail = 1;
                                        goto out;
                                    }
                                }

                                offset2 += to_write2;
                            }
                        }
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

                    // underlying implementation of memcpy_to_pmem_nocache includes sfences.
                    // so we need to account for that
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

                    new_op->metadata->dst = 0;
                    new_op->metadata->src = 0;
                    new_op->metadata->len = 0;
                    new_op->metadata->type = SFENCE;
                    new_op->metadata->likely_data = 0;
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

                    // offset += to_write;
                }
            }
            else {
                // offset = 0;
                while (len > 0) {
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

                    to_write = len < CACHELINE_SIZE ? len : CACHELINE_SIZE;

                    // copy metadata to the log entry
                    new_op->metadata->len = to_write;
                    new_op->metadata->dst = dest + data_offset;
                    new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)regs->dx)) + data_offset;
                    new_op->metadata->type = NT;
                    new_op->metadata->likely_data = 1;
                    new_op->metadata->seq_num = seq_num;

                    len -= to_write;
                    data_offset += to_write;

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
                    // this function ensures that faults are handled correctly when reading data from user space
                    ret = probe_kernel_read((new_op->data), (void*)(regs->dx), new_op->metadata->len);
                    if (ret < 0) {
                        printk(KERN_ALERT "failed down here\n");
                        printk(KERN_ALERT "could not read data in memcpy_to_pmem\n");
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

                    // underlying implementation of memcpy_to_pmem_nocache includes sfences.
                    // so we need to account for that
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

                    new_op->metadata->dst = 0;
                    new_op->metadata->src = 0;
                    new_op->metadata->len = 0;
                    new_op->metadata->type = SFENCE;
                    new_op->metadata->likely_data = 0;
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

                    // offset += to_write;
                }
            }
        }
        else { // make an undo record
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
            // new_op->metadata->len = len;
            // new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)(regs->si)));
            // new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)(regs->di)));
            // new_op->metadata->type = NT;
            // new_op->metadata->len = (unsigned long long)regs->cx;
            new_op->metadata->len = len;
            // printk(KERN_ALERT "len: %lu\n", regs->cx);
            // printk(KERN_ALERT "len: %llu\n", new_op->metadata->len);
            new_op->metadata->dst = dest + data_offset;
            new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)regs->dx)) + data_offset;
            new_op->metadata->type = NT;
            // new_op->metadata->likely_data = 1;
            // new_op->metadata->seq_num = seq_num;

            new_op->data = NULL;

            // new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
            // if (new_op->data == NULL) {
            //     printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
            //     kfree(new_op->metadata);
            //     kfree(new_op);
            //     kprobe_fail = 1;
            //     goto out;
            // }

            // // we want to read what is already there in the file system
            // // rather than what is about to be written
            // memcpy(new_op->data, (void*)regs->si, new_op->metadata->len);

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
    }

    seq_num++;
    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed during Kprobe handling of memcpy_to_nvmm\n");
        return SUCCESS; // not really a success but we probably don't want to stop the memcpy operation entirely
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

static int __kprobes flush_buffer_pre_handler(struct kprobe *p, struct pt_regs *regs) {
        struct write_op* new_op;
    int ret;
    struct stack_trace trace;
    unsigned long long len, to_write, offset, start, mod64;
    if (Log.logging_on && (unsigned long long)(virt_to_phys((void*)regs->di)) >= pm_start && (unsigned long long)(virt_to_phys((void*)regs->di)) < (pm_start+pm_size)) {
        struct task_struct *task = current;
        
        start = (unsigned long long)(virt_to_phys((void*)regs->di));
        mod64 = start % CACHELINE_SIZE;
        len = regs->si + ((unsigned long)(regs->di) & (CACHELINE_SIZE - 1)); // why does NOVA do this?
        // if the start address isn't cache aligned, adjust so that we split writes 
        // that cross the cache line up into separate flushes
        if (mod64 != 0) {
            // move the pointer to the beginning of the flushed region to a multiple of 64
            // and increase len by the same amount
            start -= mod64;
            // TODO: why isn't len being increased too
        }
        if (!Log.undo) {
            offset = 0;
            for (offset = 0; offset < len; offset += CACHELINE_SIZE) {
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

                // to_write = len < CACHELINE_SIZE ? len : CACHELINE_SIZE;

                // copy metadata to log entry
                // here, source and destination are the same
                new_op->metadata->len = CACHELINE_SIZE;
                new_op->metadata->src = start+offset;
                new_op->metadata->dst = start+offset;
                new_op->metadata->type = CLWB;
                new_op->metadata->likely_data = 0; // seems like NOVA doesn't use flushes to write data, but I'm not 100% sure about this
                new_op->metadata->pid = current->pid;

                // len -= to_write;

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
                ret = probe_kernel_read(new_op->data, (void*)(phys_to_virt(start)+offset), new_op->metadata->len);
                if (ret < 0) {
                    printk(KERN_ALERT "could not read data in flush buffer at %llx\n", start+offset);
                    printk(KERN_ALERT "%d\n", ret);
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

                // offset += CACHELINE_SIZE;
            }
        }
        else { // make an undo entry
            offset = 0;
            for (offset = 0; offset < len; offset += CACHELINE_SIZE) {
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

                // new_op->metadata->len = len;
                new_op->metadata->len = CACHELINE_SIZE;
                new_op->metadata->src = start+offset;
                new_op->metadata->dst = start+offset;
                new_op->metadata->type = CLWB;

                new_op->data = NULL;
                // new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
                // if (new_op->data == NULL) {
                //     printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                //     kfree(new_op->metadata);
                //     kfree(new_op);
                //     kprobe_fail = 1;
                //     goto out;
                // }

                // // copy the data that is about to be overwritten
                // memcpy(new_op->data, (void*)regs->di+offset, new_op->metadata->len);

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
        }

    }

    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed during Kprobe handling of nova_flush_buffer\n");
        return SUCCESS;
}

// this one doesn't log any data, just need to make a note that SFENCE was called
static int __kprobes persistent_barrier_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct write_op* new_op;
    struct stack_trace trace;
    if (Log.logging_on && !Log.undo) {
        new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
        if (new_op == NULL) {
            printk(KERN_INFO "logger: could not allocate space for log entry\n");
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
        new_op->metadata->likely_data = 0;

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
        printk(KERN_ALERT "logger: failed during Kprobe handling of PERSISTENT_BARRIER\n");
        return SUCCESS;
}

static int __kprobes memset_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct write_op *new_op;
    int ret;
    struct stack_trace trace;

    if (Log.logging_on && (unsigned long long)(virt_to_phys((void*)regs->di)) >= pm_start && 
        (unsigned long long)(virt_to_phys((void*)regs->di)) < (pm_start+pm_size)) {
        new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
        if (!Log.undo) {
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
            new_op->metadata->len = regs->dx;
            new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)regs->di));
            new_op->metadata->type = NT;
            new_op->metadata->likely_data = 1;
            new_op->metadata->pid = current->pid;
            // printk(KERN_ALERT "memsetting %llu bytes to %d\n", new_op->metadata->len, (int)regs->si);

            // allocate space for the data
            new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
            if (new_op->data == NULL) {
                printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                kfree(new_op->metadata);
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }
            // memset the data in the log entry
            memset(new_op->data, (int)regs->si, new_op->metadata->len);

            // add the op to the list
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
        else { // make an undo entry
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

            new_op->metadata->len = regs->dx;
            new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)regs->di));
            new_op->metadata->type = NT;

            new_op->data = NULL;
            // new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
            // if (new_op->data == NULL) {
            //     printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
            //     kfree(new_op->metadata);
            //     kfree(new_op);
            //     kprobe_fail = 1;
            //     goto out;
            // }

            // // copy out what is about to be overwritten
            // memcpy(new_op->data, (void*)regs->di, new_op->metadata->len);

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
    }

    return SUCCESS;

out:
    printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
    printk(KERN_INFO "logger: failed during Kprobe handling of memset_nt\n");
    return SUCCESS;
}

static int fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr) {
    // TODO: if the trapnr indicates a page fault, we may need to handle it ourselves
    // with do_page_fault?
    printk(KERN_ALERT "fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

// TODO: with some more global variables, could we register the kprobes with one callback 
// function for kallsyms_on_each_symbol that takes the name of a symbol (or a list of names)?
// that should also reduce the size of the init function

static int memcpy_kprobe_index = 0;
static int find_memcpy_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "memcpy_to_nvmm", strlen("memcpy_to_nvmm")) == 0) {
        ((unsigned long*)data)[memcpy_kprobe_index] = address;
        memcpy_kprobe_index++;
    }
    return 0;
}

static int flush_buffer_kprobe_index = 0;
static int find_flush_buffer_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "pmfs_flush_buffer", strlen("pmfs_flush_buffer")) == 0) {
        ((unsigned long*)data)[flush_buffer_kprobe_index] = address;
        flush_buffer_kprobe_index++;
    }
    return 0;
}

static int persistent_barrier_kprobe_index = 0;
static int find_persistent_barrier_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "PERSISTENT_BARRIER", strlen("PERSISTENT_BARRIER")) == 0) {
        ((unsigned long*)data)[persistent_barrier_kprobe_index] = address;
        persistent_barrier_kprobe_index++;
    }
    return 0;
}

static int kprobe_memset_nt_index = 0;
static int find_memset_nt_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "memset_nt", strlen("memset_nt")) == 0) {
        ((unsigned long*)data)[kprobe_memset_nt_index] = address;
        kprobe_memset_nt_index++;
    }
    return 0;
}


// this function will NOT be combined with the other pre-handlers because it needs to be handled separately
// even though it looks very similar to them
static int insert_checkpoint(void) {
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

        // no data is logged here 
        // just need to take note that this is a checkpoint
        new_op->metadata->dst = 0;
        new_op->metadata->src = 0;
        new_op->metadata->len = 0;
        new_op->metadata->type = CHECKPOINT;

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

static int insert_mark_sys(unsigned int sys, int end, long ret) {
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

// this is used to mark the point in the log where the file system has been mounted
// might be useful for testing for sfence bugs I think
static int insert_mount_mark(void) {
    struct write_op* new_op;

    if (Log.logging_on) {
        new_op = kzalloc(sizeof(struct write_op), GFP_KERNEL);
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

unsigned long* memcpy_kprobe_addrs;
unsigned long* flush_buffer_kprobe_addrs;
unsigned long* persistent_barrier_kprobe_addrs;
unsigned long* kprobe_memset_nt_addrs;

void free_addrs(void) {
    kfree(memcpy_kprobe_addrs);
    kfree(flush_buffer_kprobe_addrs);
    kfree(persistent_barrier_kprobe_addrs);
    kfree(kprobe_memset_nt_addrs);
}

static int __init logger_init(void) {
    int ret;

    // TODO: come up with a better way to do this that doesn't assume 
    // a maximum number of functions that will need to be probed 

    memcpy_kprobe_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (memcpy_kprobe_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory\n");
        return -1;
    }
    flush_buffer_kprobe_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (flush_buffer_kprobe_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory\n");
        kfree(memcpy_kprobe_addrs);
        return -1;
    }
    persistent_barrier_kprobe_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (persistent_barrier_kprobe_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory\n");
        kfree(memcpy_kprobe_addrs);
        kfree(flush_buffer_kprobe_addrs);
        return -1;
    }
    kprobe_memset_nt_addrs = (unsigned long*)kzalloc(NUM_KPROBE_ADDRS*sizeof(unsigned long), GFP_KERNEL);
    if (kprobe_memset_nt_addrs == NULL) {
        printk(KERN_ALERT "Unable to allocate memory\n");
        kfree(memcpy_kprobe_addrs);
        kfree(flush_buffer_kprobe_addrs);
        kfree(persistent_barrier_kprobe_addrs);
        return -1;
    }

    kallsyms_on_each_symbol(find_memcpy_addrs, memcpy_kprobe_addrs);
    kallsyms_on_each_symbol(find_flush_buffer_addrs, flush_buffer_kprobe_addrs);
    kallsyms_on_each_symbol(find_persistent_barrier_addrs, persistent_barrier_kprobe_addrs);
    kallsyms_on_each_symbol(find_memset_nt_addrs, kprobe_memset_nt_addrs);

    // check to make sure we actually found these symbols. if we didn't, the file system probably isn't loaded,
    // so we shouldn't try to set up the kprobes
    if (memcpy_kprobe_addrs[0] == 0 || flush_buffer_kprobe_addrs[0] == 0 || persistent_barrier_kprobe_addrs[0] == 0 || kprobe_memset_nt_addrs[0] == 0) {
        printk(KERN_ALERT "Unable to find symbols to probe - is the file system loaded?\n");
        if (memcpy_kprobe_addrs[0] == 0) {
            printk(KERN_ALERT "couldn't find symbols for memcpy\n");
        }
        if (flush_buffer_kprobe_addrs[0] == 0) {
            printk(KERN_ALERT "couldn't find symbols for flush buffer\n");
        }
        if (persistent_barrier_kprobe_addrs[0] == 0) {
            printk(KERN_ALERT "couldn't find symbols for sfence\n");
        }
        if (kprobe_memset_nt_addrs[0] == 0) {
            printk(KERN_ALERT "couldn't find symbols for memset\n");
        }
        kfree(memcpy_kprobe_addrs);
        kfree(flush_buffer_kprobe_addrs);
        kfree(persistent_barrier_kprobe_addrs);
        kfree(kprobe_memset_nt_addrs);
        return -1;
    }

    kp_memcpy_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_memcpy_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_addrs();
        return -ENOMEM;
    }
    // printk(KERN_INFO "setting up memcpy probes\n");
    ret = set_up_kprobes(memcpy_kprobe_addrs, kp_memcpy_head, memcpy_to_nvmm_pre_handler, NULL);
    if (ret < 0) {
        free_kprobe_list(kp_memcpy_head);
        free_addrs();
        return ret;
    }

    // set up duofs_flush_buffer kprobe list
    kp_flush_buffer_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_flush_buffer_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_memcpy_head);
        free_addrs();
        return -ENOMEM;
    }
    // printk(KERN_INFO "setting up flush probes\n");
    ret = set_up_kprobes(flush_buffer_kprobe_addrs, kp_flush_buffer_head, flush_buffer_pre_handler, NULL);
    if (ret < 0) {
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_addrs();
        return ret;
    }

    kp_persistent_barrier_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_persistent_barrier_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_addrs();
        return -ENOMEM;
    }
    // printk(KERN_INFO "setting up fence probes\n");
    ret = set_up_kprobes(persistent_barrier_kprobe_addrs, kp_persistent_barrier_head, persistent_barrier_pre_handler, NULL);
    if (ret < 0) {
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_addrs();
        return ret;
    }
    kp_memset_nt_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_memset_nt_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
    }
    // printk(KERN_INFO "setting up memset probes\n");
    ret = set_up_kprobes(kprobe_memset_nt_addrs, kp_memset_nt_head, memset_pre_handler, NULL);
    if (ret < 0) {
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_kprobe_list(kp_memset_nt_head);
        free_addrs();
        return ret;
    }

    spin_lock(&kprobe_lock);
    Log.head = NULL;
    Log.tail = NULL;
    spin_unlock(&kprobe_lock);
    Log.logging_on = false; // TODO: make this an argument at load time
    // Log.logging_on = true;

    // create device for user processes to interact with this module via IOCTL
    // register the device
    major_num = register_blkdev(major_num, DEVICE_NAME);
    if (major_num <= 0) {
        printk(KERN_ALERT "logger: unable to register IOCTL device\n");
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_kprobe_list(kp_memset_nt_head);
        free_addrs();
        return FAIL;
    }
    // note to self: this device does NOT wrap anything because we can't wrap /dev/pmem0; it's just a standalone dummy device for communication 
    // w/ user processes

    ioctl_dev.ioctl_gd = alloc_disk(1);
    if (!ioctl_dev.ioctl_gd) {
        printk(KERN_ALERT "logger: failed to allocate gendisk\n");
        unregister_blkdev(major_num, DEVICE_NAME);
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_kprobe_list(kp_memset_nt_head);
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
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_kprobe_list(kp_memset_nt_head);
        free_addrs();
        return FAIL;
    }
    // TODO: do we have to set a custom queue request function if we won't actually be using the queue?
    ioctl_dev.ioctl_gd->queue->queuedata = &ioctl_dev;

    // actually add the disk
    add_disk(ioctl_dev.ioctl_gd);

    return SUCCESS;
}

// TODO: can you speed this up? Is there a better way to store our kprobe lists
// and log to make the exit procedure run a little faster? 
static void __exit logger_exit(void) {
    struct write_op* cur;
    struct write_op* temp;

    free_kprobe_list(kp_memcpy_head);
    free_kprobe_list(kp_flush_buffer_head);
    free_kprobe_list(kp_persistent_barrier_head);
    free_kprobe_list(kp_memset_nt_head);

    free_addrs();

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

static int logger_ioctl(struct block_device* bdev, fmode_t mode, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    unsigned int missed = 0;
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
            missed = check_failure();
            kprobe_fail = 0;
            return missed;
        case LOGGER_MARK_SYS:
            ret = insert_mark_sys(arg, 0, 0);
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

module_init(logger_init);
module_exit(logger_exit);
