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

// TODO: define one kprobe_node pointer for each function to probe. See more notes 
// about this in logger_init
struct kprobe_node* kp_memcpy_head = NULL;
struct kprobe_node* kp_flush_buffer_head = NULL;
struct kprobe_node* kp_persistent_barrier_head = NULL;
struct kprobe_node* kp_memset_nt_head = NULL;

// TODO: update these variables based on the location and size of your PM.
// note that pm_end is NOT the size of the PM; it's pm_start+size.
// the testing infrastructure currently doesn't pass these values into 
// the logger when it's loaded, so you should hardcode them here.
unsigned long pm_start = 0x100000000;
unsigned long pm_end = 0x107ffffff;

/*
 * This is an example of a handler function used for a non-temporal memcpy function
 * that the file system uses for both data and metadata updates.
 */
static int __kprobes memcpy_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    int ret;
    unsigned long long len, to_write, offset;
    struct write_op* new_op;  // write_op is a structure that holds data and metadata about a write.
    struct stack_trace trace;

    /* 
     * `start` is the address being updated; it comes from the destination parameter
     * of the instrumented persistence function. See newfs.md for information about 
     * which `regs` field should be accessed. We convert the virtual address to 
     * physical to make it easier to reason about in the context of the PM device.
     */
    // TODO: updated this variable assignment
    unsigned long long start = (unsigned long long)(virt_to_phys((void*)regs->di));


    // add an entry to the write log
    if (Log.logging_on && start >= pm_start && start < pm_end) {
        len = regs->dx; // TODO: update this variable assignment 

        /*
         * If the function being probed is used for both metadata writes and data writes
         * (for example, NOVA's memcpy_to_pmem_nocache function, which copies data to PM using 
         * non-temporal stores, is both used to copy file data to PM and to update inodes in some 
         * places), it's a good idea to have a size threshhold after which you assume
         * a write is a data write (rather than a metadata write). This is because if we split 
         * very large writes into 64-byte chunks and treat them as separate writes, the tester
         * will take a very, very long time. For example, if we split a 4096-byte write into cache 
         * line chunks, a brute force check will examine 18 quintillion crash states.
         * 
         * The threshhold can be modified based on the file system in question. Ideally, this threshold
         * will be greater than the size of any metadata structure stored on PM. When an intercepted
         * update has a size greater than the threshold, we do not break it into cache line-sized chunks,
         * and we set a field in the write_op structure indicating that it is likely data. The tester will 
         * still replay this write, it just won't check all possible crash states for this write. 
         */
        if (len > CACHELINE_SIZE * 10) {
            // allocate space for the new write_op and its metadata            
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
            // this is not currently in use, but leave it here anyway.
            trace.nr_entries = 0;
            trace.entries = &(new_op->metadata->trace_entries[0]);
            trace.max_entries = TRACE_SIZE;
            trace.skip = TRACE_SKIP;
            save_stack_trace(&trace);
            new_op->metadata->nr_entries = trace.nr_entries;

            /*
             * Copy metadata from the intercepted write to the write_op structure here.
             * See newfs.md for an explanation of `regs` and which of its fields should be accessed.
             * Below is an example of how we set these fields for a non-temporal memcpy operation in 
             * NOVA that we have determined is likely to be a data write.
             */
            // TODO: set the len, src, dst, type, and likely_data fields based on the `regs` fields
            // containing the relevant information for your probed function

            new_op->metadata->len = len;
            new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)(regs->si)));
            new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)(regs->di)));
            new_op->metadata->type = NT;
            new_op->metadata->likely_data = 1;

            // allocate space for the data
            new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
            if (new_op->data == NULL) {
                printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                kfree(new_op->metadata);
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }

            /*
             * Since a non-temporal memcpy involves copying data, we want to record that data.
             * probe_kernel_read() MUST be used to copy this data into the space we've allocated;
             * regular memcpy can fail and cause the logger to crash randomly. Note that the 
             * source address CANNOT be one we have converted to physical; we must use the original 
             * virtual address at which the data currently lives.
             */
            // TODO: update the src parameter of probe_kernel_read based on the correct `regs` field
            ret = probe_kernel_read((new_op->data), (void*)(regs->si), new_op->metadata->len);
            if (ret < 0) {
                printk(KERN_ALERT "could not read data in memcpy_to_pmem\n");
                kprobe_fail = 1;
                goto out;
            }

            // this adds the new write_op to a linked list maintained by the logger
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
        /*
         * If a write is below the threshold, we treat it as a metadata write. This means that 
         * if it is longer than a cache line, we split it into cache line sized chunks and save 
         * each chunk as a separate write. This makes slightly less sense in the context of non-temporal 
         * stores than it does for cache line flushes, but it's how we do it for now. In the future,
         * we should probably split non-temporal stores (and maybe flushes too) into 8-byte writes, but 
         * it's possible that this would slow down the tester too much. 
         * 
         * The process here is almost identical to how we record a write in the previous case,
         * but here, we save 64-byte writes in a loop, creating and filling in a new write_op 
         * structure each time.
         */
        else {
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

                // this line ensures that each write is at least the size of a cache line
                to_write = len < CACHELINE_SIZE ? len : CACHELINE_SIZE;

                /*
                 * Notice here that the src, dst, and len fields are set based on the to_write and offset
                 * values, since we aren't copying the intercepted write here.
                 */
                // TODO: set the len, src, dst, type, and likely_data fields based on the `regs` fields
                // containing the relevant information for your probed function
                new_op->metadata->len = to_write;
                new_op->metadata->src = (unsigned long long)(virt_to_phys((void*)(regs->si+offset)));
                new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)(regs->di+offset)));
                new_op->metadata->type = NT;
                new_op->metadata->likely_data = 0;

                len -= to_write;

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
                // TODO: update the src parameter of probe_kernel_read based on the correct `regs` field
                ret = probe_kernel_read((new_op->data), (void*)(regs->si+offset), new_op->metadata->len);
                if (ret < 0) {
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

                offset += to_write;
            }
        }
    }

    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed during Kprobe handling of memcpy\n");
        return SUCCESS; // not really a success but we probably don't want to stop the memcpy operation entirely
}

/*
 * This is an example of a flush function pre-handler, in which the probed flush function 
 * only ever handles metadata writes. It can easily be modified to check whether a write 
 * is likely to be a data write (by comparing the write's size to a threshold). It differs
 * from the non-temporal memcpy handler above primarily in that it accounts for cache line 
 * alignment.
 */
static int __kprobes flush_buffer_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct write_op* new_op;
    int ret;
    struct stack_trace trace;
    unsigned long long len, to_write, offset, start, mod64;
    start = (unsigned long long)(virt_to_phys((void*)regs->di)); // TODO: update this variable assignment

    if (Log.logging_on && start >= pm_start && start < pm_end) {
        /*
         * Since cache line flushes are cache aligned, if we intercept a write that is NOT 
         * aligned, we must account for this. We modify the start address and length of the intercepted
         * write to include the entirety of the first cache line, and increase the length of the 
         * intercepted write to reflect this. These modifications make it so our recorded
         * writes realistically reflect writes that are torn across cache lines.
         */
        mod64 = start % CACHELINE_SIZE;
        // if the start address isn't cache aligned, adjust so that we split writes 
        // that cross the cache line up into separate flushes
        if (mod64 != 0) {
            // move the pointer to the beginning of the flushed region to a multiple of 64
            // and increase len by the same amount
            start -= mod64;
            len += mod64;
        }
        // if the length is now not a multiple of cacheline size, increase it so that it is and we 
        // correctly model the behavior of actual cacheline flushes
        if (len % CACHELINE_SIZE != 0) {
            len += CACHELINE_SIZE - (len % CACHELINE_SIZE);
        }
        offset = 0;
        /*
         * This loop is more or less the same as the loop that runs in the memcpy_pre_handler function 
         * above in the case of a metadata write. If your flush function can be used to make data writes,
         * you should include a case to compare the size of the write against a threshold, similar to 
         * that case above.
         */
        while (len > 0) {
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

            to_write = len < CACHELINE_SIZE ? len : CACHELINE_SIZE;

            // copy metadata to log entry
            // here, source and destination are the same, since a flush is not a copy operation
            new_op->metadata->len = to_write;
            new_op->metadata->src = start+offset;
            new_op->metadata->dst = start+offset;
            new_op->metadata->type = CLWB; 
            new_op->metadata->likely_data = 0; 

            len -= to_write;

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

            offset += to_write;
        }

    }

    return SUCCESS;

    out:
        printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
        printk(KERN_INFO "logger: failed during Kprobe handling of a flush\n");
        return SUCCESS;
}

/*
 * This is an example of a handler for a wrapper around SFENCE in the file system. It is 
 * simpler than the previous two functions because it does not copy any data; it simply 
 * records the fact that an SFENCE was invoked. You can probably copy this function directly
 * into your logger without any changes.
 */
static int __kprobes persistent_barrier_pre_handler(struct kprobe *p, struct pt_regs *regs) {
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
        printk(KERN_INFO "logger: failed during Kprobe handling of PERSISTENT_BARRIER\n");
        return SUCCESS;
}

/*
 * Some file systems include a non-temporal memset function that is only used 
 * to update file data or to zero parts of the storage device out during initialization.
 * The key difference between this handler function and the non-temporal memcpy function
 * above is that it performs a memset, rather than a memcpy, to set the recorded data 
 * to the correct value.
 */
static int __kprobes memset_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct write_op *new_op;
    int ret;
    struct stack_trace trace;
    unsigned long long start = (unsigned long long)(virt_to_phys((void*)regs->di));

    if (Log.logging_on && start >= pm_start && start < pm_end) {
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
        // TODO: set the len, src, dst, type, and likely_data fields based on the `regs` fields
        // containing the relevant information for your probed function
        new_op->metadata->len = regs->si;
        new_op->metadata->dst = start;
        new_op->metadata->type = NT;
        new_op->metadata->likely_data = 1;

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
        // TODO: update this based on the `regs` fields containing the correct 
        // memset value from the instrumented function
        memset(new_op->data, (int)regs->dx, new_op->metadata->len);

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

    return SUCCESS;

out:
    printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
    printk(KERN_INFO "logger: failed during Kprobe handling of memset_nt\n");
    return SUCCESS;
}

/*
 * The following functions find_[memcpy, flush_buffer, persistent_barrier, memset_nt] are used 
 * to obtain the kernel addresses of the functions we want to probe. You should have one 
 * such function per persistence function in the file system. Each function fills in an array 
 * with the addresses definitions of the specified function in the kernel, based on the 
 * name of the function.
 * 
 * To write one of these functions, you need to specify a global index variable that will be 
 * used to access successive entries in the array of addresses. We call these functions using 
 * kallsyms_on_each_symbol, which is a function that lets you iterate over all symbols available in 
 * /proc/kallsyms. The amount of information that can be passed to this function is limited, which 
 * is why we need a global index variable to keep track of where we are as this function iterates over
 * the symbols. You also need to allocate space for arrays to store addresses in; these arrays are 
 * defined here, and allocated in the logger's initalization function.
 * 
 * The key thing to note here is that you need to specify the name of the function to be probed, 
 * and compare the first part of each symbol against this name. Although we cannot probe inlined functions,
 * many of the functions we want to probe are static and might be defined in multiple locations, and 
 * we need to probe each of these locations. Additionally, sometimes the kernel adds a suffix to the function
 * names for some reason, so we have to account for this by comparing the first n characters of each symbol
 * to the function name (where the function name has n characters).
 */

unsigned long* memcpy_kprobe_addrs;
unsigned long* flush_buffer_kprobe_addrs;
unsigned long* persistent_barrier_kprobe_addrs;
unsigned long* kprobe_memset_nt_addrs;

// global variable that allows us to put addrs of statically-defined
// functions in an array to use to build kprobes
static int memcpy_kprobe_index = 0;
static int find_memcpy_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "memcpy_to_pmem_nocache", strlen("memcpy_to_pmem_nocache")) == 0) {
        ((unsigned long*)data)[memcpy_kprobe_index] = address;
        memcpy_kprobe_index++;
    }
    return 0;
}

static int flush_buffer_kprobe_index = 0;
static int find_flush_buffer_addrs(void* data, const char* namebuf, struct module* module, unsigned long address) {
    if (strncmp(namebuf, "nova_flush_buffer", strlen("nova_flush_buffer")) == 0) {
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

/*
 * This function looks similar to the pre-handlers above, but it's actually called via 
 * IOCTL. Our test cases include a checkpoint at the end of the program, which is basically
 * an indication of where we can stop replaying writes when building crash staets. In 
 * crashmonkey, these checkpoints indicated points to inject crashes; we just use them
 * to indicate that nothing interesting happens in the rest of the program. You should 
 * not need to modify this function.
 */
static int insert_checkpoint(void) {
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

}

/*
 * Similar to the insert_checkpoint function above, this function is used 
 * to insert information about which system calls are called during a test 
 * program and is called only via IOCTLs. You can also ignore this function;
 * you should not need to modify it.
 */
static int insert_mark_sys(unsigned int sys, int end) {
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

/*
 * This is another function called only by IOCTLs, used to indicate 
 * the beginning of an interesting region in the test program; we usually
 * use it immediately before the system call in the test program that 
 * we want to brute force check. Again, you should not need to modify 
 * this function.
 */
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

void free_addrs(void) {
    kfree(memcpy_kprobe_addrs);
    kfree(flush_buffer_kprobe_addrs);
    kfree(persistent_barrier_kprobe_addrs);
    kfree(kprobe_memset_nt_addrs);
}

/*
 * This function runs when the logger module is loaded. It sets up the Kprobes and an IOCTL
 * device to let user processes interact with the logger.
 */
static int __init logger_init(void) {
    int ret;

    /*
     * Here, we allocate space for the arrays of addresses to probe of each type, and below we fill 
     * them in using the kallsysm_on_each_symbol function with the callbacks we defined above 
     * to save the addresses we are interested in. This could be sped up by using a single callback, 
     * rather than one for each probed function. 
     */
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
        kfree(memcpy_kprobe_addrs);
        kfree(flush_buffer_kprobe_addrs);
        kfree(persistent_barrier_kprobe_addrs);
        kfree(kprobe_memset_nt_addrs);
        return -1;
    }

    /*
     * Since we have to set up multiple Kprobes (one for each probed address), we maintain a linked list 
     * of probes for each probed function. We allocate space for the head of each of these lists here,
     * and use the set_up_kprobes function to allocate and register the other kprobes in each list.
     * set_up_kprobes is defined in logger.h and should not need to be modified.
     */
    // TODO: allocate a kprobe list head and set up the kprobe linked list for each function you probe.
    kp_memcpy_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_memcpy_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_addrs();
        return -ENOMEM;
    }
    ret = set_up_kprobes(memcpy_kprobe_addrs, kp_memcpy_head, memcpy_pre_handler);
    if (ret < 0) {
        free_kprobe_list(kp_memcpy_head);
        free_addrs();
        return ret;
    }

    // set up nova_flush_buffer kprobe list
    kp_flush_buffer_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_flush_buffer_head == NULL) {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_memcpy_head);
        free_addrs();
        return -ENOMEM;
    }
    ret = set_up_kprobes(flush_buffer_kprobe_addrs, kp_flush_buffer_head, flush_buffer_pre_handler);
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
    ret = set_up_kprobes(persistent_barrier_kprobe_addrs, kp_persistent_barrier_head, persistent_barrier_pre_handler);
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
    ret = set_up_kprobes(kprobe_memset_nt_addrs, kp_memset_nt_head, memset_pre_handler);
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
    Log.logging_on = false; 

    /*
     * The rest of this function is used to set up a device to interact with via IOCTL;
     * this is how the tester's user process interacts with this logger. You can 
     * ignore this stuff.
     */

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

/*
 * This function runs when the logger is unloaded and should free 
 * any dynamically allocated memory and unregister all kprobes.
 */ 
static void __exit logger_exit(void) {
    struct write_op* cur;
    struct write_op* temp;

    // free_kprobe_list is defined in logger.h. It walks through the kprobes 
    // in a linked list, unregisters the kprobes, and frees all dynamically 
    // memory associated with each entry in the list.
    free_kprobe_list(kp_memcpy_head);
    free_kprobe_list(kp_flush_buffer_head);
    free_kprobe_list(kp_persistent_barrier_head);
    free_kprobe_list(kp_memset_nt_head);

    free_addrs();

    // free any remaining entries in the log of recorded writes
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

/*
 * This function handles IOCTL calls made to the device we set up for interacting 
 * with the logger. You shouldn't need to modify anything here.
 */
static int logger_ioctl(struct block_device* bdev, fmode_t mode, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    unsigned int missed = 0;
    unsigned int not_copied;
    unsigned int offset;
    struct write_op* cur;
    struct write_op* temp;

    switch (cmd) {
        // test function to make sure that IOCTL function is working
        case LOGGER_TEST:
            printk(KERN_INFO "logger: ioctl is working\n");
            break;

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
            ret = insert_mark_sys(arg, 0);
            break;
        case LOGGER_MARK_SYS_END:
            ret = insert_mark_sys(0, 1);
            break;
        case LOGGER_MARK:
            ret = insert_mount_mark();
            break;
    }
    return ret;
}

module_init(logger_init);
module_exit(logger_exit);