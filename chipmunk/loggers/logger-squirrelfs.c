#include "logger.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hayley LeBlanc");

unsigned long long seq_num = 0;

struct kprobe_node *kp_memcpy_head = NULL;
struct kprobe_node *kp_flush_buffer_head = NULL;
struct kprobe_node *kp_persistent_barrier_head = NULL;
struct kprobe_node *kp_memset_nt_head = NULL;

unsigned long *memcpy_addrs;
unsigned long *flush_buffer_addrs;
unsigned long *persistent_barrier_addrs;
unsigned long *memset_nt_addrs;

void free_addrs(void)
{
    kfree(memcpy_addrs);
    kfree(flush_buffer_addrs);
    kfree(persistent_barrier_addrs);
    kfree(memset_nt_addrs);
}

static int __kprobes memcpy_to_pmem_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int ret, remainder;
    short likely_data = 0;
    long long len;
    unsigned long long to_write, offset, bytes_left;
    struct write_op *new_op;
    unsigned long long start = (unsigned long long)(virt_to_phys((void *)regs->di));
    // add an entry to the write log
    if (Log.logging_on && start >= pm_start && start < (pm_start + pm_size))
    {
        len = regs->si;

        // if len is greater than the size of the start address to the end of the
        // PM device, reduce it to that size. This will prevent weird errors
        // if the fuzzer provides a super big buffer or file write count
        // start address - end of PM address = amount of data we can write
        // without overflowing the PM device
        bytes_left = start - (pm_start + pm_size);
        if (bytes_left < len)
        {
            len = bytes_left;
        }

        // underlying implementation uses cached copy for writes less than 4 bytes
        if (len < 4 && !Log.undo)
        {
            return 0;
        }

        // if dst addr is not 8 byte aligned, underlying implementation uses
        // cache copy to align it. we want to skip those bytes
        remainder = start % 8;
        if (remainder != 0)
        {
            int cached_copy_size = 8 - remainder;
            start += cached_copy_size;
        }

        // if size is not 4 byte aligned, last few bytes will be copied via cache
        // so we want to skip them too
        remainder = len % 4;
        len -= remainder;

        offset = 0;
        // offset = 0;
        // don't break up very large data writes (for now)
        if (!Log.undo)
        {
            if (len > CACHELINE_SIZE * 5)
            {
                while (len > 0)
                {
                    // printk(KERN_INFO "Skipping large memcpy of size %lld\n", len);
                    // goto skip;
                    likely_data = 1;

                    new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
                    if (new_op == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                        kprobe_fail = 1;
                        goto out;
                    }

                    new_op->next = NULL;
                    new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
                    if (new_op->metadata == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    new_op->metadata->nr_entries = stack_trace_save(&(new_op->metadata->trace_entries[0]), TRACE_SIZE, TRACE_SKIP);

                    // to_write = len < 4096 ? len : 4096;
                    // 4MB (4 << 20) is maximum kzalloc size
                    to_write = len < (4 << 20) ? len : (4 << 20);
                    len -= to_write;

                    // copy metadata to the log entry
                    // new_op->metadata->len = to_write;
                    new_op->metadata->len = to_write;
                    // new_op->metadata->src = (unsigned long long)(virt_to_phys((void *)(regs->si))) + offset;
                    // new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)(regs->di)))+offset;
                    new_op->metadata->src = start + offset;
                    new_op->metadata->dst = start + offset;
                    new_op->metadata->type = NT;
                    new_op->metadata->likely_data = 1;
                    new_op->metadata->pid = current->pid;
                    new_op->metadata->seq_num = seq_num;
                    new_op->metadata->memset = 0;

                    // allocate space for the data
                    new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
                    if (new_op->data == NULL)
                    {
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

                    // ret = copy_from_kernel_nofault(new_op->data, (void *)(regs->si), new_op->metadata->len);
                    ret = copy_from_kernel_nofault(new_op->data, (void*)(regs->di), new_op->metadata->len);
                    if (ret < 0)
                    {
                        // if the write is less than the size of a page, just try again
                        if (new_op->metadata->len < 4096)
                        {
                            // ret = copy_from_kernel_nofault(new_op->data, (void *)(regs->si), new_op->metadata->len);
                            ret = copy_from_kernel_nofault(new_op->data, (void *)(regs->di), new_op->metadata->len);
                            if (ret < 0)
                            {
                                // if it still fails, fail the test
                                printk(KERN_ALERT "A PROBE KERNEL READ IN MEMCPY FAILED 1\n");
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
                        else
                        {
                            unsigned long long offset2 = 0;
                            unsigned long long len2 = new_op->metadata->len;
                            unsigned long long to_write2 = 0;
                            while (len2 > 0)
                            {
                                to_write2 = len2 < 4096 ? len2 : 4096;
                                len2 -= to_write2;

                                // ret = copy_from_kernel_nofault(new_op->data + offset2, (void *)(regs->si + offset2), to_write2);
                                ret = copy_from_kernel_nofault(new_op->data + offset2, (void *)(regs->di + offset2), to_write2);

                                if (ret < 0)
                                {
                                    // try one more time
                                    // ret = copy_from_kernel_nofault(new_op->data + offset2, (void *)(regs->si + offset2), to_write2);
                                    ret = copy_from_kernel_nofault(new_op->data + offset2, (void *)(regs->di + offset2), to_write2);
                                    // TODO: what should we do if it fails the second time?
                                    if (ret < 0)
                                    {
                                        // if it still fails, fail the test
                                        printk(KERN_ALERT "A PROBE KERNEL READ IN MEMCPY FAILED 2 %d\n", ret);
                                        printk(KERN_ALERT "could not read data in memcpy_to_pmem\n");
                                        kprobe_fail = 1;
                                        goto out;
                                    }
                                }

                                offset2 += to_write2;
                            }
                        }
                    }

                    spin_lock(&kprobe_lock);
                    if (Log.tail != NULL)
                    {
                        Log.tail->next = new_op;
                        Log.tail = new_op;
                    }
                    else
                    {
                        Log.tail = new_op;
                    }
                    if (Log.head == NULL)
                    {
                        Log.head = new_op;
                    }
                    spin_unlock(&kprobe_lock);

                    // underlying implementation of memcpy_to_pmem_nocache includes sfences.
                    // so we need to account for that
                    new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
                    if (new_op == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                        kprobe_fail = 1;
                        goto out;
                    }

                    new_op->next = NULL;
                    new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
                    if (new_op->metadata == NULL)
                    {
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
                    new_op->metadata->memset = 0;

                    spin_lock(&kprobe_lock);
                    if (Log.tail != NULL)
                    {
                        Log.tail->next = new_op;
                        Log.tail = new_op;
                    }
                    else
                    {
                        Log.tail = new_op;
                    }
                    if (Log.head == NULL)
                    {
                        Log.head = new_op;
                    }
                    spin_unlock(&kprobe_lock);

                    offset += to_write;
                }
            }
            else
            {
                // offset = 0;
                while (len > 0)
                {
                    new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
                    if (new_op == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                        kprobe_fail = 1;
                        goto out;
                    }

                    new_op->next = NULL;
                    new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
                    if (new_op->metadata == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    // save call stack so we can determine where in the FS code the kprobe was hit
                    new_op->metadata->nr_entries = stack_trace_save(&(new_op->metadata->trace_entries[0]), TRACE_SIZE, TRACE_SKIP);

                    to_write = len < CACHELINE_SIZE ? len : CACHELINE_SIZE;

                    // copy metadata to the log entry
                    new_op->metadata->len = to_write;
                    // new_op->metadata->src = (unsigned long long)(virt_to_phys((void *)(regs->si))) + offset;
                    // new_op->metadata->dst = (unsigned long long)(virt_to_phys((void*)(regs->di)))+offset;
                    new_op->metadata->src = start + offset;
                    new_op->metadata->dst = start + offset;
                    new_op->metadata->type = NT;
                    new_op->metadata->likely_data = 0;
                    new_op->metadata->seq_num = seq_num;

                    len -= to_write;

                    // allocate space for the data
                    new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
                    if (new_op->data == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                        kfree(new_op->metadata);
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    // copy the data to the log
                    // this function ensures that faults are handled correctly when reading data from user space
                    // ret = copy_from_kernel_nofault((new_op->data), (void *)(regs->si + offset), new_op->metadata->len);
                    ret = copy_from_kernel_nofault((new_op->data), (void *)(regs->di + offset), new_op->metadata->len);
                    if (ret < 0)
                    {
                        printk(KERN_ALERT "failed down here\n");
                        printk(KERN_ALERT "could not read data in memcpy_to_pmem\n");
                        kprobe_fail = 1;
                        goto out;
                    }

                    spin_lock(&kprobe_lock);
                    if (Log.tail != NULL)
                    {
                        Log.tail->next = new_op;
                        Log.tail = new_op;
                    }
                    else
                    {
                        Log.tail = new_op;
                    }
                    if (Log.head == NULL)
                    {
                        Log.head = new_op;
                    }
                    spin_unlock(&kprobe_lock);

                    // underlying implementation of memcpy_to_pmem_nocache includes sfences.
                    // so we need to account for that
                    new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
                    if (new_op == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                        kprobe_fail = 1;
                        goto out;
                    }

                    new_op->next = NULL;
                    new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
                    if (new_op->metadata == NULL)
                    {
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
                    new_op->metadata->memset = 0;

                    spin_lock(&kprobe_lock);
                    if (Log.tail != NULL)
                    {
                        Log.tail->next = new_op;
                        Log.tail = new_op;
                    }
                    else
                    {
                        Log.tail = new_op;
                    }
                    if (Log.head == NULL)
                    {
                        Log.head = new_op;
                    }
                    spin_unlock(&kprobe_lock);

                    offset += to_write;
                }
            }
        }
        else
        { // make an undo record
            new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
            if (new_op == NULL)
            {
                printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                kprobe_fail = 1;
                goto out;
            }

            new_op->next = NULL;
            new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
            if (new_op->metadata == NULL)
            {
                printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }
            new_op->metadata->len = len;
            new_op->metadata->src = (unsigned long long)(virt_to_phys((void *)(regs->di)));
            // TODO: we are ignoring the unaligned bytes issue so that we get all of the copied data
            // since this isn't used for crash consistency checking
            new_op->metadata->dst = (unsigned long long)(virt_to_phys((void *)(regs->di)));
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

            // // we want to read what is already there in the file system
            // // rather than what is about to be written
            // memcpy(new_op->data, (void*)regs->si, new_op->metadata->len);

            spin_lock(&kprobe_lock);
            if (Log.tail != NULL)
            {
                Log.tail->next = new_op;
                Log.tail = new_op;
            }
            else
            {
                Log.tail = new_op;
            }
            if (Log.head == NULL)
            {
                Log.head = new_op;
            }
            spin_unlock(&kprobe_lock);
        }
    }

    seq_num++;
    return SUCCESS;

out:
    printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
    printk(KERN_INFO "logger: failed during Kprobe handling of memcpy_to_pmem_nocache\n");
    return SUCCESS; // not really a success but we probably don't want to stop the memcpy operation entirely
}

static int __kprobes flush_buffer_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct write_op *new_op;
    int ret;
    unsigned long long len, to_write, offset, start, mod64;
    start = (unsigned long long)(virt_to_phys((void *)regs->di));
    if (Log.logging_on && (unsigned long long)(virt_to_phys((void *)regs->di)) >= pm_start && (unsigned long long)(virt_to_phys((void *)regs->di)) < (pm_start + pm_size))
    {

        
        mod64 = start % CACHELINE_SIZE;
        len = regs->si + ((unsigned long)(regs->di) & (CACHELINE_SIZE - 1)); // why does NOVA do this?
        // if the start address isn't cache aligned, adjust so that we split writes
        // that cross the cache line up into separate flushes
        if (mod64 != 0)
        {
            // move the pointer to the beginning of the flushed region to a multiple of 64
            // and increase len by the same amount
            start -= mod64;
        }
        
        if (!Log.undo)
        {
            offset = 0;
            // TODO: take this out
            // since we have to use cacheline flushes for everything right now,
            // combine large data writes into a single record rather than
            // recording them all separately
            if (len > CACHELINE_SIZE * 5)
            {
                while (len > 0)
                {
                    new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
                    if (new_op == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                        kprobe_fail = 1;
                        goto out;
                    }

                    new_op->next = NULL;
                    new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
                    if (new_op->metadata == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    // save call stack so we can determine where in the FS code the kprobe was hit
                    new_op->metadata->nr_entries = stack_trace_save(&(new_op->metadata->trace_entries[0]), TRACE_SIZE, TRACE_SKIP);

                    to_write = len < (4 << 20) ? len : (4 << 20);
                    len -= to_write;

                    // copy metadata to log entry
                    // here, source and destination are the same
                    new_op->metadata->len = to_write;
                    new_op->metadata->src = start + offset;
                    new_op->metadata->dst = start + offset;
                    new_op->metadata->type = CLWB;
                    new_op->metadata->likely_data = 1;
                    new_op->metadata->pid = current->pid;
                    new_op->metadata->memset = 0;

                    // allocate space for the data
                    new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
                    if (new_op->data == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                        kfree(new_op->metadata);
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    ret = copy_from_kernel_nofault(new_op->data, phys_to_virt(start) + offset, new_op->metadata->len);
                    if (ret < 0)
                    {
                        if (new_op->metadata->len < 4096)
                        {
                            ret = copy_from_kernel_nofault(new_op->data, phys_to_virt(start) + offset, new_op->metadata->len);
                            if (ret < 0)
                            {
                                printk(KERN_ALERT "PROBE IN FLUSH BUFFER FAILED\n");
                                printk(KERN_ALERT "could not read %d bytes in flush_buffer", new_op->metadata->len);
                                kprobe_fail = 1;
                                goto out;
                            }
                        }
                        else
                        {
                            unsigned long long offset2 = 0;
                            unsigned long long len2 = new_op->metadata->len;
                            unsigned long long to_write2 = 0;
                            while (len2 > 0)
                            {
                                to_write2 = len2 < 4096 ? len2 : 4096;
                                len2 -= to_write2;

                                // ret = copy_from_kernel_nofault(new_op->data+offset2, (void*)(regs->si + offset2), to_write2);
                                ret = copy_from_kernel_nofault(new_op->data + offset2, phys_to_virt(start) + offset + offset2, to_write2);
                                if (ret < 0)
                                {
                                    // try one more time
                                    ret = copy_from_kernel_nofault(new_op->data + offset2, phys_to_virt(start) + offset + offset2, to_write2);
                                    // TODO: what should we do if it fails the second time?
                                    if (ret < 0)
                                    {
                                        // if it still fails, fail the test
                                        printk(KERN_ALERT "A PROBE KERNEL READ IN FLUSH BUFFER FAILED\n");
                                        printk(KERN_ALERT "could not read %d bytes in flush_buffer", new_op->metadata->len);
                                        kprobe_fail = 1;
                                        goto out;
                                    }
                                }
                                offset2 += to_write2;
                            }
                        }
                    }

                    spin_lock(&kprobe_lock);
                    if (Log.tail != NULL)
                    {
                        Log.tail->next = new_op;
                        Log.tail = new_op;
                    }
                    else
                    {
                        Log.tail = new_op;
                    }
                    if (Log.head == NULL)
                    {
                        Log.head = new_op;
                    }
                    spin_unlock(&kprobe_lock);

                    offset += to_write;
                }
            }
            else
            {
                for (offset = 0; offset < len; offset += CACHELINE_SIZE)
                {
                    new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
                    if (new_op == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                        kprobe_fail = 1;
                        goto out;
                    }

                    new_op->next = NULL;
                    new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
                    if (new_op->metadata == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    // save call stack so we can determine where in the FS code the kprobe was hit
                    new_op->metadata->nr_entries = stack_trace_save(&(new_op->metadata->trace_entries[0]), TRACE_SIZE, TRACE_SKIP);

                    // copy metadata to log entry
                    // here, source and destination are the same
                    new_op->metadata->len = CACHELINE_SIZE;
                    new_op->metadata->src = start + offset;
                    new_op->metadata->dst = start + offset;
                    new_op->metadata->type = CLWB;
                    new_op->metadata->likely_data = 0; // seems like NOVA doesn't use flushes to write data, but I'm not 100% sure about this
                    new_op->metadata->pid = current->pid;
                    new_op->metadata->memset = 0;

                    // len -= to_write;

                    // allocate space for the data
                    new_op->data = kzalloc(new_op->metadata->len, GFP_NOWAIT);
                    if (new_op->data == NULL)
                    {
                        printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
                        kfree(new_op->metadata);
                        kfree(new_op);
                        kprobe_fail = 1;
                        goto out;
                    }

                    // copy the data to the log
                    ret = copy_from_kernel_nofault(new_op->data, (void *)(phys_to_virt(start) + offset), new_op->metadata->len);
                    if (ret < 0)
                    {
                        printk(KERN_ALERT "could not read data in flush buffer at %llx\n", start + offset);
                        printk(KERN_ALERT "%d\n", ret);
                        kprobe_fail = 1;
                        goto out;
                    }

                    spin_lock(&kprobe_lock);
                    if (Log.tail != NULL)
                    {
                        Log.tail->next = new_op;
                        Log.tail = new_op;
                    }
                    else
                    {
                        Log.tail = new_op;
                    }
                    if (Log.head == NULL)
                    {
                        Log.head = new_op;
                    }
                    spin_unlock(&kprobe_lock);

                    // offset += CACHELINE_SIZE;
                }
            }
        }
        else
        { // make an undo entry
            offset = 0;
            for (offset = 0; offset < len; offset += CACHELINE_SIZE)
            {
                new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
                if (new_op == NULL)
                {
                    printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                    kprobe_fail = 1;
                    goto out;
                }

                new_op->next = NULL;
                new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
                if (new_op->metadata == NULL)
                {
                    printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                    kfree(new_op);
                    kprobe_fail = 1;
                    goto out;
                }

                // new_op->metadata->len = len;
                new_op->metadata->len = CACHELINE_SIZE;
                new_op->metadata->src = start + offset;
                new_op->metadata->dst = start + offset;
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
                if (Log.tail != NULL)
                {
                    Log.tail->next = new_op;
                    Log.tail = new_op;
                }
                else
                {
                    Log.tail = new_op;
                }
                if (Log.head == NULL)
                {
                    Log.head = new_op;
                }
                spin_unlock(&kprobe_lock);
            }
        }
    }
    return SUCCESS;

out:
    printk(KERN_ALERT "logger: there was an error trying to append to the write log\n");
    printk(KERN_INFO "logger: failed during Kprobe handling of flush_buffer\n");
    return SUCCESS;
}

// this one doesn't log any data, just need to make a note that SFENCE was called
static int __kprobes persistent_barrier_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct write_op *new_op;
    // we don't need to know about SFENCES when creating an undo log
    if (Log.logging_on && !Log.undo)
    {
        new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
        if (new_op == NULL)
        {
            printk(KERN_ALERT "logger: could not allocate space for log entry\n");
            kprobe_fail = 1;
            goto out;
        }

        new_op->next = NULL;
        new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
        if (new_op->metadata == NULL)
        {
            printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
            kfree(new_op);
            kprobe_fail = 1;
            goto out;
        }

        // save call stack so we can determine where in the FS code the kprobe was hit
        new_op->metadata->nr_entries = stack_trace_save(&(new_op->metadata->trace_entries[0]), TRACE_SIZE, TRACE_SKIP);

        // no data is logged here
        // just need to take note that this is an SFENCE instruction
        new_op->metadata->dst = 0;
        new_op->metadata->src = 0;
        new_op->metadata->len = 0;
        new_op->metadata->type = SFENCE;
        new_op->metadata->likely_data = 0;
        new_op->metadata->pid = current->pid;
        new_op->metadata->memset = 0;

        spin_lock(&kprobe_lock);
        if (Log.tail != NULL)
        {
            Log.tail->next = new_op;
            Log.tail = new_op;
        }
        else
        {
            Log.tail = new_op;
        }
        if (Log.head == NULL)
        {
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

static int __kprobes memset_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct write_op *new_op;

    if (Log.logging_on && (unsigned long long)(virt_to_phys((void *)regs->di)) >= pm_start &&
        (unsigned long long)(virt_to_phys((void *)regs->di)) < (pm_start + pm_size))
    {
        new_op = kzalloc(sizeof(struct write_op), GFP_NOWAIT);
        if (!Log.undo)
        {
            if (new_op == NULL)
            {
                printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                kprobe_fail = 1;
                goto out;
            }

            new_op->next = NULL;
            new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
            if (new_op->metadata == NULL)
            {
                printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }

            // save call stack so we can determine where in the FS code the kprobe was hit
            new_op->metadata->nr_entries = stack_trace_save(&(new_op->metadata->trace_entries[0]), TRACE_SIZE, TRACE_SKIP);

            // copy metadata to log entry
            new_op->metadata->len = regs->dx;
            new_op->metadata->dst = (unsigned long long)(virt_to_phys((void *)regs->di));
            new_op->metadata->type = NT;
            new_op->metadata->likely_data = 1;
            new_op->metadata->pid = current->pid;
            new_op->metadata->memset = 1;

            // // instead of creating a buffer for the whole memset, just record the value we are setting
            // printk(KERN_ALERT "allocating %d\n", sizeof(int));
            // new_op->data = kzalloc(sizeof(int), GFP_NOWAIT);
            // {
            //     printk(KERN_ALERT "logger: could not allocate space for log entry data\n");
            //     kfree(new_op->metadata);
            //     kfree(new_op);
            //     kprobe_fail = 1;
            //     goto out;
            // }
            // memset(new_op->data, (int)regs->si, sizeof(int));
            new_op->data = NULL;
            new_op->metadata->memset_val = (int)regs->si;

            // add the op to the list
            spin_lock(&kprobe_lock);
            if (Log.tail != NULL)
            {
                Log.tail->next = new_op;
                Log.tail = new_op;
            }
            else
            {
                Log.tail = new_op;
            }
            if (Log.head == NULL)
            {
                Log.head = new_op;
            }
            spin_unlock(&kprobe_lock);
        }
        else
        { // make an undo entry
            if (new_op == NULL)
            {
                printk(KERN_ALERT "logger: could not allocate space for log entry\n");
                kprobe_fail = 1;
                goto out;
            }

            new_op->next = NULL;
            new_op->metadata = kzalloc(sizeof(struct op_metadata), GFP_NOWAIT);
            if (new_op->metadata == NULL)
            {
                printk(KERN_ALERT "logger: could not allocate space for log entry metadata\n");
                kfree(new_op);
                kprobe_fail = 1;
                goto out;
            }

            new_op->metadata->len = regs->dx;
            new_op->metadata->dst = (unsigned long long)(virt_to_phys((void *)regs->di));
            new_op->metadata->type = NT;
            new_op->metadata->memset = 0; // TODO: does it matter if we identify this as a memset?

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
            if (Log.tail != NULL)
            {
                Log.tail->next = new_op;
                Log.tail = new_op;
            }
            else
            {
                Log.tail = new_op;
            }
            if (Log.head == NULL)
            {
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

static int memcpy_index = 0;
static int find_memcpy_addrs(void *data, const char *namebuf,
                             struct module *module, unsigned long address)
{
    if (strncmp(namebuf, "rust_helper_memcpy_hook", strlen("rust_helper_memcpy_hook")) == 0)
    {
        printk(KERN_INFO "%s\n", namebuf);
        ((unsigned long *)data)[memcpy_index] = address;
        memcpy_index++;
    }
    return 0;
}

static int flush_buffer_index = 0;
static int find_flush_buffer_addrs(void *data, const char *namebuf,
                                   struct module *module, unsigned long address)
{
    if (strcmp(namebuf, "rust_helper_flush_buffer") == 0)
    {
        printk(KERN_INFO "%s\n", namebuf);
        ((unsigned long *)data)[flush_buffer_index] = address;
        flush_buffer_index++;
    }
    return 0;
}

static int persistent_barrier_index = 0;
static int find_persistent_barrier_addrs(void *data, const char *namebuf,
                                         struct module *module, unsigned long address)
{
    if (strcmp(namebuf, "rust_helper_sfence") == 0)
    {
        printk(KERN_INFO "%s\n", namebuf);
        ((unsigned long *)data)[persistent_barrier_index] = address;
        persistent_barrier_index++;
    }
    return 0;
}

static int memset_nt_index = 0;
static int find_memset_nt_addrs(void *data, const char *namebuf,
                                struct module *module, unsigned long address)
{
    if (strcmp(namebuf, "rust_helper_memset_nt") == 0)
    {
        printk(KERN_INFO "%s\n", namebuf);
        ((unsigned long *)data)[memset_nt_index] = address;
        memset_nt_index++;
    }
    return 0;
}

static int __init logger_init(void)
{
    int ret;

    printk(KERN_ALERT "loading squirrelfs logger\n");

    memcpy_addrs = kzalloc(NUM_KPROBE_ADDRS * sizeof(unsigned long), GFP_KERNEL);
    if (memcpy_addrs == NULL)
    {
        printk(KERN_ALERT "Unable to allocate memory\n");
        return -1;
    }

    flush_buffer_addrs = kzalloc(NUM_KPROBE_ADDRS * sizeof(unsigned long), GFP_KERNEL);
    if (flush_buffer_addrs == NULL)
    {
        printk(KERN_ALERT "Unable to allocate memory\n");
        return -1;
    }

    persistent_barrier_addrs = kzalloc(NUM_KPROBE_ADDRS * sizeof(unsigned long), GFP_KERNEL);
    if (persistent_barrier_addrs == NULL)
    {
        printk(KERN_ALERT "Unable to allocate memory\n");
        return -1;
    }

    memset_nt_addrs = kzalloc(NUM_KPROBE_ADDRS * sizeof(unsigned long), GFP_KERNEL);
    if (memset_nt_addrs == NULL)
    {
        printk(KERN_ALERT "Unable to allocate memory\n");
        return -1;
    }

    // find the address of each symbol
    // FIXME: kallsyms_on_each_symbol is no longer exported (v5.7+); current workaround is to modify the kernel
    // to export it
    kallsyms_on_each_symbol(find_memcpy_addrs, memcpy_addrs);
    kallsyms_on_each_symbol(find_flush_buffer_addrs, flush_buffer_addrs);
    kallsyms_on_each_symbol(find_persistent_barrier_addrs, persistent_barrier_addrs);
    kallsyms_on_each_symbol(find_memset_nt_addrs, memset_nt_addrs);

    // as a sanity check, make sure we found at least one of each symbol
    if (memcpy_addrs[0] == 0 || flush_buffer_addrs[0] == 0 || persistent_barrier_addrs[0] == 0 || memset_nt_addrs[0] == 0)
    {
        printk(KERN_ALERT "Unable to find symbols to probe - is the file system loaded?\n");
        kfree(memcpy_addrs);
        kfree(flush_buffer_addrs);
        kfree(persistent_barrier_addrs);
        kfree(memset_nt_addrs);
        return -1;
    }

    kp_memcpy_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_memcpy_head == NULL)
    {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_addrs();
        return -ENOMEM;
    }
    // printk(KERN_INFO "setting up memcpy probes\n");
    ret = set_up_kprobes(memcpy_addrs, kp_memcpy_head, memcpy_to_pmem_pre_handler, NULL);
    if (ret < 0)
    {
        free_kprobe_list(kp_memcpy_head);
        free_addrs();
        return ret;
    }

    // set up probes

    kp_flush_buffer_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_flush_buffer_head == NULL)
    {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_memcpy_head);
        free_addrs();
        return -ENOMEM;
    }
    // printk(KERN_INFO "setting up flush probes\n");
    ret = set_up_kprobes(flush_buffer_addrs, kp_flush_buffer_head, flush_buffer_pre_handler, NULL);
    if (ret < 0)
    {
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_addrs();
        return ret;
    }

    kp_persistent_barrier_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_persistent_barrier_head == NULL)
    {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_addrs();
        return -ENOMEM;
    }
    ret = set_up_kprobes(persistent_barrier_addrs, kp_persistent_barrier_head, persistent_barrier_pre_handler, NULL);
    if (ret < 0)
    {
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_addrs();
        return ret;
    }

    kp_memset_nt_head = kzalloc(sizeof(struct kprobe_node), GFP_KERNEL);
    if (kp_memset_nt_head == NULL)
    {
        printk(KERN_ALERT "logger: unable to allocate space for kprobe list head\n");
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
    }
    // printk(KERN_INFO "setting up memset probes\n");
    ret = set_up_kprobes(memset_nt_addrs, kp_memset_nt_head, memset_pre_handler, NULL);
    if (ret < 0)
    {
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_kprobe_list(kp_memset_nt_head);
        free_addrs();
        return ret;
    }

    // set up the log
    spin_lock(&kprobe_lock);
    Log.head = NULL;
    Log.tail = NULL;
    spin_unlock(&kprobe_lock);
    Log.logging_on = false; // TODO: make this an argument at load time
    Log.undo = false;

    printk(KERN_INFO "setting up ioctl device\n");

    // set up ioctl device
    major_num = register_blkdev(major_num, DEVICE_NAME);
    if (major_num <= 0)
    {
        printk(KERN_ALERT "logger: unable to register IOCTL device\n");
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_kprobe_list(kp_memset_nt_head);
        free_addrs();
        return FAIL;
    }

    ioctl_dev.ioctl_gd = blk_alloc_disk(1);
    if (!ioctl_dev.ioctl_gd)
    {
        printk(KERN_ALERT "logger: failed to allocate gendisk\n");
        unregister_blkdev(major_num, DEVICE_NAME);
        free_kprobe_list(kp_memcpy_head);
        free_kprobe_list(kp_flush_buffer_head);
        free_kprobe_list(kp_persistent_barrier_head);
        free_kprobe_list(kp_memset_nt_head);
        free_addrs();
        return FAIL;
    }
    ioctl_dev.ioctl_gd->private_data = &ioctl_dev;
    ioctl_dev.ioctl_gd->fops = &blkdev_ops;
    strcpy(ioctl_dev.ioctl_gd->disk_name, DEVICE_NAME);

    ret = add_disk(ioctl_dev.ioctl_gd);
    if (ret < 0)
    {
        printk(KERN_INFO "failed to add disk\n");
        return ret;
    }
    printk(KERN_INFO "loaded squirrelfs logger\n");

    return 0;
}

static void __exit logger_exit(void)
{
    struct write_op *cur;
    struct write_op *temp;

    free_kprobe_list(kp_memcpy_head);
    free_kprobe_list(kp_persistent_barrier_head);
    free_kprobe_list(kp_flush_buffer_head);
    free_kprobe_list(kp_memset_nt_head);

    free_addrs();

    spin_lock(&kprobe_lock);
    // clean up log
    cur = Log.head;
    while (cur)
    {
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

module_init(logger_init);
module_exit(logger_exit);