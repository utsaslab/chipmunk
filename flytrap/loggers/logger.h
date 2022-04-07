#ifndef LOGGER_H
#define LOGGER_H

#define CACHELINE_SIZE 64 // TODO: set dynamically?
#define FAIL -1
#define SUCCESS 0
#define DEVICE_NAME "ioctl_dummy"
#define NUM_KPROBE_ADDRS 32
static int major_num = 0;
static DEFINE_SPINLOCK(kprobe_lock);

int kprobe_fail = 0;

static int __init logger_init(void);
static void __exit logger_exit(void);

static int logger_ioctl(struct block_device* bdev, fmode_t mode, unsigned int cmd, unsigned long arg);

struct kprobe_node {
    struct kprobe_node* next;
    struct kprobe* kp;
};

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

static int set_up_kprobes(unsigned long* kprobe_addrs, struct kprobe_node* kp_head, int (*pre_handler)(struct kprobe*, struct pt_regs*), void (*post_handler)(struct kprobe*, struct pt_regs*, unsigned long flags)) {
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
                kp_head->kp->fault_handler = NULL;

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
                new_kp->kp->fault_handler = NULL;

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

static int check_failure(void) {
    if (kprobe_fail) {
        printk(KERN_INFO "A memcpy from userspace failed, so this test is unreliable\n");
        return -1;
    }
    return 0;
}
#endif
