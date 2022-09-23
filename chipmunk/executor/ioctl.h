// #ifndef LOGGER_IOCTL_H
// #define LOGGER_IOCTL_H

// #include <linux/ioctl.h>

// // define IOCTL stuff
// #define LOGGER_IOCTL_BASE '@' // you may need to change this at some point but it should work for now

// // start sequence numbers at 0xf1
// // according to Docmentation/ioctl/ioctl-number.rst, this should be safe, but that document is very out of date
// #define LOGGER_GET_OP       _IOR(LOGGER_IOCTL_BASE, 0xf1, char*)
// #define LOGGER_GET_DATA     _IOR(LOGGER_IOCTL_BASE, 0xf2, void*)
// #define LOGGER_NEXT_OP      _IO(LOGGER_IOCTL_BASE, 0xf3)
// #define LOGGER_LOG_ON       _IO(LOGGER_IOCTL_BASE, 0xf4)
// #define LOGGER_LOG_OFF      _IO(LOGGER_IOCTL_BASE, 0xf5)
// #define LOGGER_SET_PM_START _IOW(LOGGER_IOCTL_BASE, 0xf6, unsigned long)
// #define LOGGER_CHECKPOINT   _IO(LOGGER_IOCTL_BASE, 0xf7)
// #define LOGGER_FREE_LOG     _IO(LOGGER_IOCTL_BASE, 0xf8)
// #define LOGGER_CHECK_MISSED _IO(LOGGER_IOCTL_BASE, 0xf9)
// #define LOGGER_MARK         _IO(LOGGER_IOCTL_BASE, 0xfa)
// #define LOGGER_MARK_SYS     _IOR(LOGGER_IOCTL_BASE, 0xfb, unsigned int)
// #define LOGGER_MARK_SYS_END _IO(LOGGER_IOCTL_BASE, 0xfc)
// #define LOGGER_UNDO_ON      _IO(LOGGER_IOCTL_BASE, 0xfd)
// #define LOGGER_UNDO_OFF     _IO(LOGGER_IOCTL_BASE, 0xfe)

// // types of operations 
// // NT == non-temporal store
// #define NT 0
// #define SFENCE 1
// #define CLWB 2
// #define CHECKPOINT 3
// #define MARK 4
// #define MARK_SYS 5
// #define MARK_SYS_END 6

// #define TRACE_SIZE 4
// #define TRACE_SKIP 4 // avoids printing weird functions related to kprobes. Might be good to determine dynamically in the harness...

// struct op_metadata {
//     unsigned long long src;
//     unsigned long long dst;
//     unsigned long long len;
//     short type;
//     unsigned long trace_entries[TRACE_SIZE];
//     unsigned int nr_entries;
//     unsigned int sys;
//     short likely_data;
//     int pid;
//     unsigned long long seq_num;
// };

// struct write_op {
//     void* data;
//     struct op_metadata* metadata;
//     // struct stack_trace trace;
//     struct write_op* next;
//     struct write_op* prev;
// };

// #endif 

#ifndef LOGGER_IOCTL_H
#define LOGGER_IOCTL_H

#include <linux/ioctl.h>

// define IOCTL stuff
#define LOGGER_IOCTL_BASE '@' // you may need to change this at some point but it should work for now

// start sequence numbers at 0xf1
// according to Docmentation/ioctl/ioctl-number.rst, this should be safe, but that document is very out of date
#define LOGGER_GET_OP       _IOR(LOGGER_IOCTL_BASE, 0xf1, char*)
#define LOGGER_GET_DATA     _IOR(LOGGER_IOCTL_BASE, 0xf2, void*)
#define LOGGER_NEXT_OP      _IO(LOGGER_IOCTL_BASE, 0xf3)
#define LOGGER_LOG_ON       _IO(LOGGER_IOCTL_BASE, 0xf4)
#define LOGGER_LOG_OFF      _IO(LOGGER_IOCTL_BASE, 0xf5)
#define LOGGER_SET_PM_START _IOW(LOGGER_IOCTL_BASE, 0xf6, unsigned long)
#define LOGGER_CHECKPOINT   _IO(LOGGER_IOCTL_BASE, 0xf7)
#define LOGGER_FREE_LOG     _IO(LOGGER_IOCTL_BASE, 0xf8)
#define LOGGER_CHECK_MISSED _IO(LOGGER_IOCTL_BASE, 0xf9)
#define LOGGER_MARK         _IO(LOGGER_IOCTL_BASE, 0xfa)
#define LOGGER_MARK_SYS     _IOR(LOGGER_IOCTL_BASE, 0xfb, unsigned int)
#define LOGGER_MARK_SYS_END _IOW(LOGGER_IOCTL_BASE, 0xfc, unsigned long)
#define LOGGER_UNDO_ON      _IO(LOGGER_IOCTL_BASE, 0xfd)
#define LOGGER_UNDO_OFF     _IO(LOGGER_IOCTL_BASE, 0xfe)

// types of operations 
// NT == non-temporal store
#define NT 0
#define SFENCE 1
#define CLWB 2
#define CHECKPOINT 3
#define MARK 4
#define MARK_SYS 5
#define MARK_SYS_END 6

#define TRACE_SIZE 4
#define TRACE_SKIP 4 // avoids printing weird functions related to kprobes. Might be good to determine dynamically in the harness...

struct op_metadata {
    unsigned long long src;
    unsigned long long dst;
    unsigned long long len;
    short type;
    unsigned long trace_entries[TRACE_SIZE];
    unsigned int nr_entries;
    unsigned int sys;
    short likely_data;
    unsigned int pid;
    unsigned long long seq_num;
    long sys_ret;
};

struct write_op {
    void* data;
    struct op_metadata* metadata;
    // struct stack_trace trace;
    struct write_op* next;
    struct write_op* prev;
};

#endif 

