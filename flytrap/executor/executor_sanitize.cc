// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <algorithm>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <cstring>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include <time.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <linux/module.h>
#include <fstream>
#include <cassert>
#include <string>


#include <iostream>


#include "user_tools/api/wrapper.h"
#include "tester_defs.h"

using std::endl;
using namespace fs_testing;
using namespace fs_testing::user_tools::api;

static __thread int skip_segv;
static __thread jmp_buf segv_env;



#if !GOOS_windows
#include <unistd.h>
#endif

#include "defs.h"

#if defined(__GNUC__)
#define SYSCALLAPI
#define NORETURN __attribute__((noreturn))
#define ALIGNED(N) __attribute__((aligned(N)))
#define PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#define INPUT_DATA_ALIGNMENT 64 << 10
#else
// Assuming windows/cl.
#define SYSCALLAPI WINAPI
#define NORETURN __declspec(noreturn)
#define INPUT_DATA_ALIGNMENT 4 << 10
#define ALIGNED(N) __declspec(align(N)) // here we are not aligning the value because of msvc reporting the value as an illegal value
#define PRINTF(fmt, args)
#define __thread __declspec(thread)
#endif

#ifndef GIT_REVISION
#define GIT_REVISION "unknown"
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
// uint64 is impossible to printf without using the clumsy and verbose "%" PRId64.
// So we define and use uint64. Note: pkg/csource does s/uint64/uint64/.
// Also define uint32/16/8 for consistency.
// typedef unsigned long long uint64;
// typedef unsigned int uint32;
// typedef unsigned short uint16;
// typedef unsigned char uint8;

// exit/_exit do not necessary work (e.g. if fuzzer sets seccomp filter that prohibits exit_group).
// Use doexit instead.  We must redefine exit to something that exists in stdlib,
// because some standard libraries contain "using ::exit;", but has different signature.
#define exit vsnprintf

// Dynamic memory allocation reduces test reproducibility across different libc versions and kernels.
// malloc will cause unspecified number of additional mmap's at unspecified locations.
// For small objects prefer stack allocations, for larger -- either global objects (this may have
// issues with concurrency), or controlled mmaps, or make the fuzzer allocate memory.
#define malloc do_not_use_malloc
#define calloc do_not_use_calloc

// Note: zircon max fd is 256.
// Some common_OS.h files know about this constant for RLIMIT_NOFILE.
const int kMaxFd = 250;
const int kMaxThreads = 16;
const int kInPipeFd = kMaxFd - 1; // remapped from stdin
const int kOutPipeFd = kMaxFd - 2; // remapped from stdout
const int kCoverFd = kOutPipeFd - kMaxThreads;
// const int kMaxArgs = 9;
const int kCoverSize = 256 << 10;
const int kFailStatus = 67;

const unsigned long replay_pm_start = 0x108000000; // TODO: make this command line arg or get it dynamically

// Logical error (e.g. invalid input program), use as an assert() alternative.
// If such error happens 10+ times in a row, it will be detected as a bug by syz-fuzzer.
// syz-fuzzer will fail and syz-manager will create a bug for this.
// Note: err is used for bug deduplication, thus distinction between err (constant message)
// and msg (varying part).
static NORETURN void fail(const char* err);
static NORETURN PRINTF(2, 3) void failmsg(const char* err, const char* msg, ...);
// Just exit (e.g. due to temporal ENOMEM error).
static NORETURN PRINTF(1, 2) void exitf(const char* msg, ...);
static void doexit(int status);

static void doexit(int status)
{
	_exit(status);
	for (;;) {
	}
}

// Print debug output that is visible when running syz-manager/execprog with -debug flag.
// Debug output is supposed to be relatively high-level (syscalls executed, return values, timing, etc)
// and is intended mostly for end users. If you need to debug lower-level details, use debug_verbose
// function and temporary enable it in your build by changing #if 0 below.
// This function does not add \n at the end of msg as opposed to the previous functions.
static PRINTF(1, 2) void debug(const char* msg, ...);
void debug_dump_data(const char* data, int length);

#if 0
#define debug_verbose(...) debug(__VA_ARGS__)
#else
#define debug_verbose(...) (void)0
#endif


#if GOOS_akaros
static void resend_execute(int fd);
#endif


#define ZERO1 "dd if=/dev/zero of="
#define ZERO2 " status=noxfer > /dev/null 2>&1"

#define IMG1 "sudo dd if=/dev/zero of="
#define IMG2 "/code/replay/nova_replay.img bs=128M count=1 status=noxfer > /dev/null 2>&1"

#define BITMASK(bf_off, bf_len) (((1ull << (bf_len)) - 1) << (bf_off))


uint64 start_time_ms = 0;

static bool flag_debug;
static bool flag_coverage;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;
static bool flag_sandbox_namespace;
static bool flag_sandbox_android;
static bool flag_extra_coverage;
static bool flag_net_injection;
static bool flag_net_devices;
static bool flag_net_reset;
static bool flag_cgroups;
static bool flag_close_fds;
static bool flag_devlink_pci;
static bool flag_vhci_injection;
static bool flag_wifi;

static bool flag_collect_cover;
static bool flag_dedup_cover;
static bool flag_threaded;
static bool flag_collide;
static bool flag_coverage_filter;
static bool checkpt;
static bool reloadFS;

// If true, then executor should write the comparisons data to fuzzer.
static bool flag_comparisons;

// Inject fault into flag_fault_nth-th operation in flag_fault_call-th syscall.
static bool flag_fault;
static int flag_fault_call;
static int flag_fault_nth;

// Tunable timeouts, received with execute_req.
static uint64 syscall_timeout_ms;
static uint64 program_timeout_ms;
static uint64 slowdown_scale;

#define SYZ_EXECUTOR 1

const int kMaxInput = 4 << 20; // keep in sync with prog.ExecBufferSize
const int kMaxCommands = 1000; // prog package knows about this constant (prog.execMaxCommands)

#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912

const uint64 instr_eof = -1;
const uint64 instr_copyin = -2;
const uint64 instr_copyout = -3;

const uint64 arg_const = 0;
const uint64 arg_result = 1;
const uint64 arg_data = 2;
const uint64 arg_csum = 3;

const uint64 binary_format_native = 0;
const uint64 binary_format_bigendian = 1;
const uint64 binary_format_strdec = 2;
const uint64 binary_format_strhex = 3;
const uint64 binary_format_stroct = 4;

static int num_threads;

const uint64 no_copyout = -1;

static bool collide;
uint32 completed;
bool is_kernel_64_bit = true;

ALIGNED(INPUT_DATA_ALIGNMENT)
static char input_data[kMaxInput];

// Checksum kinds.
static const uint64 arg_csum_inet = 0;

// Checksum chunk kinds.
static const uint64 arg_csum_chunk_data = 0;
static const uint64 arg_csum_chunk_const = 1;
static bool check_data = false;

static constexpr char kChangePath[] = "/root/tmpdir/run_changes";

static CmFsOps *cm_;


std::string mount_point = "/mnt/pmem";
std::string mount_point_replay = "/mnt/pmem_replay";

static std::string logger;
static std::string fs_module;
static std::string FS;

static unsigned long pm_start = 0x100000000;
static unsigned long pm_size =  0x7ffffff;


typedef intptr_t(SYSCALLAPI* syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);

struct call_t {
	const char* name;
	int sys_nr;
	call_attrs_t attrs;
	syscall_t call;
};

#define NONFAILING(...)                                              \
	({                                                           \
		int ok = 1;                                          \
		__atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		if (_setjmp(segv_env) == 0) {                        \
			__VA_ARGS__;                                 \
		} else                                               \
			ok = 0;                                      \
		__atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		ok;                                                  \
	})


// struct cover_t {
// 	int fd;
// 	uint32 size;
// 	char* data;
// 	char* data_end;
// };

// struct thread_t {
// 	int id;
// 	bool created;
// 	event_t ready;
// 	event_t done;
// 	uint64* copyout_pos;
// 	uint64 copyout_index;
// 	bool colliding;
// 	bool executing;
// 	int call_index;
// 	int call_num;
// 	int num_args;
// 	intptr_t args[kMaxArgs];
// 	intptr_t res;
// 	uint32 reserrno;
// 	bool fault_injected;
// 	cover_t cov;
// 	bool soft_fail_state;
// };

static thread_t threads[kMaxThreads];
static thread_t* last_scheduled;
// Threads use this variable to access information about themselves.
static __thread struct thread_t* current_thread;

static cover_t extra_cov;

static uint64 *input_pos;

struct res_t {
	bool executed;
	uint64 val;
};

static res_t results[kMaxCommands];

const uint64 kInMagic = 0xbadc0ffeebadface;
const uint32 kOutMagic = 0xbadf00d;

struct handshake_req {
	uint64 magic;
	uint64 flags; // env flags
	uint64 pid;
};

struct handshake_reply {
	uint32 magic;
};

struct execute_req {
	uint64 magic;
	uint64 env_flags;
	uint64 exec_flags;
	uint64 pid;
	uint64 fault_call;
	uint64 fault_nth;
	uint64 syscall_timeout_ms;
	uint64 program_timeout_ms;
	uint64 slowdown_scale;
	uint64 prog_size;
	uint64 prog_len;
};

struct execute_reply {
	uint32 magic;
	uint32 done;
	uint32 status;
};

// call_reply.flags
const uint32 call_flag_executed = 1 << 0;
const uint32 call_flag_finished = 1 << 1;
const uint32 call_flag_blocked = 1 << 2;
const uint32 call_flag_fault_injected = 1 << 3;
bool mountCov = false;
bool loadModule = false;
std::string instanceId;
// std::string FS = "";
int max_k = 2; // TODO: make this a command line argument

struct call_reply {
	execute_reply header;
	uint32 call_index;
	uint32 call_num;
	uint32 reserrno;
	uint32 flags;
	uint32 signal_size;
	uint32 cover_size;
	uint32 comps_size;
	// signal/cover/comps follow
};

enum {
	KCOV_CMP_CONST = 1,
	KCOV_CMP_SIZE1 = 0,
	KCOV_CMP_SIZE2 = 2,
	KCOV_CMP_SIZE4 = 4,
	KCOV_CMP_SIZE8 = 6,
	KCOV_CMP_SIZE_MASK = 6,
};

struct kcov_comparison_t {
	// Note: comparisons are always 64-bits regardless of kernel bitness.
	uint64 type;
	uint64 arg1;
	uint64 arg2;
	uint64 pc;

	bool ignore() const;
	void write();
	bool operator==(const struct kcov_comparison_t& other) const;
	bool operator<(const struct kcov_comparison_t& other) const;
};

typedef char kcov_comparison_size[sizeof(kcov_comparison_t) == 4 * sizeof(uint64) ? 1 : -1];

struct feature_t {
	const char* name;
	void (*setup)();
};

static thread_t* schedule_call(int call_index, int call_num, bool colliding, uint64 copyout_index, uint64 num_args, uint64* args, uint64* pos);
static void handle_completion(thread_t* th, bool writeCoverage);
static void copyout_call_results(thread_t* th);
static void write_call_output(thread_t* th, bool finished);
static void write_extra_output();
static int run_test();
static void execute_call(thread_t* th);
static void thread_create(thread_t* th, int id);
static void* worker_thread(void* arg);
static int execute_test();
static uint64 read_input(uint64** input_posp, bool peek = false);
static uint64 read_arg(uint64** input_posp);
static uint64 read_const_arg(uint64** input_posp, uint64* size_p, uint64* bf, uint64* bf_off_p, uint64* bf_len_p);
static uint64 read_result(uint64** input_posp);
static uint64 swap(uint64 v, uint64 size, uint64 bf);
static void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len);
static bool copyout(char* addr, uint64 size, uint64* res);
static void setup_control_pipes();
static void setup_features(char** enable, int n);
// static int set_up_imgs(std::string pm_device);


const call_t syscalls[] = {
    {"accept", 43},
    {"accept$alg", 43},
    {"accept$ax25", 43},
    {"accept$inet", 43},
    {"accept$inet6", 43},
    {"accept$ipx", 43},
    {"accept$netrom", 43},
    {"accept$nfc_llcp", 43},
    {"accept$packet", 43},
    {"accept$phonet_pipe", 43},
    {"accept$unix", 43},
    {"accept4", 288},
    {"accept4$alg", 288},
    {"accept4$ax25", 288},
    {"accept4$bt_l2cap", 288},
    {"accept4$inet", 288},
    {"accept4$inet6", 288},
    {"accept4$ipx", 288},
    {"accept4$llc", 288},
    {"accept4$netrom", 288},
    {"accept4$nfc_llcp", 288},
    {"accept4$packet", 288},
    {"accept4$phonet_pipe", 288},
    {"accept4$rose", 288},
    {"accept4$tipc", 288},
    {"accept4$unix", 288},
    {"accept4$vsock_stream", 288},
    {"accept4$x25", 288},
    {"acct", 163},
    {"add_key", 248},
    {"add_key$fscrypt_provisioning", 248},
    {"add_key$fscrypt_v1", 248},
    {"add_key$keyring", 248},
    {"add_key$user", 248},
    {"alarm", 37},
    {"arch_prctl$ARCH_GET_CPUID", 158},
    {"arch_prctl$ARCH_GET_FS", 158},
    {"arch_prctl$ARCH_GET_GS", 158},
    {"arch_prctl$ARCH_MAP_VDSO_32", 158},
    {"arch_prctl$ARCH_MAP_VDSO_64", 158},
    {"arch_prctl$ARCH_MAP_VDSO_X32", 158},
    {"arch_prctl$ARCH_SET_CPUID", 158},
    {"arch_prctl$ARCH_SET_GS", 158},
    {"bind", 49},
    {"bind$802154_dgram", 49},
    {"bind$802154_raw", 49},
    {"bind$alg", 49},
    {"bind$ax25", 49},
    {"bind$bt_hci", 49},
    {"bind$bt_l2cap", 49},
    {"bind$bt_rfcomm", 49},
    {"bind$bt_sco", 49},
    {"bind$can_j1939", 49},
    {"bind$can_raw", 49},
    {"bind$inet", 49},
    {"bind$inet6", 49},
    {"bind$ipx", 49},
    {"bind$isdn", 49},
    {"bind$isdn_base", 49},
    {"bind$l2tp", 49},
    {"bind$l2tp6", 49},
    {"bind$llc", 49},
    {"bind$netlink", 49},
    {"bind$netrom", 49},
    {"bind$nfc_llcp", 49},
    {"bind$packet", 49},
    {"bind$phonet", 49},
    {"bind$pptp", 49},
    {"bind$qrtr", 49},
    {"bind$rds", 49},
    {"bind$rose", 49},
    {"bind$rxrpc", 49},
    {"bind$tipc", 49},
    {"bind$unix", 49},
    {"bind$vsock_dgram", 49},
    {"bind$vsock_stream", 49},
    {"bind$x25", 49},
    {"bind$xdp", 49},
    {"bpf$BPF_BTF_GET_FD_BY_ID", 321},
    {"bpf$BPF_BTF_GET_NEXT_ID", 321},
    {"bpf$BPF_BTF_LOAD", 321},
    {"bpf$BPF_GET_BTF_INFO", 321},
    {"bpf$BPF_GET_MAP_INFO", 321},
    {"bpf$BPF_GET_PROG_INFO", 321},
    {"bpf$BPF_LINK_CREATE", 321},
    {"bpf$BPF_LINK_UPDATE", 321},
    {"bpf$BPF_MAP_FREEZE", 321},
    {"bpf$BPF_MAP_GET_FD_BY_ID", 321},
    {"bpf$BPF_MAP_GET_NEXT_ID", 321},
    {"bpf$BPF_MAP_LOOKUP_AND_DELETE_BATCH", 321},
    {"bpf$BPF_MAP_LOOKUP_AND_DELETE_ELEM", 321},
    {"bpf$BPF_PROG_ATTACH", 321},
    {"bpf$BPF_PROG_DETACH", 321},
    {"bpf$BPF_PROG_GET_FD_BY_ID", 321},
    {"bpf$BPF_PROG_GET_NEXT_ID", 321},
    {"bpf$BPF_PROG_QUERY", 321},
    {"bpf$BPF_PROG_RAW_TRACEPOINT_LOAD", 321, {0, 500}},
    {"bpf$BPF_PROG_TEST_RUN", 321},
    {"bpf$BPF_PROG_WITH_BTFID_LOAD", 321, {0, 500}},
    {"bpf$BPF_RAW_TRACEPOINT_OPEN", 321, {0, 500}},
    {"bpf$BPF_RAW_TRACEPOINT_OPEN_UNNAMED", 321, {0, 500}},
    {"bpf$BPF_TASK_FD_QUERY", 321},
    {"bpf$ENABLE_STATS", 321},
    {"bpf$ITER_CREATE", 321},
    {"bpf$LINK_DETACH", 321},
    {"bpf$LINK_GET_FD_BY_ID", 321},
    {"bpf$LINK_GET_NEXT_ID", 321},
    {"bpf$MAP_CREATE", 321},
    {"bpf$MAP_DELETE_BATCH", 321},
    {"bpf$MAP_DELETE_ELEM", 321},
    {"bpf$MAP_GET_NEXT_KEY", 321},
    {"bpf$MAP_LOOKUP_BATCH", 321},
    {"bpf$MAP_LOOKUP_ELEM", 321},
    {"bpf$MAP_UPDATE_BATCH", 321},
    {"bpf$MAP_UPDATE_ELEM", 321},
    {"bpf$OBJ_GET_MAP", 321},
    {"bpf$OBJ_GET_PROG", 321},
    {"bpf$OBJ_PIN_MAP", 321},
    {"bpf$OBJ_PIN_PROG", 321},
    {"bpf$PROG_BIND_MAP", 321},
    {"bpf$PROG_LOAD", 321},
    {"capget", 125},
    {"capset", 126},
    {"chdir", 80},
    {"chmod", 90},
    {"chown", 92},
    {"chroot", 161},
    {"clock_adjtime", 305},
    {"clock_getres", 229},
    {"clock_gettime", 228},
    {"clock_nanosleep", 230},
    {"clock_settime", 227},
    {"clone", 56, {0, 0, 0, 0, 1}},
    {"clone3", 435, {0, 0, 0, 0, 1}},
    {"close", 3},
    {"close$ibv_device", 3},
    {"close_range", 436},
    {"connect", 42},
    {"connect$802154_dgram", 42},
    {"connect$ax25", 42},
    {"connect$bt_l2cap", 42},
    {"connect$bt_rfcomm", 42},
    {"connect$bt_sco", 42},
    {"connect$caif", 42},
    {"connect$can_bcm", 42},
    {"connect$can_j1939", 42},
    {"connect$hf", 42},
    {"connect$inet", 42},
    {"connect$inet6", 42},
    {"connect$ipx", 42},
    {"connect$l2tp", 42},
    {"connect$l2tp6", 42},
    {"connect$llc", 42},
    {"connect$netlink", 42},
    {"connect$netrom", 42},
    {"connect$nfc_llcp", 42},
    {"connect$nfc_raw", 42},
    {"connect$packet", 42},
    {"connect$phonet_pipe", 42},
    {"connect$pppl2tp", 42},
    {"connect$pppoe", 42},
    {"connect$pptp", 42},
    {"connect$qrtr", 42},
    {"connect$rds", 42},
    {"connect$rose", 42},
    {"connect$rxrpc", 42},
    {"connect$tipc", 42},
    {"connect$unix", 42},
    {"connect$vsock_dgram", 42},
    {"connect$vsock_stream", 42},
    {"connect$x25", 42},
    {"copy_file_range", 326},
    {"creat", 85},
    {"delete_module", 176},
    {"dup", 32},
    {"dup2", 33},
    {"dup3", 292},
    {"epoll_create", 213},
    {"epoll_create1", 291},
    {"epoll_ctl$EPOLL_CTL_ADD", 233},
    {"epoll_ctl$EPOLL_CTL_DEL", 233},
    {"epoll_ctl$EPOLL_CTL_MOD", 233},
    {"epoll_pwait", 281},
    {"epoll_wait", 232},
    {"eventfd", 284},
    {"eventfd2", 290},
    {"execve", 59},
    {"execveat", 322},
    {"exit", 60},
    {"exit_group", 231},
    {"faccessat", 269},
    {"faccessat2", 439},
    {"fadvise64", 221},
    {"fallocate", 285},
    {"fanotify_init", 300},
    {"fanotify_mark", 301},
    {"fchdir", 81},
    {"fchmod", 91},
    {"fchmodat", 268},
    {"fchown", 93},
    {"fchownat", 260},
    {"fcntl$F_GET_FILE_RW_HINT", 72},
    {"fcntl$F_GET_RW_HINT", 72},
    {"fcntl$F_SET_FILE_RW_HINT", 72},
    {"fcntl$F_SET_RW_HINT", 72},
    {"fcntl$addseals", 72},
    {"fcntl$dupfd", 72},
    {"fcntl$getflags", 72},
    {"fcntl$getown", 72},
    {"fcntl$getownex", 72},
    {"fcntl$lock", 72},
    {"fcntl$notify", 72},
    {"fcntl$setflags", 72},
    {"fcntl$setlease", 72},
    {"fcntl$setown", 72},
    {"fcntl$setownex", 72},
    {"fcntl$setpipe", 72},
    {"fcntl$setsig", 72},
    {"fcntl$setstatus", 72},
    {"fdatasync", 75},
    {"fgetxattr", 193},
    {"finit_module", 313},
    {"flistxattr", 196},
    {"flock", 73},
    {"fork", 57, {0, 0, 0, 0, 1}},
    {"fremovexattr", 199},
    {"fsconfig$FSCONFIG_CMD_CREATE", 431},
    {"fsconfig$FSCONFIG_CMD_RECONFIGURE", 431},
    {"fsconfig$FSCONFIG_SET_BINARY", 431},
    {"fsconfig$FSCONFIG_SET_FD", 431},
    {"fsconfig$FSCONFIG_SET_FLAG", 431},
    {"fsconfig$FSCONFIG_SET_PATH", 431},
    {"fsconfig$FSCONFIG_SET_PATH_EMPTY", 431},
    {"fsconfig$FSCONFIG_SET_STRING", 431},
    {"fsetxattr", 190},
    {"fsetxattr$security_capability", 190},
    {"fsetxattr$security_evm", 190},
    {"fsetxattr$security_ima", 190},
    {"fsetxattr$security_selinux", 190},
    {"fsetxattr$security_smack_transmute", 190},
    {"fsetxattr$smack_xattr_label", 190},
    {"fsetxattr$system_posix_acl", 190},
    {"fsetxattr$trusted_overlay_nlink", 190},
    {"fsetxattr$trusted_overlay_opaque", 190},
    {"fsetxattr$trusted_overlay_origin", 190},
    {"fsetxattr$trusted_overlay_redirect", 190},
    {"fsetxattr$trusted_overlay_upper", 190},
    {"fsmount", 432},
    {"fsopen", 430},
    {"fspick", 433},
    {"fstat", 5},
    {"fstatfs", 138},
    {"fsync", 74},
    {"ftruncate", 77},
    {"futex", 202},
    {"futimesat", 261},
    {"get_mempolicy", 239},
    {"get_robust_list", 274},
    {"get_thread_area", 211},
    {"getcwd", 79},
    {"getdents", 78},
    {"getdents64", 217},
    {"getegid", 108},
    {"geteuid", 107},
    {"getgid", 104},
    {"getgroups", 115},
    {"getitimer", 36},
    {"getpeername", 52},
    {"getpeername$ax25", 52},
    {"getpeername$inet", 52},
    {"getpeername$inet6", 52},
    {"getpeername$ipx", 52},
    {"getpeername$l2tp", 52},
    {"getpeername$l2tp6", 52},
    {"getpeername$llc", 52},
    {"getpeername$netlink", 52},
    {"getpeername$netrom", 52},
    {"getpeername$packet", 52},
    {"getpeername$qrtr", 52},
    {"getpeername$tipc", 52},
    {"getpeername$unix", 52},
    {"getpgid", 121},
    {"getpgrp", 111},
    {"getpid", 39},
    {"getpriority", 140},
    {"getrandom", 318},
    {"getresgid", 120},
    {"getresuid", 118},
    {"getrlimit", 97},
    {"getrusage", 98},
    {"getsockname", 51},
    {"getsockname$ax25", 51},
    {"getsockname$inet", 51},
    {"getsockname$inet6", 51},
    {"getsockname$ipx", 51},
    {"getsockname$l2tp", 51},
    {"getsockname$l2tp6", 51},
    {"getsockname$llc", 51},
    {"getsockname$netlink", 51},
    {"getsockname$netrom", 51},
    {"getsockname$packet", 51},
    {"getsockname$qrtr", 51},
    {"getsockname$tipc", 51},
    {"getsockname$unix", 51},
    {"getsockopt", 55},
    {"getsockopt$ARPT_SO_GET_ENTRIES", 55},
    {"getsockopt$ARPT_SO_GET_INFO", 55},
    {"getsockopt$ARPT_SO_GET_REVISION_TARGET", 55},
    {"getsockopt$CAN_RAW_FD_FRAMES", 55},
    {"getsockopt$CAN_RAW_FILTER", 55},
    {"getsockopt$CAN_RAW_JOIN_FILTERS", 55},
    {"getsockopt$CAN_RAW_LOOPBACK", 55},
    {"getsockopt$CAN_RAW_RECV_OWN_MSGS", 55},
    {"getsockopt$EBT_SO_GET_ENTRIES", 55},
    {"getsockopt$EBT_SO_GET_INFO", 55},
    {"getsockopt$EBT_SO_GET_INIT_ENTRIES", 55},
    {"getsockopt$EBT_SO_GET_INIT_INFO", 55},
    {"getsockopt$IP6T_SO_GET_ENTRIES", 55},
    {"getsockopt$IP6T_SO_GET_INFO", 55},
    {"getsockopt$IP6T_SO_GET_REVISION_MATCH", 55},
    {"getsockopt$IP6T_SO_GET_REVISION_TARGET", 55},
    {"getsockopt$IPT_SO_GET_ENTRIES", 55},
    {"getsockopt$IPT_SO_GET_INFO", 55},
    {"getsockopt$IPT_SO_GET_REVISION_MATCH", 55},
    {"getsockopt$IPT_SO_GET_REVISION_TARGET", 55},
    {"getsockopt$IP_SET_OP_GET_BYINDEX", 55},
    {"getsockopt$IP_SET_OP_GET_BYNAME", 55},
    {"getsockopt$IP_SET_OP_GET_FNAME", 55},
    {"getsockopt$IP_SET_OP_VERSION", 55},
    {"getsockopt$IP_VS_SO_GET_DAEMON", 55},
    {"getsockopt$IP_VS_SO_GET_DESTS", 55},
    {"getsockopt$IP_VS_SO_GET_INFO", 55},
    {"getsockopt$IP_VS_SO_GET_SERVICE", 55},
    {"getsockopt$IP_VS_SO_GET_SERVICES", 55},
    {"getsockopt$IP_VS_SO_GET_TIMEOUT", 55},
    {"getsockopt$IP_VS_SO_GET_VERSION", 55},
    {"getsockopt$MISDN_TIME_STAMP", 55},
    {"getsockopt$PNPIPE_ENCAP", 55},
    {"getsockopt$PNPIPE_HANDLE", 55},
    {"getsockopt$PNPIPE_IFINDEX", 55},
    {"getsockopt$PNPIPE_INITSTATE", 55},
    {"getsockopt$SO_BINDTODEVICE", 55},
    {"getsockopt$SO_COOKIE", 55},
    {"getsockopt$SO_J1939_ERRQUEUE", 55},
    {"getsockopt$SO_J1939_PROMISC", 55},
    {"getsockopt$SO_J1939_SEND_PRIO", 55},
    {"getsockopt$SO_TIMESTAMP", 55},
    {"getsockopt$SO_TIMESTAMPING", 55},
    {"getsockopt$TIPC_CONN_TIMEOUT", 55},
    {"getsockopt$TIPC_DEST_DROPPABLE", 55},
    {"getsockopt$TIPC_GROUP_JOIN", 55},
    {"getsockopt$TIPC_IMPORTANCE", 55},
    {"getsockopt$TIPC_NODE_RECVQ_DEPTH", 55},
    {"getsockopt$TIPC_SOCK_RECVQ_DEPTH", 55},
    {"getsockopt$TIPC_SRC_DROPPABLE", 55},
    {"getsockopt$WPAN_SECURITY", 55},
    {"getsockopt$WPAN_SECURITY_LEVEL", 55},
    {"getsockopt$WPAN_WANTACK", 55},
    {"getsockopt$WPAN_WANTLQI", 55},
    {"getsockopt$X25_QBITINCL", 55},
    {"getsockopt$XDP_MMAP_OFFSETS", 55},
    {"getsockopt$XDP_STATISTICS", 55},
    {"getsockopt$ax25_int", 55},
    {"getsockopt$bt_BT_CHANNEL_POLICY", 55},
    {"getsockopt$bt_BT_DEFER_SETUP", 55},
    {"getsockopt$bt_BT_FLUSHABLE", 55},
    {"getsockopt$bt_BT_POWER", 55},
    {"getsockopt$bt_BT_RCVMTU", 55},
    {"getsockopt$bt_BT_SECURITY", 55},
    {"getsockopt$bt_BT_SNDMTU", 55},
    {"getsockopt$bt_BT_VOICE", 55},
    {"getsockopt$bt_hci", 55},
    {"getsockopt$bt_l2cap_L2CAP_CONNINFO", 55},
    {"getsockopt$bt_l2cap_L2CAP_LM", 55},
    {"getsockopt$bt_l2cap_L2CAP_OPTIONS", 55},
    {"getsockopt$bt_rfcomm_RFCOMM_CONNINFO", 55},
    {"getsockopt$bt_rfcomm_RFCOMM_LM", 55},
    {"getsockopt$bt_sco_SCO_CONNINFO", 55},
    {"getsockopt$bt_sco_SCO_OPTIONS", 55},
    {"getsockopt$inet6_IPV6_FLOWLABEL_MGR", 55},
    {"getsockopt$inet6_IPV6_IPSEC_POLICY", 55},
    {"getsockopt$inet6_IPV6_XFRM_POLICY", 55},
    {"getsockopt$inet6_buf", 55},
    {"getsockopt$inet6_dccp_buf", 55},
    {"getsockopt$inet6_dccp_int", 55},
    {"getsockopt$inet6_int", 55},
    {"getsockopt$inet6_mreq", 55},
    {"getsockopt$inet6_mtu", 55},
    {"getsockopt$inet6_opts", 55},
    {"getsockopt$inet6_tcp_TCP_REPAIR_WINDOW", 55},
    {"getsockopt$inet6_tcp_TCP_ZEROCOPY_RECEIVE", 55},
    {"getsockopt$inet6_tcp_buf", 55},
    {"getsockopt$inet6_tcp_int", 55},
    {"getsockopt$inet6_udp_int", 55},
    {"getsockopt$inet_IP_IPSEC_POLICY", 55},
    {"getsockopt$inet_IP_XFRM_POLICY", 55},
    {"getsockopt$inet_buf", 55},
    {"getsockopt$inet_dccp_buf", 55},
    {"getsockopt$inet_dccp_int", 55},
    {"getsockopt$inet_int", 55},
    {"getsockopt$inet_mreq", 55},
    {"getsockopt$inet_mreqn", 55},
    {"getsockopt$inet_mreqsrc", 55},
    {"getsockopt$inet_mtu", 55},
    {"getsockopt$inet_opts", 55},
    {"getsockopt$inet_pktinfo", 55},
    {"getsockopt$inet_sctp6_SCTP_ADAPTATION_LAYER", 55},
    {"getsockopt$inet_sctp6_SCTP_ASSOCINFO", 55},
    {"getsockopt$inet_sctp6_SCTP_AUTH_ACTIVE_KEY", 55},
    {"getsockopt$inet_sctp6_SCTP_AUTOCLOSE", 55},
    {"getsockopt$inet_sctp6_SCTP_AUTO_ASCONF", 55},
    {"getsockopt$inet_sctp6_SCTP_CONTEXT", 55},
    {"getsockopt$inet_sctp6_SCTP_DEFAULT_PRINFO", 55},
    {"getsockopt$inet_sctp6_SCTP_DEFAULT_SEND_PARAM", 55},
    {"getsockopt$inet_sctp6_SCTP_DEFAULT_SNDINFO", 55},
    {"getsockopt$inet_sctp6_SCTP_DELAYED_SACK", 55},
    {"getsockopt$inet_sctp6_SCTP_DISABLE_FRAGMENTS", 55},
    {"getsockopt$inet_sctp6_SCTP_ENABLE_STREAM_RESET", 55},
    {"getsockopt$inet_sctp6_SCTP_EVENTS", 55},
    {"getsockopt$inet_sctp6_SCTP_FRAGMENT_INTERLEAVE", 55},
    {"getsockopt$inet_sctp6_SCTP_GET_ASSOC_ID_LIST", 55},
    {"getsockopt$inet_sctp6_SCTP_GET_ASSOC_NUMBER", 55},
    {"getsockopt$inet_sctp6_SCTP_GET_ASSOC_STATS", 55},
    {"getsockopt$inet_sctp6_SCTP_GET_LOCAL_ADDRS", 55},
    {"getsockopt$inet_sctp6_SCTP_GET_PEER_ADDRS", 55},
    {"getsockopt$inet_sctp6_SCTP_GET_PEER_ADDR_INFO", 55},
    {"getsockopt$inet_sctp6_SCTP_HMAC_IDENT", 55},
    {"getsockopt$inet_sctp6_SCTP_INITMSG", 55},
    {"getsockopt$inet_sctp6_SCTP_I_WANT_MAPPED_V4_ADDR", 55},
    {"getsockopt$inet_sctp6_SCTP_LOCAL_AUTH_CHUNKS", 55},
    {"getsockopt$inet_sctp6_SCTP_MAXSEG", 55},
    {"getsockopt$inet_sctp6_SCTP_MAX_BURST", 55},
    {"getsockopt$inet_sctp6_SCTP_NODELAY", 55},
    {"getsockopt$inet_sctp6_SCTP_PARTIAL_DELIVERY_POINT", 55},
    {"getsockopt$inet_sctp6_SCTP_PEER_ADDR_PARAMS", 55},
    {"getsockopt$inet_sctp6_SCTP_PEER_ADDR_THLDS", 55},
    {"getsockopt$inet_sctp6_SCTP_PEER_AUTH_CHUNKS", 55},
    {"getsockopt$inet_sctp6_SCTP_PRIMARY_ADDR", 55},
    {"getsockopt$inet_sctp6_SCTP_PR_ASSOC_STATUS", 55},
    {"getsockopt$inet_sctp6_SCTP_PR_STREAM_STATUS", 55},
    {"getsockopt$inet_sctp6_SCTP_PR_SUPPORTED", 55},
    {"getsockopt$inet_sctp6_SCTP_RECONFIG_SUPPORTED", 55},
    {"getsockopt$inet_sctp6_SCTP_RECVNXTINFO", 55},
    {"getsockopt$inet_sctp6_SCTP_RECVRCVINFO", 55},
    {"getsockopt$inet_sctp6_SCTP_RESET_STREAMS", 55},
    {"getsockopt$inet_sctp6_SCTP_RTOINFO", 55},
    {"getsockopt$inet_sctp6_SCTP_SOCKOPT_CONNECTX3", 55},
    {"getsockopt$inet_sctp6_SCTP_SOCKOPT_PEELOFF", 55},
    {"getsockopt$inet_sctp6_SCTP_STATUS", 55},
    {"getsockopt$inet_sctp6_SCTP_STREAM_SCHEDULER", 55},
    {"getsockopt$inet_sctp6_SCTP_STREAM_SCHEDULER_VALUE", 55},
    {"getsockopt$inet_sctp_SCTP_ADAPTATION_LAYER", 55},
    {"getsockopt$inet_sctp_SCTP_ASSOCINFO", 55},
    {"getsockopt$inet_sctp_SCTP_AUTH_ACTIVE_KEY", 55},
    {"getsockopt$inet_sctp_SCTP_AUTOCLOSE", 55},
    {"getsockopt$inet_sctp_SCTP_AUTO_ASCONF", 55},
    {"getsockopt$inet_sctp_SCTP_CONTEXT", 55},
    {"getsockopt$inet_sctp_SCTP_DEFAULT_PRINFO", 55},
    {"getsockopt$inet_sctp_SCTP_DEFAULT_SEND_PARAM", 55},
    {"getsockopt$inet_sctp_SCTP_DEFAULT_SNDINFO", 55},
    {"getsockopt$inet_sctp_SCTP_DELAYED_SACK", 55},
    {"getsockopt$inet_sctp_SCTP_DISABLE_FRAGMENTS", 55},
    {"getsockopt$inet_sctp_SCTP_ENABLE_STREAM_RESET", 55},
    {"getsockopt$inet_sctp_SCTP_EVENTS", 55},
    {"getsockopt$inet_sctp_SCTP_FRAGMENT_INTERLEAVE", 55},
    {"getsockopt$inet_sctp_SCTP_GET_ASSOC_ID_LIST", 55},
    {"getsockopt$inet_sctp_SCTP_GET_ASSOC_NUMBER", 55},
    {"getsockopt$inet_sctp_SCTP_GET_ASSOC_STATS", 55},
    {"getsockopt$inet_sctp_SCTP_GET_LOCAL_ADDRS", 55},
    {"getsockopt$inet_sctp_SCTP_GET_PEER_ADDRS", 55},
    {"getsockopt$inet_sctp_SCTP_GET_PEER_ADDR_INFO", 55},
    {"getsockopt$inet_sctp_SCTP_HMAC_IDENT", 55},
    {"getsockopt$inet_sctp_SCTP_INITMSG", 55},
    {"getsockopt$inet_sctp_SCTP_I_WANT_MAPPED_V4_ADDR", 55},
    {"getsockopt$inet_sctp_SCTP_LOCAL_AUTH_CHUNKS", 55},
    {"getsockopt$inet_sctp_SCTP_MAXSEG", 55},
    {"getsockopt$inet_sctp_SCTP_MAX_BURST", 55},
    {"getsockopt$inet_sctp_SCTP_NODELAY", 55},
    {"getsockopt$inet_sctp_SCTP_PARTIAL_DELIVERY_POINT", 55},
    {"getsockopt$inet_sctp_SCTP_PEER_ADDR_PARAMS", 55},
    {"getsockopt$inet_sctp_SCTP_PEER_ADDR_THLDS", 55},
    {"getsockopt$inet_sctp_SCTP_PEER_AUTH_CHUNKS", 55},
    {"getsockopt$inet_sctp_SCTP_PRIMARY_ADDR", 55},
    {"getsockopt$inet_sctp_SCTP_PR_ASSOC_STATUS", 55},
    {"getsockopt$inet_sctp_SCTP_PR_STREAM_STATUS", 55},
    {"getsockopt$inet_sctp_SCTP_PR_SUPPORTED", 55},
    {"getsockopt$inet_sctp_SCTP_RECONFIG_SUPPORTED", 55},
    {"getsockopt$inet_sctp_SCTP_RECVNXTINFO", 55},
    {"getsockopt$inet_sctp_SCTP_RECVRCVINFO", 55},
    {"getsockopt$inet_sctp_SCTP_RESET_STREAMS", 55},
    {"getsockopt$inet_sctp_SCTP_RTOINFO", 55},
    {"getsockopt$inet_sctp_SCTP_SOCKOPT_CONNECTX3", 55},
    {"getsockopt$inet_sctp_SCTP_SOCKOPT_PEELOFF", 55},
    {"getsockopt$inet_sctp_SCTP_STATUS", 55},
    {"getsockopt$inet_sctp_SCTP_STREAM_SCHEDULER", 55},
    {"getsockopt$inet_sctp_SCTP_STREAM_SCHEDULER_VALUE", 55},
    {"getsockopt$inet_tcp_TCP_REPAIR_WINDOW", 55},
    {"getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE", 55},
    {"getsockopt$inet_tcp_buf", 55},
    {"getsockopt$inet_tcp_int", 55},
    {"getsockopt$inet_udp_int", 55},
    {"getsockopt$ipx_IPX_TYPE", 55},
    {"getsockopt$kcm_KCM_RECV_DISABLE", 55},
    {"getsockopt$llc_int", 55},
    {"getsockopt$netlink", 55},
    {"getsockopt$netrom_NETROM_IDLE", 55},
    {"getsockopt$netrom_NETROM_N2", 55},
    {"getsockopt$netrom_NETROM_T1", 55},
    {"getsockopt$netrom_NETROM_T2", 55},
    {"getsockopt$netrom_NETROM_T4", 55},
    {"getsockopt$nfc_llcp", 55},
    {"getsockopt$packet_buf", 55},
    {"getsockopt$packet_int", 55},
    {"getsockopt$rose", 55},
    {"getsockopt$sock_buf", 55},
    {"getsockopt$sock_cred", 55},
    {"getsockopt$sock_int", 55},
    {"getsockopt$sock_linger", 55},
    {"getsockopt$sock_timeval", 55},
    {"gettid", 186},
    {"getuid", 102},
    {"getxattr", 191},
    {"init_module", 175},
    {"inotify_add_watch", 254},
    {"inotify_init", 253},
    {"inotify_init1", 294},
    {"inotify_rm_watch", 255},
    {"io_cancel", 210},
    {"io_destroy", 207},
    {"io_getevents", 208},
    {"io_pgetevents", 333},
    {"io_setup", 206},
    {"io_submit", 209},
    {"io_uring_enter", 426},
    {"io_uring_register$IORING_REGISTER_BUFFERS", 427},
    {"io_uring_register$IORING_REGISTER_EVENTFD", 427},
    {"io_uring_register$IORING_REGISTER_EVENTFD_ASYNC", 427},
    {"io_uring_register$IORING_REGISTER_FILES", 427},
    {"io_uring_register$IORING_REGISTER_FILES_UPDATE", 427},
    {"io_uring_register$IORING_REGISTER_PERSONALITY", 427},
    {"io_uring_register$IORING_REGISTER_PROBE", 427},
    {"io_uring_register$IORING_UNREGISTER_BUFFERS", 427},
    {"io_uring_register$IORING_UNREGISTER_EVENTFD", 427},
    {"io_uring_register$IORING_UNREGISTER_FILES", 427},
    {"io_uring_register$IORING_UNREGISTER_PERSONALITY", 427},
    {"io_uring_setup", 425},
    {"ioctl", 16},
    {"ioctl$ASHMEM_GET_NAME", 16},
    {"ioctl$ASHMEM_GET_PIN_STATUS", 16},
    {"ioctl$ASHMEM_GET_PROT_MASK", 16},
    {"ioctl$ASHMEM_GET_SIZE", 16},
    {"ioctl$ASHMEM_PURGE_ALL_CACHES", 16},
    {"ioctl$ASHMEM_SET_NAME", 16},
    {"ioctl$ASHMEM_SET_PROT_MASK", 16},
    {"ioctl$ASHMEM_SET_SIZE", 16},
    {"ioctl$BINDER_GET_NODE_DEBUG_INFO", 16},
    {"ioctl$BINDER_GET_NODE_INFO_FOR_REF", 16},
    {"ioctl$BINDER_SET_CONTEXT_MGR", 16},
    {"ioctl$BINDER_SET_CONTEXT_MGR_EXT", 16},
    {"ioctl$BINDER_SET_MAX_THREADS", 16},
    {"ioctl$BINDER_THREAD_EXIT", 16},
    {"ioctl$BINDER_WRITE_READ", 16},
    {"ioctl$BLKALIGNOFF", 16},
    {"ioctl$BLKBSZGET", 16},
    {"ioctl$BLKBSZSET", 16},
    {"ioctl$BLKDISCARD", 16},
    {"ioctl$BLKFLSBUF", 16},
    {"ioctl$BLKFRASET", 16},
    {"ioctl$BLKGETSIZE", 16},
    {"ioctl$BLKGETSIZE64", 16},
    {"ioctl$BLKIOMIN", 16},
    {"ioctl$BLKIOOPT", 16},
    {"ioctl$BLKPBSZGET", 16},
    {"ioctl$BLKPG", 16},
    {"ioctl$BLKRAGET", 16},
    {"ioctl$BLKREPORTZONE", 16},
    {"ioctl$BLKRESETZONE", 16},
    {"ioctl$BLKROGET", 16},
    {"ioctl$BLKROSET", 16},
    {"ioctl$BLKROTATIONAL", 16},
    {"ioctl$BLKRRPART", 16},
    {"ioctl$BLKSECDISCARD", 16},
    {"ioctl$BLKSECTGET", 16},
    {"ioctl$BLKTRACESETUP", 16},
    {"ioctl$BLKTRACESTART", 16},
    {"ioctl$BLKTRACESTOP", 16},
    {"ioctl$BLKTRACETEARDOWN", 16},
    {"ioctl$BLKZEROOUT", 16},
    {"ioctl$BTRFS_IOC_ADD_DEV", 16},
    {"ioctl$BTRFS_IOC_BALANCE", 16},
    {"ioctl$BTRFS_IOC_BALANCE_CTL", 16},
    {"ioctl$BTRFS_IOC_BALANCE_PROGRESS", 16},
    {"ioctl$BTRFS_IOC_BALANCE_V2", 16},
    {"ioctl$BTRFS_IOC_DEFAULT_SUBVOL", 16},
    {"ioctl$BTRFS_IOC_DEFRAG", 16},
    {"ioctl$BTRFS_IOC_DEFRAG_RANGE", 16},
    {"ioctl$BTRFS_IOC_DEV_INFO", 16},
    {"ioctl$BTRFS_IOC_DEV_REPLACE", 16},
    {"ioctl$BTRFS_IOC_FS_INFO", 16},
    {"ioctl$BTRFS_IOC_GET_DEV_STATS", 16},
    {"ioctl$BTRFS_IOC_GET_FEATURES", 16},
    {"ioctl$BTRFS_IOC_GET_SUBVOL_INFO", 16},
    {"ioctl$BTRFS_IOC_GET_SUBVOL_ROOTREF", 16},
    {"ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES", 16},
    {"ioctl$BTRFS_IOC_INO_LOOKUP", 16},
    {"ioctl$BTRFS_IOC_INO_LOOKUP_USER", 16},
    {"ioctl$BTRFS_IOC_INO_PATHS", 16},
    {"ioctl$BTRFS_IOC_LOGICAL_INO", 16},
    {"ioctl$BTRFS_IOC_LOGICAL_INO_V2", 16},
    {"ioctl$BTRFS_IOC_QGROUP_ASSIGN", 16},
    {"ioctl$BTRFS_IOC_QGROUP_CREATE", 16},
    {"ioctl$BTRFS_IOC_QGROUP_LIMIT", 16},
    {"ioctl$BTRFS_IOC_QUOTA_CTL", 16},
    {"ioctl$BTRFS_IOC_QUOTA_RESCAN", 16},
    {"ioctl$BTRFS_IOC_QUOTA_RESCAN_STATUS", 16},
    {"ioctl$BTRFS_IOC_QUOTA_RESCAN_WAIT", 16},
    {"ioctl$BTRFS_IOC_RESIZE", 16},
    {"ioctl$BTRFS_IOC_RM_DEV", 16},
    {"ioctl$BTRFS_IOC_RM_DEV_V2", 16},
    {"ioctl$BTRFS_IOC_SCRUB", 16},
    {"ioctl$BTRFS_IOC_SCRUB_CANCEL", 16},
    {"ioctl$BTRFS_IOC_SCRUB_PROGRESS", 16},
    {"ioctl$BTRFS_IOC_SEND", 16},
    {"ioctl$BTRFS_IOC_SET_FEATURES", 16},
    {"ioctl$BTRFS_IOC_SET_RECEIVED_SUBVOL", 16},
    {"ioctl$BTRFS_IOC_SNAP_CREATE", 16},
    {"ioctl$BTRFS_IOC_SNAP_CREATE_V2", 16},
    {"ioctl$BTRFS_IOC_SNAP_DESTROY", 16},
    {"ioctl$BTRFS_IOC_SNAP_DESTROY_V2", 16},
    {"ioctl$BTRFS_IOC_SPACE_INFO", 16},
    {"ioctl$BTRFS_IOC_START_SYNC", 16},
    {"ioctl$BTRFS_IOC_SUBVOL_CREATE", 16},
    {"ioctl$BTRFS_IOC_SUBVOL_CREATE_V2", 16},
    {"ioctl$BTRFS_IOC_SUBVOL_GETFLAGS", 16},
    {"ioctl$BTRFS_IOC_SUBVOL_SETFLAGS", 16},
    {"ioctl$BTRFS_IOC_SYNC", 16},
    {"ioctl$BTRFS_IOC_TREE_SEARCH", 16},
    {"ioctl$BTRFS_IOC_TREE_SEARCH_V2", 16},
    {"ioctl$BTRFS_IOC_WAIT_SYNC", 16},
    {"ioctl$CAPI_CLR_FLAGS", 16},
    {"ioctl$CAPI_GET_ERRCODE", 16},
    {"ioctl$CAPI_GET_FLAGS", 16},
    {"ioctl$CAPI_GET_MANUFACTURER", 16},
    {"ioctl$CAPI_GET_PROFILE", 16},
    {"ioctl$CAPI_GET_SERIAL", 16},
    {"ioctl$CAPI_INSTALLED", 16},
    {"ioctl$CAPI_MANUFACTURER_CMD", 16},
    {"ioctl$CAPI_NCCI_GETUNIT", 16},
    {"ioctl$CAPI_NCCI_OPENCOUNT", 16},
    {"ioctl$CAPI_REGISTER", 16},
    {"ioctl$CAPI_SET_FLAGS", 16},
    {"ioctl$CDROMCLOSETRAY", 16},
    {"ioctl$CDROMEJECT", 16},
    {"ioctl$CDROMEJECT_SW", 16},
    {"ioctl$CDROMGETSPINDOWN", 16},
    {"ioctl$CDROMMULTISESSION", 16},
    {"ioctl$CDROMPAUSE", 16},
    {"ioctl$CDROMPLAYBLK", 16},
    {"ioctl$CDROMPLAYMSF", 16},
    {"ioctl$CDROMPLAYTRKIND", 16},
    {"ioctl$CDROMREADALL", 16},
    {"ioctl$CDROMREADAUDIO", 16},
    {"ioctl$CDROMREADCOOKED", 16},
    {"ioctl$CDROMREADMODE1", 16},
    {"ioctl$CDROMREADMODE2", 16},
    {"ioctl$CDROMREADRAW", 16},
    {"ioctl$CDROMREADTOCENTRY", 16},
    {"ioctl$CDROMREADTOCHDR", 16},
    {"ioctl$CDROMRESET", 16},
    {"ioctl$CDROMRESUME", 16},
    {"ioctl$CDROMSEEK", 16},
    {"ioctl$CDROMSETSPINDOWN", 16},
    {"ioctl$CDROMSTART", 16},
    {"ioctl$CDROMSTOP", 16},
    {"ioctl$CDROMSUBCHNL", 16},
    {"ioctl$CDROMVOLCTRL", 16},
    {"ioctl$CDROMVOLREAD", 16},
    {"ioctl$CDROM_CHANGER_NSLOTS", 16},
    {"ioctl$CDROM_CLEAR_OPTIONS", 16},
    {"ioctl$CDROM_DEBUG", 16},
    {"ioctl$CDROM_DISC_STATUS", 16},
    {"ioctl$CDROM_GET_CAPABILITY", 16},
    {"ioctl$CDROM_GET_MCN", 16},
    {"ioctl$CDROM_LAST_WRITTEN", 16},
    {"ioctl$CDROM_LOCKDOOR", 16},
    {"ioctl$CDROM_MEDIA_CHANGED", 16},
    {"ioctl$CDROM_NEXT_WRITABLE", 16},
    {"ioctl$CDROM_SELECT_DISK", 16},
    {"ioctl$CDROM_SELECT_SPEED", 16},
    {"ioctl$CDROM_SEND_PACKET", 16},
    {"ioctl$CDROM_SET_OPTIONS", 16},
    {"ioctl$CHAR_RAW_ALIGNOFF", 16},
    {"ioctl$CHAR_RAW_BSZGET", 16},
    {"ioctl$CHAR_RAW_BSZSET", 16},
    {"ioctl$CHAR_RAW_DISCARD", 16},
    {"ioctl$CHAR_RAW_FLSBUF", 16},
    {"ioctl$CHAR_RAW_FRASET", 16},
    {"ioctl$CHAR_RAW_GETSIZE", 16},
    {"ioctl$CHAR_RAW_GETSIZE64", 16},
    {"ioctl$CHAR_RAW_HDIO_GETGEO", 16},
    {"ioctl$CHAR_RAW_IOMIN", 16},
    {"ioctl$CHAR_RAW_IOOPT", 16},
    {"ioctl$CHAR_RAW_PBSZGET", 16},
    {"ioctl$CHAR_RAW_PG", 16},
    {"ioctl$CHAR_RAW_RAGET", 16},
    {"ioctl$CHAR_RAW_REPORTZONE", 16},
    {"ioctl$CHAR_RAW_RESETZONE", 16},
    {"ioctl$CHAR_RAW_ROGET", 16},
    {"ioctl$CHAR_RAW_ROSET", 16},
    {"ioctl$CHAR_RAW_ROTATIONAL", 16},
    {"ioctl$CHAR_RAW_RRPART", 16},
    {"ioctl$CHAR_RAW_SECDISCARD", 16},
    {"ioctl$CHAR_RAW_SECTGET", 16},
    {"ioctl$CHAR_RAW_ZEROOUT", 16},
    {"ioctl$CREATE_COUNTERS", 16},
    {"ioctl$DESTROY_COUNTERS", 16},
    {"ioctl$DMA_BUF_IOCTL_SYNC", 16},
    {"ioctl$DRM_IOCTL_ADD_BUFS", 16},
    {"ioctl$DRM_IOCTL_ADD_CTX", 16},
    {"ioctl$DRM_IOCTL_ADD_MAP", 16},
    {"ioctl$DRM_IOCTL_AGP_ACQUIRE", 16},
    {"ioctl$DRM_IOCTL_AGP_ALLOC", 16},
    {"ioctl$DRM_IOCTL_AGP_BIND", 16},
    {"ioctl$DRM_IOCTL_AGP_ENABLE", 16},
    {"ioctl$DRM_IOCTL_AGP_FREE", 16},
    {"ioctl$DRM_IOCTL_AGP_INFO", 16},
    {"ioctl$DRM_IOCTL_AGP_RELEASE", 16},
    {"ioctl$DRM_IOCTL_AGP_UNBIND", 16},
    {"ioctl$DRM_IOCTL_AUTH_MAGIC", 16},
    {"ioctl$DRM_IOCTL_CONTROL", 16},
    {"ioctl$DRM_IOCTL_DMA", 16},
    {"ioctl$DRM_IOCTL_DROP_MASTER", 16},
    {"ioctl$DRM_IOCTL_FREE_BUFS", 16},
    {"ioctl$DRM_IOCTL_GEM_CLOSE", 16},
    {"ioctl$DRM_IOCTL_GEM_FLINK", 16},
    {"ioctl$DRM_IOCTL_GEM_OPEN", 16},
    {"ioctl$DRM_IOCTL_GET_CAP", 16},
    {"ioctl$DRM_IOCTL_GET_CLIENT", 16},
    {"ioctl$DRM_IOCTL_GET_CTX", 16},
    {"ioctl$DRM_IOCTL_GET_MAGIC", 16},
    {"ioctl$DRM_IOCTL_GET_MAP", 16},
    {"ioctl$DRM_IOCTL_GET_SAREA_CTX", 16},
    {"ioctl$DRM_IOCTL_GET_STATS", 16},
    {"ioctl$DRM_IOCTL_GET_UNIQUE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_BUSY", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_CONTEXT_CREATE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_CONTEXT_DESTROY", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_CONTEXT_SETPARAM", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_CREATE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_EXECBUFFER", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_EXECBUFFER2", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_EXECBUFFER2_WR", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_GET_APERTURE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_GET_CACHING", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_GET_TILING", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_MADVISE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_MMAP", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_MMAP_GTT", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_MMAP_OFFSET", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_PIN", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_PREAD", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_PWRITE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_SET_CACHING", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_SET_DOMAIN", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_SET_TILING", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_SW_FINISH", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_THROTTLE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_UNPIN", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_USERPTR", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_VM_CREATE", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_VM_DESTROY", 16},
    {"ioctl$DRM_IOCTL_I915_GEM_WAIT", 16},
    {"ioctl$DRM_IOCTL_I915_GETPARAM", 16},
    {"ioctl$DRM_IOCTL_I915_GET_PIPE_FROM_CRTC_ID", 16},
    {"ioctl$DRM_IOCTL_I915_GET_RESET_STATS", 16},
    {"ioctl$DRM_IOCTL_I915_OVERLAY_ATTRS", 16},
    {"ioctl$DRM_IOCTL_I915_OVERLAY_PUT_IMAGE", 16},
    {"ioctl$DRM_IOCTL_I915_PERF_ADD_CONFIG", 16},
    {"ioctl$DRM_IOCTL_I915_PERF_OPEN", 16},
    {"ioctl$DRM_IOCTL_I915_PERF_REMOVE_CONFIG", 16},
    {"ioctl$DRM_IOCTL_I915_QUERY", 16},
    {"ioctl$DRM_IOCTL_I915_REG_READ", 16},
    {"ioctl$DRM_IOCTL_I915_SET_SPRITE_COLORKEY", 16},
    {"ioctl$DRM_IOCTL_INFO_BUFS", 16},
    {"ioctl$DRM_IOCTL_IRQ_BUSID", 16},
    {"ioctl$DRM_IOCTL_LOCK", 16},
    {"ioctl$DRM_IOCTL_MAP_BUFS", 16},
    {"ioctl$DRM_IOCTL_MARK_BUFS", 16},
    {"ioctl$DRM_IOCTL_MODESET_CTL", 16},
    {"ioctl$DRM_IOCTL_MODE_ADDFB", 16},
    {"ioctl$DRM_IOCTL_MODE_ADDFB2", 16},
    {"ioctl$DRM_IOCTL_MODE_ATOMIC", 16},
    {"ioctl$DRM_IOCTL_MODE_CREATEPROPBLOB", 16},
    {"ioctl$DRM_IOCTL_MODE_CREATE_DUMB", 16},
    {"ioctl$DRM_IOCTL_MODE_CREATE_LEASE", 16},
    {"ioctl$DRM_IOCTL_MODE_CURSOR", 16},
    {"ioctl$DRM_IOCTL_MODE_CURSOR2", 16},
    {"ioctl$DRM_IOCTL_MODE_DESTROYPROPBLOB", 16},
    {"ioctl$DRM_IOCTL_MODE_DESTROY_DUMB", 16},
    {"ioctl$DRM_IOCTL_MODE_DIRTYFB", 16},
    {"ioctl$DRM_IOCTL_MODE_GETCONNECTOR", 16},
    {"ioctl$DRM_IOCTL_MODE_GETCRTC", 16},
    {"ioctl$DRM_IOCTL_MODE_GETENCODER", 16},
    {"ioctl$DRM_IOCTL_MODE_GETFB", 16},
    {"ioctl$DRM_IOCTL_MODE_GETGAMMA", 16},
    {"ioctl$DRM_IOCTL_MODE_GETPLANE", 16},
    {"ioctl$DRM_IOCTL_MODE_GETPLANERESOURCES", 16},
    {"ioctl$DRM_IOCTL_MODE_GETPROPBLOB", 16},
    {"ioctl$DRM_IOCTL_MODE_GETPROPERTY", 16},
    {"ioctl$DRM_IOCTL_MODE_GETRESOURCES", 16},
    {"ioctl$DRM_IOCTL_MODE_GET_LEASE", 16},
    {"ioctl$DRM_IOCTL_MODE_LIST_LESSEES", 16},
    {"ioctl$DRM_IOCTL_MODE_MAP_DUMB", 16},
    {"ioctl$DRM_IOCTL_MODE_OBJ_GETPROPERTIES", 16},
    {"ioctl$DRM_IOCTL_MODE_OBJ_SETPROPERTY", 16},
    {"ioctl$DRM_IOCTL_MODE_PAGE_FLIP", 16},
    {"ioctl$DRM_IOCTL_MODE_REVOKE_LEASE", 16},
    {"ioctl$DRM_IOCTL_MODE_RMFB", 16},
    {"ioctl$DRM_IOCTL_MODE_SETCRTC", 16},
    {"ioctl$DRM_IOCTL_MODE_SETGAMMA", 16},
    {"ioctl$DRM_IOCTL_MODE_SETPLANE", 16},
    {"ioctl$DRM_IOCTL_MODE_SETPROPERTY", 16},
    {"ioctl$DRM_IOCTL_NEW_CTX", 16},
    {"ioctl$DRM_IOCTL_PRIME_FD_TO_HANDLE", 16},
    {"ioctl$DRM_IOCTL_PRIME_HANDLE_TO_FD", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_CACHE_CACHEOPEXEC", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_CACHE_CACHEOPLOG", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_CACHE_CACHEOPQUEUE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_CMM_DEVMEMINTACQUIREREMOTECTX", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_CMM_DEVMEMINTEXPORTCTX", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_CMM_DEVMEMINTUNEXPORTCTX", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DEVICEMEMHISTORY_DEVICEMEMHISTORYMAP", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DEVICEMEMHISTORY_DEVICEMEMHISTORYMAPVRANGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DEVICEMEMHISTORY_DEVICEMEMHISTORYSPARSECHANGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DEVICEMEMHISTORY_DEVICEMEMHISTORYUNMAP", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DEVICEMEMHISTORY_DEVICEMEMHISTORYUNMAPVRANGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DMABUF_PHYSMEMEXPORTDMABUF", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DMABUF_PHYSMEMIMPORTDMABUF", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_DMABUF_PHYSMEMIMPORTSPARSEDMABUF", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_HTBUFFER_HTBCONTROL", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_HTBUFFER_HTBLOG", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_CHANGESPARSEMEM", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMFLUSHDEVSLCRANGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMGETFAULTADDRESS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTCTXCREATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTCTXDESTROY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTHEAPCREATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTHEAPDESTROY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTMAPPAGES", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTMAPPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTPIN", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTPINVALIDATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTREGISTERPFNOTIFYKM", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTRESERVERANGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTUNMAPPAGES", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTUNMAPPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTUNPIN", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTUNPININVALIDATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINTUNRESERVERANGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMINVALIDATEFBSCTABLE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_DEVMEMISVDEVADDRVALID", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_GETMAXDEVMEMSIZE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_HEAPCFGHEAPCONFIGCOUNT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_HEAPCFGHEAPCONFIGNAME", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_HEAPCFGHEAPCOUNT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_HEAPCFGHEAPDETAILS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PHYSMEMNEWRAMBACKEDLOCKEDPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PHYSMEMNEWRAMBACKEDPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMREXPORTPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRGETUID", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRIMPORTPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRLOCALIMPORTPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRMAKELOCALIMPORTHANDLE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRUNEXPORTPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRUNMAKELOCALIMPORTHANDLE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRUNREFPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PMRUNREFUNLOCKPMR", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_MM_PVRSRVUPDATEOOMSTATS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLACQUIREDATA", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLCLOSESTREAM", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLCOMMITSTREAM", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLDISCOVERSTREAMS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLOPENSTREAM", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLRELEASEDATA", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLRESERVESTREAM", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_PVRTL_TLWRITEDATA", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXBREAKPOINT_RGXCLEARBREAKPOINT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXBREAKPOINT_RGXDISABLEBREAKPOINT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXBREAKPOINT_RGXENABLEBREAKPOINT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXBREAKPOINT_RGXOVERALLOCATEBPREGISTERS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXBREAKPOINT_RGXSETBREAKPOINT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXCREATECOMPUTECONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXDESTROYCOMPUTECONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXFLUSHCOMPUTEDATA", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXGETLASTCOMPUTECONTEXTRESETREASON", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXKICKCDM2", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXNOTIFYCOMPUTEWRITEOFFSETUPDATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXSETCOMPUTECONTEXTPRIORITY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXCMP_RGXSETCOMPUTECONTEXTPROPERTY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXFWDBG_RGXCURRENTTIME", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXFWDBG_RGXFWDEBUGDUMPFREELISTPAGELIST", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXFWDBG_RGXFWDEBUGPHRCONFIGURE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXFWDBG_RGXFWDEBUGSETFWLOG", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXFWDBG_RGXFWDEBUGSETHCSDEADLINE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXFWDBG_RGXFWDEBUGSETOSIDPRIORITY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXFWDBG_RGXFWDEBUGSETOSNEWONLINESTATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXHWPERF_RGXCONFIGCUSTOMCOUNTERS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXHWPERF_RGXCONFIGENABLEHWPERFCOUNTERS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXHWPERF_RGXCTRLHWPERF", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXHWPERF_RGXCTRLHWPERFCOUNTERS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXHWPERF_RGXGETHWPERFBVNCFEATUREFLAGS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXKICKSYNC_RGXCREATEKICKSYNCCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXKICKSYNC_RGXDESTROYKICKSYNCCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXKICKSYNC_RGXKICKSYNC2", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXKICKSYNC_RGXSETKICKSYNCCONTEXTPROPERTY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXREGCONFIG_RGXADDREGCONFIG", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXREGCONFIG_RGXCLEARREGCONFIG", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXREGCONFIG_RGXDISABLEREGCONFIG", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXREGCONFIG_RGXENABLEREGCONFIG", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXREGCONFIG_RGXSETREGCONFIGTYPE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXSIGNALS_RGXNOTIFYSIGNALUPDATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXCREATEFREELIST", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXCREATEHWRTDATASET", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXCREATERENDERCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXCREATEZSBUFFER", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXDESTROYFREELIST", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXDESTROYHWRTDATASET", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXDESTROYRENDERCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXDESTROYZSBUFFER", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXGETLASTRENDERCONTEXTRESETREASON", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXKICKTA3D2", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXPOPULATEZSBUFFER", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXRENDERCONTEXTSTALLED", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXSETRENDERCONTEXTPRIORITY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXSETRENDERCONTEXTPROPERTY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTA3D_RGXUNPOPULATEZSBUFFER", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMCREATETRANSFERCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMDESTROYTRANSFERCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMGETSHAREDMEMORY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMNOTIFYWRITEOFFSETUPDATE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMRELEASESHAREDMEMORY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMSETTRANSFERCONTEXTPRIORITY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMSETTRANSFERCONTEXTPROPERTY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ2_RGXTDMSUBMITTRANSFER2", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ_RGXCREATETRANSFERCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ_RGXDESTROYTRANSFERCONTEXT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ_RGXSETTRANSFERCONTEXTPRIORITY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ_RGXSETTRANSFERCONTEXTPROPERTY", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_RGXTQ_RGXSUBMITTRANSFER2", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_ACQUIREGLOBALEVENTOBJECT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_ACQUIREINFOPAGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_ALIGNMENTCHECK", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_CONNECT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_DISCONNECT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_DUMPDEBUGINFO", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_EVENTOBJECTCLOSE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_EVENTOBJECTOPEN", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_EVENTOBJECTWAIT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_EVENTOBJECTWAITTIMEOUT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_FINDPROCESSMEMSTATS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_GETDEVCLOCKSPEED", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_GETDEVICESTATUS", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_GETMULTICOREINFO", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_HWOPTIMEOUT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_RELEASEGLOBALEVENTOBJECT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SRVCORE_RELEASEINFOPAGE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNCTRACKING_SYNCRECORDADD", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNCTRACKING_SYNCRECORDREMOVEBYHANDLE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_ALLOCSYNCPRIMITIVEBLOCK", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_FREESYNCPRIMITIVEBLOCK", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCALLOCEVENT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCCHECKPOINTSIGNALLEDPDUMPPOL", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCFREEEVENT", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCPRIMPDUMP", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCPRIMPDUMPCBP", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCPRIMPDUMPPOL", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCPRIMPDUMPVALUE", 16},
    {"ioctl$DRM_IOCTL_PVR_SRVKM_CMD_PVRSRV_BRIDGE_SYNC_SYNCPRIMSET", 16},
    {"ioctl$DRM_IOCTL_RES_CTX", 16},
    {"ioctl$DRM_IOCTL_RM_CTX", 16},
    {"ioctl$DRM_IOCTL_RM_MAP", 16},
    {"ioctl$DRM_IOCTL_SET_CLIENT_CAP", 16},
    {"ioctl$DRM_IOCTL_SET_MASTER", 16},
    {"ioctl$DRM_IOCTL_SET_SAREA_CTX", 16},
    {"ioctl$DRM_IOCTL_SET_UNIQUE", 16},
    {"ioctl$DRM_IOCTL_SET_VERSION", 16},
    {"ioctl$DRM_IOCTL_SG_ALLOC", 16},
    {"ioctl$DRM_IOCTL_SG_FREE", 16},
    {"ioctl$DRM_IOCTL_SWITCH_CTX", 16},
    {"ioctl$DRM_IOCTL_UNLOCK", 16},
    {"ioctl$DRM_IOCTL_VERSION", 16},
    {"ioctl$DRM_IOCTL_WAIT_VBLANK", 16},
    {"ioctl$DVD_AUTH", 16},
    {"ioctl$DVD_READ_STRUCT", 16},
    {"ioctl$DVD_WRITE_STRUCT", 16},
    {"ioctl$EVIOCGABS0", 16},
    {"ioctl$EVIOCGABS20", 16},
    {"ioctl$EVIOCGABS2F", 16},
    {"ioctl$EVIOCGABS3F", 16},
    {"ioctl$EVIOCGBITKEY", 16},
    {"ioctl$EVIOCGBITSND", 16},
    {"ioctl$EVIOCGBITSW", 16},
    {"ioctl$EVIOCGEFFECTS", 16},
    {"ioctl$EVIOCGID", 16},
    {"ioctl$EVIOCGKEY", 16},
    {"ioctl$EVIOCGKEYCODE", 16},
    {"ioctl$EVIOCGKEYCODE_V2", 16},
    {"ioctl$EVIOCGLED", 16},
    {"ioctl$EVIOCGMASK", 16},
    {"ioctl$EVIOCGMTSLOTS", 16},
    {"ioctl$EVIOCGNAME", 16},
    {"ioctl$EVIOCGPHYS", 16},
    {"ioctl$EVIOCGPROP", 16},
    {"ioctl$EVIOCGRAB", 16},
    {"ioctl$EVIOCGREP", 16},
    {"ioctl$EVIOCGSND", 16},
    {"ioctl$EVIOCGSW", 16},
    {"ioctl$EVIOCGUNIQ", 16},
    {"ioctl$EVIOCGVERSION", 16},
    {"ioctl$EVIOCREVOKE", 16},
    {"ioctl$EVIOCRMFF", 16},
    {"ioctl$EVIOCSABS0", 16},
    {"ioctl$EVIOCSABS20", 16},
    {"ioctl$EVIOCSABS2F", 16},
    {"ioctl$EVIOCSABS3F", 16},
    {"ioctl$EVIOCSCLOCKID", 16},
    {"ioctl$EVIOCSFF", 16},
    {"ioctl$EVIOCSKEYCODE", 16},
    {"ioctl$EVIOCSKEYCODE_V2", 16},
    {"ioctl$EVIOCSMASK", 16},
    {"ioctl$EVIOCSREP", 16},
    {"ioctl$EXT4_IOC_ALLOC_DA_BLKS", 16},
    {"ioctl$EXT4_IOC_GROUP_ADD", 16},
    {"ioctl$EXT4_IOC_GROUP_EXTEND", 16},
    {"ioctl$EXT4_IOC_MIGRATE", 16},
    {"ioctl$EXT4_IOC_MOVE_EXT", 16},
    {"ioctl$EXT4_IOC_PRECACHE_EXTENTS", 16},
    {"ioctl$EXT4_IOC_RESIZE_FS", 16, {1}},
    {"ioctl$EXT4_IOC_SHUTDOWN", 16, {1}},
    {"ioctl$EXT4_IOC_SWAP_BOOT", 16},
    {"ioctl$F2FS_IOC_ABORT_VOLATILE_WRITE", 16},
    {"ioctl$F2FS_IOC_COMMIT_ATOMIC_WRITE", 16},
    {"ioctl$F2FS_IOC_DEFRAGMENT", 16},
    {"ioctl$F2FS_IOC_FLUSH_DEVICE", 16},
    {"ioctl$F2FS_IOC_GARBAGE_COLLECT", 16},
    {"ioctl$F2FS_IOC_GARBAGE_COLLECT_RANGE", 16},
    {"ioctl$F2FS_IOC_GET_COMPRESS_BLOCKS", 16},
    {"ioctl$F2FS_IOC_GET_FEATURES", 16},
    {"ioctl$F2FS_IOC_GET_PIN_FILE", 16},
    {"ioctl$F2FS_IOC_MOVE_RANGE", 16},
    {"ioctl$F2FS_IOC_PRECACHE_EXTENTS", 16},
    {"ioctl$F2FS_IOC_RELEASE_COMPRESS_BLOCKS", 16},
    {"ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE", 16},
    {"ioctl$F2FS_IOC_RESERVE_COMPRESS_BLOCKS", 16},
    {"ioctl$F2FS_IOC_RESIZE_FS", 16},
    {"ioctl$F2FS_IOC_SET_PIN_FILE", 16},
    {"ioctl$F2FS_IOC_SHUTDOWN", 16, {1}},
    {"ioctl$F2FS_IOC_START_ATOMIC_WRITE", 16},
    {"ioctl$F2FS_IOC_START_VOLATILE_WRITE", 16},
    {"ioctl$F2FS_IOC_WRITE_CHECKPOINT", 16},
    {"ioctl$FBIOBLANK", 16},
    {"ioctl$FBIOGETCMAP", 16},
    {"ioctl$FBIOGET_CON2FBMAP", 16},
    {"ioctl$FBIOGET_FSCREENINFO", 16},
    {"ioctl$FBIOGET_VSCREENINFO", 16},
    {"ioctl$FBIOPAN_DISPLAY", 16},
    {"ioctl$FBIOPUTCMAP", 16},
    {"ioctl$FBIOPUT_CON2FBMAP", 16},
    {"ioctl$FBIOPUT_VSCREENINFO", 16},
    {"ioctl$FBIO_WAITFORVSYNC", 16},
    {"ioctl$FIBMAP", 16},
    {"ioctl$FICLONE", 16},
    {"ioctl$FICLONERANGE", 16},
    {"ioctl$FIDEDUPERANGE", 16},
    {"ioctl$FIFREEZE", 16, {1}},
    {"ioctl$FIGETBSZ", 16},
    {"ioctl$FIOCLEX", 16},
    {"ioctl$FIONCLEX", 16},
    {"ioctl$FIONREAD", 16},
    {"ioctl$FITHAW", 16},
    {"ioctl$FITRIM", 16},
    {"ioctl$FLOPPY_FDCLRPRM", 16},
    {"ioctl$FLOPPY_FDDEFPRM", 16},
    {"ioctl$FLOPPY_FDEJECT", 16},
    {"ioctl$FLOPPY_FDFLUSH", 16},
    {"ioctl$FLOPPY_FDFMTBEG", 16},
    {"ioctl$FLOPPY_FDFMTEND", 16},
    {"ioctl$FLOPPY_FDFMTTRK", 16},
    {"ioctl$FLOPPY_FDGETDRVPRM", 16},
    {"ioctl$FLOPPY_FDGETDRVSTAT", 16},
    {"ioctl$FLOPPY_FDGETDRVTYP", 16},
    {"ioctl$FLOPPY_FDGETFDCSTAT", 16},
    {"ioctl$FLOPPY_FDGETMAXERRS", 16},
    {"ioctl$FLOPPY_FDGETPRM", 16},
    {"ioctl$FLOPPY_FDMSGOFF", 16},
    {"ioctl$FLOPPY_FDMSGON", 16},
    {"ioctl$FLOPPY_FDPOLLDRVSTAT", 16},
    {"ioctl$FLOPPY_FDRAWCMD", 16},
    {"ioctl$FLOPPY_FDRESET", 16},
    {"ioctl$FLOPPY_FDSETDRVPRM", 16},
    {"ioctl$FLOPPY_FDSETEMSGTRESH", 16},
    {"ioctl$FLOPPY_FDSETMAXERRS", 16},
    {"ioctl$FLOPPY_FDSETPRM", 16},
    {"ioctl$FLOPPY_FDTWADDLE", 16},
    {"ioctl$FLOPPY_FDWERRORCLR", 16},
    {"ioctl$FLOPPY_FDWERRORGET", 16},
    {"ioctl$FS_IOC_ADD_ENCRYPTION_KEY", 16},
    {"ioctl$FS_IOC_ENABLE_VERITY", 16},
    {"ioctl$FS_IOC_FIEMAP", 16},
    {"ioctl$FS_IOC_FSGETXATTR", 16},
    {"ioctl$FS_IOC_FSSETXATTR", 16},
    {"ioctl$FS_IOC_GETFLAGS", 16},
    {"ioctl$FS_IOC_GETFSLABEL", 16},
    {"ioctl$FS_IOC_GETFSMAP", 16},
    {"ioctl$FS_IOC_GETVERSION", 16},
    {"ioctl$FS_IOC_GET_ENCRYPTION_KEY_STATUS", 16},
    {"ioctl$FS_IOC_GET_ENCRYPTION_NONCE", 16},
    {"ioctl$FS_IOC_GET_ENCRYPTION_POLICY", 16},
    {"ioctl$FS_IOC_GET_ENCRYPTION_POLICY_EX", 16},
    {"ioctl$FS_IOC_GET_ENCRYPTION_PWSALT", 16},
    {"ioctl$FS_IOC_MEASURE_VERITY", 16},
    {"ioctl$FS_IOC_READ_VERITY_METADATA", 16},
    {"ioctl$FS_IOC_REMOVE_ENCRYPTION_KEY", 16},
    {"ioctl$FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS", 16},
    {"ioctl$FS_IOC_RESVSP", 16},
    {"ioctl$FS_IOC_SETFLAGS", 16},
    {"ioctl$FS_IOC_SETFSLABEL", 16},
    {"ioctl$FS_IOC_SETVERSION", 16},
    {"ioctl$FS_IOC_SET_ENCRYPTION_POLICY", 16},
    {"ioctl$FUSE_DEV_IOC_CLONE", 16},
    {"ioctl$GIO_CMAP", 16},
    {"ioctl$GIO_FONT", 16},
    {"ioctl$GIO_FONTX", 16},
    {"ioctl$GIO_SCRNMAP", 16},
    {"ioctl$GIO_UNIMAP", 16},
    {"ioctl$GIO_UNISCRNMAP", 16},
    {"ioctl$HCIINQUIRY", 16},
    {"ioctl$HDIO_GETGEO", 16},
    {"ioctl$HIDIOCAPPLICATION", 16},
    {"ioctl$HIDIOCGCOLLECTIONINDEX", 16},
    {"ioctl$HIDIOCGCOLLECTIONINFO", 16},
    {"ioctl$HIDIOCGDEVINFO", 16},
    {"ioctl$HIDIOCGFEATURE", 16},
    {"ioctl$HIDIOCGFIELDINFO", 16},
    {"ioctl$HIDIOCGFLAG", 16},
    {"ioctl$HIDIOCGNAME", 16},
    {"ioctl$HIDIOCGPHYS", 16},
    {"ioctl$HIDIOCGRAWINFO", 16},
    {"ioctl$HIDIOCGRAWNAME", 16},
    {"ioctl$HIDIOCGRAWPHYS", 16},
    {"ioctl$HIDIOCGRDESC", 16},
    {"ioctl$HIDIOCGRDESCSIZE", 16},
    {"ioctl$HIDIOCGREPORT", 16},
    {"ioctl$HIDIOCGREPORTINFO", 16},
    {"ioctl$HIDIOCGSTRING", 16},
    {"ioctl$HIDIOCGUCODE", 16},
    {"ioctl$HIDIOCGUSAGE", 16},
    {"ioctl$HIDIOCGUSAGES", 16},
    {"ioctl$HIDIOCGVERSION", 16},
    {"ioctl$HIDIOCINITREPORT", 16},
    {"ioctl$HIDIOCSFEATURE", 16},
    {"ioctl$HIDIOCSFLAG", 16},
    {"ioctl$HIDIOCSREPORT", 16},
    {"ioctl$HIDIOCSUSAGE", 16},
    {"ioctl$HIDIOCSUSAGES", 16},
    {"ioctl$I2C_FUNCS", 16},
    {"ioctl$I2C_PEC", 16},
    {"ioctl$I2C_RDWR", 16},
    {"ioctl$I2C_RETRIES", 16},
    {"ioctl$I2C_SLAVE", 16},
    {"ioctl$I2C_SLAVE_FORCE", 16},
    {"ioctl$I2C_SMBUS", 16},
    {"ioctl$I2C_TENBIT", 16},
    {"ioctl$I2C_TIMEOUT", 16},
    {"ioctl$IMADDTIMER", 16},
    {"ioctl$IMCLEAR_L2", 16},
    {"ioctl$IMCTRLREQ", 16},
    {"ioctl$IMDELTIMER", 16},
    {"ioctl$IMGETCOUNT", 16},
    {"ioctl$IMGETDEVINFO", 16},
    {"ioctl$IMGETVERSION", 16},
    {"ioctl$IMHOLD_L1", 16},
    {"ioctl$IMSETDEVNAME", 16},
    {"ioctl$INCFS_IOC_CREATE_FILE", 16},
    {"ioctl$INCFS_IOC_FILL_BLOCKS", 16},
    {"ioctl$INCFS_IOC_GET_FILLED_BLOCKS", 16},
    {"ioctl$INCFS_IOC_PERMIT_FILL", 16},
    {"ioctl$INCFS_IOC_READ_FILE_SIGNATURE", 16},
    {"ioctl$INOTIFY_IOC_SETNEXTWD", 16},
    {"ioctl$IOCTL_CONFIG_SYS_RESOURCE_PARAMETERS", 16},
    {"ioctl$IOCTL_GET_NUM_DEVICES", 16},
    {"ioctl$IOCTL_START_ACCEL_DEV", 16},
    {"ioctl$IOCTL_STATUS_ACCEL_DEV", 16},
    {"ioctl$IOCTL_STOP_ACCEL_DEV", 16},
    {"ioctl$IOCTL_VMCI_CTX_ADD_NOTIFICATION", 16},
    {"ioctl$IOCTL_VMCI_CTX_GET_CPT_STATE", 16},
    {"ioctl$IOCTL_VMCI_CTX_REMOVE_NOTIFICATION", 16},
    {"ioctl$IOCTL_VMCI_CTX_SET_CPT_STATE", 16},
    {"ioctl$IOCTL_VMCI_DATAGRAM_RECEIVE", 16},
    {"ioctl$IOCTL_VMCI_DATAGRAM_SEND", 16},
    {"ioctl$IOCTL_VMCI_GET_CONTEXT_ID", 16},
    {"ioctl$IOCTL_VMCI_INIT_CONTEXT", 16},
    {"ioctl$IOCTL_VMCI_NOTIFICATIONS_RECEIVE", 16},
    {"ioctl$IOCTL_VMCI_NOTIFY_RESOURCE", 16},
    {"ioctl$IOCTL_VMCI_QUEUEPAIR_ALLOC", 16},
    {"ioctl$IOCTL_VMCI_QUEUEPAIR_DETACH", 16},
    {"ioctl$IOCTL_VMCI_QUEUEPAIR_SETPF", 16},
    {"ioctl$IOCTL_VMCI_QUEUEPAIR_SETVA", 16},
    {"ioctl$IOCTL_VMCI_SET_NOTIFY", 16},
    {"ioctl$IOCTL_VMCI_VERSION", 16},
    {"ioctl$IOCTL_VMCI_VERSION2", 16},
    {"ioctl$IOC_PR_CLEAR", 16},
    {"ioctl$IOC_PR_PREEMPT", 16},
    {"ioctl$IOC_PR_PREEMPT_ABORT", 16},
    {"ioctl$IOC_PR_REGISTER", 16},
    {"ioctl$IOC_PR_RELEASE", 16},
    {"ioctl$IOC_PR_RESERVE", 16},
    {"ioctl$IOC_WATCH_QUEUE_SET_FILTER", 16},
    {"ioctl$IOC_WATCH_QUEUE_SET_SIZE", 16},
    {"ioctl$ION_IOC_ALLOC", 16},
    {"ioctl$ION_IOC_HEAP_QUERY", 16},
    {"ioctl$KBASE_HWCNT_READER_CLEAR", 16},
    {"ioctl$KBASE_HWCNT_READER_DISABLE_EVENT", 16},
    {"ioctl$KBASE_HWCNT_READER_DUMP", 16},
    {"ioctl$KBASE_HWCNT_READER_ENABLE_EVENT", 16},
    {"ioctl$KBASE_HWCNT_READER_GET_API_VERSION", 16},
    {"ioctl$KBASE_HWCNT_READER_GET_BUFFER", 16},
    {"ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE", 16},
    {"ioctl$KBASE_HWCNT_READER_GET_HWVER", 16},
    {"ioctl$KBASE_HWCNT_READER_PUT_BUFFER", 16},
    {"ioctl$KBASE_HWCNT_READER_SET_INTERVAL", 16},
    {"ioctl$KBASE_IOCTL_DISJOINT_QUERY", 16},
    {"ioctl$KBASE_IOCTL_FENCE_VALIDATE", 16},
    {"ioctl$KBASE_IOCTL_GET_CONTEXT_ID", 16},
    {"ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO", 16},
    {"ioctl$KBASE_IOCTL_GET_DDK_VERSION", 16},
    {"ioctl$KBASE_IOCTL_GET_GPUPROPS", 16},
    {"ioctl$KBASE_IOCTL_HWCNT_CLEAR", 16},
    {"ioctl$KBASE_IOCTL_HWCNT_DUMP", 16},
    {"ioctl$KBASE_IOCTL_HWCNT_ENABLE", 16},
    {"ioctl$KBASE_IOCTL_HWCNT_READER_SETUP", 16},
    {"ioctl$KBASE_IOCTL_HWCNT_SET", 16},
    {"ioctl$KBASE_IOCTL_JOB_SUBMIT", 16},
    {"ioctl$KBASE_IOCTL_MEM_ALIAS", 16},
    {"ioctl$KBASE_IOCTL_MEM_ALLOC", 16},
    {"ioctl$KBASE_IOCTL_MEM_COMMIT", 16},
    {"ioctl$KBASE_IOCTL_MEM_EXEC_INIT", 16},
    {"ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET", 16},
    {"ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET", 16},
    {"ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE", 16},
    {"ioctl$KBASE_IOCTL_MEM_FREE", 16},
    {"ioctl$KBASE_IOCTL_MEM_IMPORT", 16},
    {"ioctl$KBASE_IOCTL_MEM_JIT_INIT", 16},
    {"ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2", 16},
    {"ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5", 16},
    {"ioctl$KBASE_IOCTL_MEM_PROFILE_ADD", 16},
    {"ioctl$KBASE_IOCTL_MEM_QUERY", 16},
    {"ioctl$KBASE_IOCTL_MEM_SYNC", 16},
    {"ioctl$KBASE_IOCTL_POST_TERM", 16},
    {"ioctl$KBASE_IOCTL_SET_FLAGS", 16},
    {"ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE", 16},
    {"ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP", 16},
    {"ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP", 16},
    {"ioctl$KBASE_IOCTL_STREAM_CREATE", 16},
    {"ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE", 16},
    {"ioctl$KBASE_IOCTL_TLSTREAM_FLUSH", 16},
    {"ioctl$KBASE_IOCTL_VERSION_CHECK", 16},
    {"ioctl$KDADDIO", 16},
    {"ioctl$KDDELIO", 16},
    {"ioctl$KDDISABIO", 16},
    {"ioctl$KDENABIO", 16},
    {"ioctl$KDFONTOP_COPY", 16},
    {"ioctl$KDFONTOP_GET", 16},
    {"ioctl$KDFONTOP_SET", 16},
    {"ioctl$KDFONTOP_SET_DEF", 16},
    {"ioctl$KDGETKEYCODE", 16},
    {"ioctl$KDGETLED", 16},
    {"ioctl$KDGETMODE", 16},
    {"ioctl$KDGKBDIACR", 16},
    {"ioctl$KDGKBENT", 16},
    {"ioctl$KDGKBLED", 16},
    {"ioctl$KDGKBMETA", 16},
    {"ioctl$KDGKBMODE", 16},
    {"ioctl$KDGKBSENT", 16},
    {"ioctl$KDGKBTYPE", 16},
    {"ioctl$KDMKTONE", 16},
    {"ioctl$KDSETKEYCODE", 16},
    {"ioctl$KDSETLED", 16},
    {"ioctl$KDSETMODE", 16},
    {"ioctl$KDSIGACCEPT", 16},
    {"ioctl$KDSKBENT", 16},
    {"ioctl$KDSKBLED", 16},
    {"ioctl$KDSKBMETA", 16},
    {"ioctl$KDSKBMODE", 16},
    {"ioctl$KDSKBSENT", 16},
    {"ioctl$KIOCSOUND", 16},
    {"ioctl$KVM_ARM_SET_DEVICE_ADDR", 16},
    {"ioctl$KVM_ASSIGN_DEV_IRQ", 16},
    {"ioctl$KVM_ASSIGN_PCI_DEVICE", 16},
    {"ioctl$KVM_ASSIGN_SET_INTX_MASK", 16},
    {"ioctl$KVM_ASSIGN_SET_MSIX_ENTRY", 16},
    {"ioctl$KVM_ASSIGN_SET_MSIX_NR", 16},
    {"ioctl$KVM_CHECK_EXTENSION", 16},
    {"ioctl$KVM_CHECK_EXTENSION_VM", 16},
    {"ioctl$KVM_CREATE_DEVICE", 16},
    {"ioctl$KVM_CREATE_IRQCHIP", 16},
    {"ioctl$KVM_CREATE_PIT2", 16},
    {"ioctl$KVM_CREATE_VCPU", 16},
    {"ioctl$KVM_CREATE_VM", 16},
    {"ioctl$KVM_DEASSIGN_DEV_IRQ", 16},
    {"ioctl$KVM_DEASSIGN_PCI_DEVICE", 16},
    {"ioctl$KVM_DIRTY_TLB", 16},
    {"ioctl$KVM_ENABLE_CAP", 16},
    {"ioctl$KVM_ENABLE_CAP_CPU", 16},
    {"ioctl$KVM_GET_API_VERSION", 16},
    {"ioctl$KVM_GET_CLOCK", 16},
    {"ioctl$KVM_GET_CPUID2", 16},
    {"ioctl$KVM_GET_DEBUGREGS", 16},
    {"ioctl$KVM_GET_DEVICE_ATTR", 16},
    {"ioctl$KVM_GET_DIRTY_LOG", 16},
    {"ioctl$KVM_GET_EMULATED_CPUID", 16},
    {"ioctl$KVM_GET_FPU", 16},
    {"ioctl$KVM_GET_IRQCHIP", 16},
    {"ioctl$KVM_GET_LAPIC", 16},
    {"ioctl$KVM_GET_MP_STATE", 16},
    {"ioctl$KVM_GET_MSRS", 16},
    {"ioctl$KVM_GET_MSR_INDEX_LIST", 16},
    {"ioctl$KVM_GET_NESTED_STATE", 16},
    {"ioctl$KVM_GET_NR_MMU_PAGES", 16},
    {"ioctl$KVM_GET_ONE_REG", 16},
    {"ioctl$KVM_GET_PIT", 16},
    {"ioctl$KVM_GET_PIT2", 16},
    {"ioctl$KVM_GET_REGS", 16},
    {"ioctl$KVM_GET_REG_LIST", 16},
    {"ioctl$KVM_GET_SREGS", 16},
    {"ioctl$KVM_GET_SUPPORTED_CPUID", 16},
    {"ioctl$KVM_GET_TSC_KHZ", 16},
    {"ioctl$KVM_GET_VCPU_EVENTS", 16},
    {"ioctl$KVM_GET_VCPU_MMAP_SIZE", 16},
    {"ioctl$KVM_GET_XCRS", 16},
    {"ioctl$KVM_GET_XSAVE", 16},
    {"ioctl$KVM_HAS_DEVICE_ATTR", 16},
    {"ioctl$KVM_HYPERV_EVENTFD", 16},
    {"ioctl$KVM_INTERRUPT", 16},
    {"ioctl$KVM_IOEVENTFD", 16},
    {"ioctl$KVM_IRQFD", 16},
    {"ioctl$KVM_IRQ_LINE", 16},
    {"ioctl$KVM_IRQ_LINE_STATUS", 16},
    {"ioctl$KVM_KVMCLOCK_CTRL", 16},
    {"ioctl$KVM_NMI", 16},
    {"ioctl$KVM_PPC_ALLOCATE_HTAB", 16},
    {"ioctl$KVM_PPC_GET_PVINFO", 16},
    {"ioctl$KVM_PPC_GET_SMMU_INFO", 16},
    {"ioctl$KVM_REGISTER_COALESCED_MMIO", 16},
    {"ioctl$KVM_REINJECT_CONTROL", 16},
    {"ioctl$KVM_RUN", 16},
    {"ioctl$KVM_S390_INTERRUPT_CPU", 16},
    {"ioctl$KVM_S390_UCAS_MAP", 16},
    {"ioctl$KVM_S390_UCAS_UNMAP", 16},
    {"ioctl$KVM_S390_VCPU_FAULT", 16},
    {"ioctl$KVM_SET_BOOT_CPU_ID", 16},
    {"ioctl$KVM_SET_CLOCK", 16},
    {"ioctl$KVM_SET_CPUID", 16},
    {"ioctl$KVM_SET_CPUID2", 16},
    {"ioctl$KVM_SET_DEBUGREGS", 16},
    {"ioctl$KVM_SET_DEVICE_ATTR", 16},
    {"ioctl$KVM_SET_FPU", 16},
    {"ioctl$KVM_SET_GSI_ROUTING", 16},
    {"ioctl$KVM_SET_GUEST_DEBUG", 16},
    {"ioctl$KVM_SET_IDENTITY_MAP_ADDR", 16},
    {"ioctl$KVM_SET_IRQCHIP", 16},
    {"ioctl$KVM_SET_LAPIC", 16},
    {"ioctl$KVM_SET_MP_STATE", 16},
    {"ioctl$KVM_SET_MSRS", 16},
    {"ioctl$KVM_SET_NESTED_STATE", 16},
    {"ioctl$KVM_SET_NR_MMU_PAGES", 16},
    {"ioctl$KVM_SET_ONE_REG", 16},
    {"ioctl$KVM_SET_PIT", 16},
    {"ioctl$KVM_SET_PIT2", 16},
    {"ioctl$KVM_SET_REGS", 16},
    {"ioctl$KVM_SET_SIGNAL_MASK", 16},
    {"ioctl$KVM_SET_SREGS", 16},
    {"ioctl$KVM_SET_TSC_KHZ", 16},
    {"ioctl$KVM_SET_TSS_ADDR", 16},
    {"ioctl$KVM_SET_USER_MEMORY_REGION", 16},
    {"ioctl$KVM_SET_VAPIC_ADDR", 16},
    {"ioctl$KVM_SET_VCPU_EVENTS", 16},
    {"ioctl$KVM_SET_XCRS", 16},
    {"ioctl$KVM_SET_XSAVE", 16},
    {"ioctl$KVM_SIGNAL_MSI", 16},
    {"ioctl$KVM_SMI", 16},
    {"ioctl$KVM_TPR_ACCESS_REPORTING", 16},
    {"ioctl$KVM_TRANSLATE", 16},
    {"ioctl$KVM_UNREGISTER_COALESCED_MMIO", 16},
    {"ioctl$KVM_X86_GET_MCE_CAP_SUPPORTED", 16},
    {"ioctl$KVM_X86_SETUP_MCE", 16},
    {"ioctl$KVM_X86_SET_MCE", 16},
    {"ioctl$KVM_XEN_HVM_CONFIG", 16},
    {"ioctl$LOOP_CHANGE_FD", 16},
    {"ioctl$LOOP_CLR_FD", 16},
    {"ioctl$LOOP_CTL_ADD", 16},
    {"ioctl$LOOP_CTL_GET_FREE", 16},
    {"ioctl$LOOP_CTL_REMOVE", 16},
    {"ioctl$LOOP_GET_STATUS", 16},
    {"ioctl$LOOP_GET_STATUS64", 16},
    {"ioctl$LOOP_SET_BLOCK_SIZE", 16},
    {"ioctl$LOOP_SET_CAPACITY", 16},
    {"ioctl$LOOP_SET_DIRECT_IO", 16},
    {"ioctl$LOOP_SET_FD", 16},
    {"ioctl$LOOP_SET_STATUS", 16},
    {"ioctl$LOOP_SET_STATUS64", 16},
    {"ioctl$MEDIA_IOC_REQUEST_ALLOC", 16},
    {"ioctl$MEDIA_REQUEST_IOC_QUEUE", 16},
    {"ioctl$MON_IOCG_STATS", 16},
    {"ioctl$MON_IOCH_MFLUSH", 16},
    {"ioctl$MON_IOCQ_RING_SIZE", 16},
    {"ioctl$MON_IOCQ_URB_LEN", 16},
    {"ioctl$MON_IOCT_RING_SIZE", 16},
    {"ioctl$MON_IOCX_GET", 16},
    {"ioctl$MON_IOCX_GETX", 16},
    {"ioctl$MON_IOCX_MFETCH", 16},
    {"ioctl$NBD_CLEAR_QUE", 16},
    {"ioctl$NBD_CLEAR_SOCK", 16},
    {"ioctl$NBD_DISCONNECT", 16},
    {"ioctl$NBD_DO_IT", 16},
    {"ioctl$NBD_SET_BLKSIZE", 16},
    {"ioctl$NBD_SET_FLAGS", 16},
    {"ioctl$NBD_SET_SIZE", 16},
    {"ioctl$NBD_SET_SIZE_BLOCKS", 16},
    {"ioctl$NBD_SET_SOCK", 16},
    {"ioctl$NBD_SET_TIMEOUT", 16},
    {"ioctl$NS_GET_NSTYPE", 16},
    {"ioctl$NS_GET_OWNER_UID", 16},
    {"ioctl$NS_GET_PARENT", 16},
    {"ioctl$NS_GET_USERNS", 16},
    {"ioctl$PERF_EVENT_IOC_DISABLE", 16},
    {"ioctl$PERF_EVENT_IOC_ENABLE", 16},
    {"ioctl$PERF_EVENT_IOC_ID", 16},
    {"ioctl$PERF_EVENT_IOC_MODIFY_ATTRIBUTES", 16},
    {"ioctl$PERF_EVENT_IOC_PAUSE_OUTPUT", 16},
    {"ioctl$PERF_EVENT_IOC_PERIOD", 16},
    {"ioctl$PERF_EVENT_IOC_QUERY_BPF", 16},
    {"ioctl$PERF_EVENT_IOC_REFRESH", 16},
    {"ioctl$PERF_EVENT_IOC_RESET", 16},
    {"ioctl$PERF_EVENT_IOC_SET_BPF", 16},
    {"ioctl$PERF_EVENT_IOC_SET_FILTER", 16},
    {"ioctl$PERF_EVENT_IOC_SET_OUTPUT", 16},
    {"ioctl$PIO_CMAP", 16},
    {"ioctl$PIO_FONT", 16},
    {"ioctl$PIO_FONTRESET", 16},
    {"ioctl$PIO_FONTX", 16},
    {"ioctl$PIO_SCRNMAP", 16},
    {"ioctl$PIO_UNIMAP", 16},
    {"ioctl$PIO_UNIMAPCLR", 16},
    {"ioctl$PIO_UNISCRNMAP", 16},
    {"ioctl$PPPIOCATTACH", 16},
    {"ioctl$PPPIOCATTCHAN", 16},
    {"ioctl$PPPIOCCONNECT", 16},
    {"ioctl$PPPIOCDISCONN", 16},
    {"ioctl$PPPIOCGCHAN", 16},
    {"ioctl$PPPIOCGDEBUG", 16},
    {"ioctl$PPPIOCGFLAGS", 16},
    {"ioctl$PPPIOCGFLAGS1", 16},
    {"ioctl$PPPIOCGIDLE", 16},
    {"ioctl$PPPIOCGL2TPSTATS", 16},
    {"ioctl$PPPIOCGMRU", 16},
    {"ioctl$PPPIOCGNPMODE", 16},
    {"ioctl$PPPIOCGUNIT", 16},
    {"ioctl$PPPIOCNEWUNIT", 16},
    {"ioctl$PPPIOCSACTIVE", 16},
    {"ioctl$PPPIOCSCOMPRESS", 16},
    {"ioctl$PPPIOCSDEBUG", 16},
    {"ioctl$PPPIOCSFLAGS", 16},
    {"ioctl$PPPIOCSFLAGS1", 16},
    {"ioctl$PPPIOCSMAXCID", 16},
    {"ioctl$PPPIOCSMRRU", 16},
    {"ioctl$PPPIOCSMRU", 16},
    {"ioctl$PPPIOCSMRU1", 16},
    {"ioctl$PPPIOCSNPMODE", 16},
    {"ioctl$PPPIOCSPASS", 16},
    {"ioctl$PPPOEIOCDFWD", 16},
    {"ioctl$PPPOEIOCSFWD", 16},
    {"ioctl$PTP_CLOCK_GETCAPS", 16},
    {"ioctl$PTP_ENABLE_PPS", 16},
    {"ioctl$PTP_EXTTS_REQUEST", 16},
    {"ioctl$PTP_EXTTS_REQUEST2", 16},
    {"ioctl$PTP_PEROUT_REQUEST", 16},
    {"ioctl$PTP_PEROUT_REQUEST2", 16},
    {"ioctl$PTP_PIN_GETFUNC", 16},
    {"ioctl$PTP_PIN_GETFUNC2", 16},
    {"ioctl$PTP_PIN_SETFUNC", 16},
    {"ioctl$PTP_PIN_SETFUNC2", 16},
    {"ioctl$PTP_SYS_OFFSET", 16},
    {"ioctl$PTP_SYS_OFFSET_EXTENDED", 16},
    {"ioctl$PTP_SYS_OFFSET_PRECISE", 16},
    {"ioctl$RAW_CHAR_CTRL_GETBIND", 16},
    {"ioctl$RAW_CHAR_CTRL_SETBIND", 16},
    {"ioctl$READ_COUNTERS", 16},
    {"ioctl$RFKILL_IOCTL_NOINPUT", 16},
    {"ioctl$RNDADDENTROPY", 16},
    {"ioctl$RNDADDTOENTCNT", 16},
    {"ioctl$RNDCLEARPOOL", 16},
    {"ioctl$RNDGETENTCNT", 16},
    {"ioctl$RNDZAPENTCNT", 16},
    {"ioctl$RTC_AIE_OFF", 16},
    {"ioctl$RTC_AIE_ON", 16},
    {"ioctl$RTC_ALM_READ", 16},
    {"ioctl$RTC_ALM_SET", 16},
    {"ioctl$RTC_EPOCH_READ", 16},
    {"ioctl$RTC_EPOCH_SET", 16},
    {"ioctl$RTC_IRQP_READ", 16},
    {"ioctl$RTC_IRQP_SET", 16},
    {"ioctl$RTC_PIE_OFF", 16},
    {"ioctl$RTC_PIE_ON", 16},
    {"ioctl$RTC_PLL_GET", 16},
    {"ioctl$RTC_PLL_SET", 16},
    {"ioctl$RTC_RD_TIME", 16},
    {"ioctl$RTC_SET_TIME", 16},
    {"ioctl$RTC_UIE_OFF", 16},
    {"ioctl$RTC_UIE_ON", 16},
    {"ioctl$RTC_VL_CLR", 16},
    {"ioctl$RTC_VL_READ", 16},
    {"ioctl$RTC_WIE_OFF", 16},
    {"ioctl$RTC_WIE_ON", 16},
    {"ioctl$RTC_WKALM_RD", 16},
    {"ioctl$RTC_WKALM_SET", 16},
    {"ioctl$SCSI_IOCTL_BENCHMARK_COMMAND", 16},
    {"ioctl$SCSI_IOCTL_DOORLOCK", 16},
    {"ioctl$SCSI_IOCTL_DOORUNLOCK", 16},
    {"ioctl$SCSI_IOCTL_GET_BUS_NUMBER", 16},
    {"ioctl$SCSI_IOCTL_GET_IDLUN", 16},
    {"ioctl$SCSI_IOCTL_GET_PCI", 16},
    {"ioctl$SCSI_IOCTL_PROBE_HOST", 16},
    {"ioctl$SCSI_IOCTL_SEND_COMMAND", 16},
    {"ioctl$SCSI_IOCTL_START_UNIT", 16},
    {"ioctl$SCSI_IOCTL_STOP_UNIT", 16},
    {"ioctl$SCSI_IOCTL_SYNC", 16},
    {"ioctl$SCSI_IOCTL_TEST_UNIT_READY", 16},
    {"ioctl$SECCOMP_IOCTL_NOTIF_ADDFD", 16, {0, 0, 0, 0, 1}},
    {"ioctl$SECCOMP_IOCTL_NOTIF_ID_VALID", 16, {0, 0, 0, 0, 1}},
    {"ioctl$SECCOMP_IOCTL_NOTIF_RECV", 16, {0, 0, 0, 0, 1}},
    {"ioctl$SECCOMP_IOCTL_NOTIF_SEND", 16, {0, 0, 0, 0, 1}},
    {"ioctl$SG_EMULATED_HOST", 16},
    {"ioctl$SG_GET_ACCESS_COUNT", 16},
    {"ioctl$SG_GET_COMMAND_Q", 16},
    {"ioctl$SG_GET_KEEP_ORPHAN", 16},
    {"ioctl$SG_GET_LOW_DMA", 16},
    {"ioctl$SG_GET_NUM_WAITING", 16},
    {"ioctl$SG_GET_PACK_ID", 16},
    {"ioctl$SG_GET_REQUEST_TABLE", 16},
    {"ioctl$SG_GET_RESERVED_SIZE", 16},
    {"ioctl$SG_GET_SCSI_ID", 16},
    {"ioctl$SG_GET_SG_TABLESIZE", 16},
    {"ioctl$SG_GET_TIMEOUT", 16},
    {"ioctl$SG_GET_VERSION_NUM", 16},
    {"ioctl$SG_IO", 16},
    {"ioctl$SG_NEXT_CMD_LEN", 16},
    {"ioctl$SG_SCSI_RESET", 16},
    {"ioctl$SG_SET_COMMAND_Q", 16},
    {"ioctl$SG_SET_DEBUG", 16},
    {"ioctl$SG_SET_FORCE_PACK_ID", 16},
    {"ioctl$SG_SET_KEEP_ORPHAN", 16},
    {"ioctl$SG_SET_RESERVED_SIZE", 16},
    {"ioctl$SG_SET_TIMEOUT", 16},
    {"ioctl$SIOCAX25ADDFWD", 16},
    {"ioctl$SIOCAX25ADDUID", 16},
    {"ioctl$SIOCAX25CTLCON", 16},
    {"ioctl$SIOCAX25DELFWD", 16},
    {"ioctl$SIOCAX25DELUID", 16},
    {"ioctl$SIOCAX25GETINFO", 16},
    {"ioctl$SIOCAX25GETINFOOLD", 16},
    {"ioctl$SIOCAX25GETUID", 16},
    {"ioctl$SIOCAX25NOUID", 16},
    {"ioctl$SIOCAX25OPTRT", 16},
    {"ioctl$SIOCGETLINKNAME", 16},
    {"ioctl$SIOCGETNODEID", 16},
    {"ioctl$SIOCGIFHWADDR", 16},
    {"ioctl$SIOCGIFMTU", 16},
    {"ioctl$SIOCGSTAMP", 16},
    {"ioctl$SIOCGSTAMPNS", 16},
    {"ioctl$SIOCNRDECOBS", 16},
    {"ioctl$SIOCPNADDRESOURCE", 16},
    {"ioctl$SIOCPNDELRESOURCE", 16},
    {"ioctl$SIOCPNENABLEPIPE", 16},
    {"ioctl$SIOCPNGETOBJECT", 16},
    {"ioctl$SIOCRSACCEPT", 16},
    {"ioctl$SIOCRSGCAUSE", 16},
    {"ioctl$SIOCRSGL2CALL", 16},
    {"ioctl$SIOCRSSCAUSE", 16},
    {"ioctl$SIOCRSSL2CALL", 16},
    {"ioctl$SIOCSIFHWADDR", 16},
    {"ioctl$SIOCSIFMTU", 16},
    {"ioctl$SIOCX25CALLACCPTAPPRV", 16},
    {"ioctl$SIOCX25GCALLUSERDATA", 16},
    {"ioctl$SIOCX25GCAUSEDIAG", 16},
    {"ioctl$SIOCX25GDTEFACILITIES", 16},
    {"ioctl$SIOCX25GFACILITIES", 16},
    {"ioctl$SIOCX25GSUBSCRIP", 16},
    {"ioctl$SIOCX25SCALLUSERDATA", 16},
    {"ioctl$SIOCX25SCAUSEDIAG", 16},
    {"ioctl$SIOCX25SCUDMATCHLEN", 16},
    {"ioctl$SIOCX25SDTEFACILITIES", 16},
    {"ioctl$SIOCX25SENDCALLACCPT", 16},
    {"ioctl$SIOCX25SFACILITIES", 16},
    {"ioctl$SIOCX25SSUBSCRIP", 16},
    {"ioctl$SNAPSHOT_ALLOC_SWAP_PAGE", 16},
    {"ioctl$SNAPSHOT_ATOMIC_RESTORE", 16},
    {"ioctl$SNAPSHOT_AVAIL_SWAP_SIZE", 16},
    {"ioctl$SNAPSHOT_CREATE_IMAGE", 16},
    {"ioctl$SNAPSHOT_FREE", 16},
    {"ioctl$SNAPSHOT_FREEZE", 16, {1}},
    {"ioctl$SNAPSHOT_FREE_SWAP_PAGES", 16},
    {"ioctl$SNAPSHOT_GET_IMAGE_SIZE", 16},
    {"ioctl$SNAPSHOT_PLATFORM_SUPPORT", 16},
    {"ioctl$SNAPSHOT_POWER_OFF", 16, {1}},
    {"ioctl$SNAPSHOT_PREF_IMAGE_SIZE", 16},
    {"ioctl$SNAPSHOT_S2RAM", 16},
    {"ioctl$SNAPSHOT_SET_SWAP_AREA", 16},
    {"ioctl$SNAPSHOT_UNFREEZE", 16},
    {"ioctl$SNDCTL_DSP_CHANNELS", 16},
    {"ioctl$SNDCTL_DSP_GETBLKSIZE", 16},
    {"ioctl$SNDCTL_DSP_GETCAPS", 16},
    {"ioctl$SNDCTL_DSP_GETFMTS", 16},
    {"ioctl$SNDCTL_DSP_GETIPTR", 16},
    {"ioctl$SNDCTL_DSP_GETISPACE", 16},
    {"ioctl$SNDCTL_DSP_GETODELAY", 16},
    {"ioctl$SNDCTL_DSP_GETOPTR", 16},
    {"ioctl$SNDCTL_DSP_GETOSPACE", 16},
    {"ioctl$SNDCTL_DSP_GETTRIGGER", 16},
    {"ioctl$SNDCTL_DSP_NONBLOCK", 16},
    {"ioctl$SNDCTL_DSP_POST", 16},
    {"ioctl$SNDCTL_DSP_RESET", 16},
    {"ioctl$SNDCTL_DSP_SETDUPLEX", 16},
    {"ioctl$SNDCTL_DSP_SETFMT", 16},
    {"ioctl$SNDCTL_DSP_SETFRAGMENT", 16},
    {"ioctl$SNDCTL_DSP_SETTRIGGER", 16},
    {"ioctl$SNDCTL_DSP_SPEED", 16},
    {"ioctl$SNDCTL_DSP_STEREO", 16},
    {"ioctl$SNDCTL_DSP_SUBDIVIDE", 16},
    {"ioctl$SNDCTL_DSP_SYNC", 16},
    {"ioctl$SNDCTL_FM_4OP_ENABLE", 16},
    {"ioctl$SNDCTL_FM_LOAD_INSTR", 16},
    {"ioctl$SNDCTL_MIDI_INFO", 16},
    {"ioctl$SNDCTL_MIDI_PRETIME", 16},
    {"ioctl$SNDCTL_SEQ_CTRLRATE", 16},
    {"ioctl$SNDCTL_SEQ_GETINCOUNT", 16},
    {"ioctl$SNDCTL_SEQ_GETOUTCOUNT", 16},
    {"ioctl$SNDCTL_SEQ_GETTIME", 16},
    {"ioctl$SNDCTL_SEQ_NRMIDIS", 16},
    {"ioctl$SNDCTL_SEQ_NRSYNTHS", 16},
    {"ioctl$SNDCTL_SEQ_OUTOFBAND", 16},
    {"ioctl$SNDCTL_SEQ_PANIC", 16},
    {"ioctl$SNDCTL_SEQ_RESET", 16},
    {"ioctl$SNDCTL_SEQ_RESETSAMPLES", 16},
    {"ioctl$SNDCTL_SEQ_SYNC", 16},
    {"ioctl$SNDCTL_SEQ_TESTMIDI", 16},
    {"ioctl$SNDCTL_SEQ_THRESHOLD", 16},
    {"ioctl$SNDCTL_SYNTH_ID", 16},
    {"ioctl$SNDCTL_SYNTH_INFO", 16},
    {"ioctl$SNDCTL_SYNTH_MEMAVL", 16},
    {"ioctl$SNDCTL_TMR_CONTINUE", 16},
    {"ioctl$SNDCTL_TMR_METRONOME", 16},
    {"ioctl$SNDCTL_TMR_SELECT", 16},
    {"ioctl$SNDCTL_TMR_SOURCE", 16},
    {"ioctl$SNDCTL_TMR_START", 16},
    {"ioctl$SNDCTL_TMR_STOP", 16},
    {"ioctl$SNDCTL_TMR_TEMPO", 16},
    {"ioctl$SNDCTL_TMR_TIMEBASE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_CARD_INFO", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_ADD", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_INFO", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_LIST", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_LOCK", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_READ", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_REMOVE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_REPLACE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_UNLOCK", 16},
    {"ioctl$SNDRV_CTL_IOCTL_ELEM_WRITE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_HWDEP_INFO", 16},
    {"ioctl$SNDRV_CTL_IOCTL_HWDEP_NEXT_DEVICE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_PCM_INFO", 16},
    {"ioctl$SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_POWER_STATE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_PVERSION", 16},
    {"ioctl$SNDRV_CTL_IOCTL_RAWMIDI_INFO", 16},
    {"ioctl$SNDRV_CTL_IOCTL_RAWMIDI_NEXT_DEVICE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_RAWMIDI_PREFER_SUBDEVICE", 16},
    {"ioctl$SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS", 16},
    {"ioctl$SNDRV_CTL_IOCTL_TLV_COMMAND", 16},
    {"ioctl$SNDRV_CTL_IOCTL_TLV_READ", 16},
    {"ioctl$SNDRV_CTL_IOCTL_TLV_WRITE", 16},
    {"ioctl$SNDRV_FIREWIRE_IOCTL_GET_INFO", 16},
    {"ioctl$SNDRV_FIREWIRE_IOCTL_LOCK", 16},
    {"ioctl$SNDRV_FIREWIRE_IOCTL_TASCAM_STATE", 16},
    {"ioctl$SNDRV_FIREWIRE_IOCTL_UNLOCK", 16},
    {"ioctl$SNDRV_HWDEP_IOCTL_DSP_LOAD", 16},
    {"ioctl$SNDRV_HWDEP_IOCTL_DSP_STATUS", 16},
    {"ioctl$SNDRV_HWDEP_IOCTL_INFO", 16},
    {"ioctl$SNDRV_HWDEP_IOCTL_PVERSION", 16},
    {"ioctl$SNDRV_PCM_IOCTL_CHANNEL_INFO", 16},
    {"ioctl$SNDRV_PCM_IOCTL_DELAY", 16},
    {"ioctl$SNDRV_PCM_IOCTL_DRAIN", 16},
    {"ioctl$SNDRV_PCM_IOCTL_DROP", 16},
    {"ioctl$SNDRV_PCM_IOCTL_FORWARD", 16},
    {"ioctl$SNDRV_PCM_IOCTL_HWSYNC", 16},
    {"ioctl$SNDRV_PCM_IOCTL_HW_FREE", 16},
    {"ioctl$SNDRV_PCM_IOCTL_HW_PARAMS", 16},
    {"ioctl$SNDRV_PCM_IOCTL_HW_PARAMS_OLD", 16},
    {"ioctl$SNDRV_PCM_IOCTL_HW_REFINE", 16},
    {"ioctl$SNDRV_PCM_IOCTL_HW_REFINE_OLD", 16},
    {"ioctl$SNDRV_PCM_IOCTL_INFO", 16},
    {"ioctl$SNDRV_PCM_IOCTL_LINK", 16},
    {"ioctl$SNDRV_PCM_IOCTL_PAUSE", 16},
    {"ioctl$SNDRV_PCM_IOCTL_PREPARE", 16},
    {"ioctl$SNDRV_PCM_IOCTL_READI_FRAMES", 16},
    {"ioctl$SNDRV_PCM_IOCTL_READN_FRAMES", 16},
    {"ioctl$SNDRV_PCM_IOCTL_RESET", 16},
    {"ioctl$SNDRV_PCM_IOCTL_RESUME", 16},
    {"ioctl$SNDRV_PCM_IOCTL_REWIND", 16},
    {"ioctl$SNDRV_PCM_IOCTL_START", 16},
    {"ioctl$SNDRV_PCM_IOCTL_STATUS32", 16},
    {"ioctl$SNDRV_PCM_IOCTL_STATUS64", 16},
    {"ioctl$SNDRV_PCM_IOCTL_STATUS_EXT32", 16},
    {"ioctl$SNDRV_PCM_IOCTL_STATUS_EXT64", 16},
    {"ioctl$SNDRV_PCM_IOCTL_SW_PARAMS", 16},
    {"ioctl$SNDRV_PCM_IOCTL_SYNC_PTR", 16},
    {"ioctl$SNDRV_PCM_IOCTL_TTSTAMP", 16},
    {"ioctl$SNDRV_PCM_IOCTL_UNLINK", 16},
    {"ioctl$SNDRV_PCM_IOCTL_USER_PVERSION", 16},
    {"ioctl$SNDRV_PCM_IOCTL_WRITEI_FRAMES", 16},
    {"ioctl$SNDRV_PCM_IOCTL_WRITEN_FRAMES", 16},
    {"ioctl$SNDRV_PCM_IOCTL_XRUN", 16},
    {"ioctl$SNDRV_RAWMIDI_IOCTL_DRAIN", 16},
    {"ioctl$SNDRV_RAWMIDI_IOCTL_DROP", 16},
    {"ioctl$SNDRV_RAWMIDI_IOCTL_INFO", 16},
    {"ioctl$SNDRV_RAWMIDI_IOCTL_PARAMS", 16},
    {"ioctl$SNDRV_RAWMIDI_IOCTL_PVERSION", 16},
    {"ioctl$SNDRV_RAWMIDI_IOCTL_STATUS32", 16},
    {"ioctl$SNDRV_RAWMIDI_IOCTL_STATUS64", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_CLIENT_ID", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_CREATE_PORT", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_CREATE_QUEUE", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_DELETE_PORT", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_DELETE_QUEUE", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_CLIENT_INFO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_CLIENT_POOL", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_PORT_INFO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_QUEUE_INFO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_PVERSION", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_QUERY_SUBS", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_REMOVE_EVENTS", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_RUNNING_MODE", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SET_CLIENT_INFO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SET_CLIENT_POOL", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SET_PORT_INFO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_INFO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_SYSTEM_INFO", 16},
    {"ioctl$SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_CONTINUE", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_GINFO", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_GPARAMS", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_GSTATUS", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_INFO", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_NEXT_DEVICE", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_PARAMS", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_PAUSE", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_PVERSION", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_SELECT", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_START", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_STATUS32", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_STATUS64", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_STOP", 16},
    {"ioctl$SNDRV_TIMER_IOCTL_TREAD", 16},
    {"ioctl$SOUND_MIXER_INFO", 16},
    {"ioctl$SOUND_MIXER_READ_CAPS", 16},
    {"ioctl$SOUND_MIXER_READ_DEVMASK", 16},
    {"ioctl$SOUND_MIXER_READ_RECMASK", 16},
    {"ioctl$SOUND_MIXER_READ_RECSRC", 16},
    {"ioctl$SOUND_MIXER_READ_STEREODEVS", 16},
    {"ioctl$SOUND_MIXER_READ_VOLUME", 16},
    {"ioctl$SOUND_MIXER_WRITE_RECSRC", 16},
    {"ioctl$SOUND_MIXER_WRITE_VOLUME", 16},
    {"ioctl$SOUND_OLD_MIXER_INFO", 16},
    {"ioctl$SOUND_PCM_READ_BITS", 16},
    {"ioctl$SOUND_PCM_READ_CHANNELS", 16},
    {"ioctl$SOUND_PCM_READ_RATE", 16},
    {"ioctl$TCFLSH", 16},
    {"ioctl$TCGETA", 16},
    {"ioctl$TCGETS", 16},
    {"ioctl$TCGETS2", 16},
    {"ioctl$TCSBRK", 16},
    {"ioctl$TCSBRKP", 16},
    {"ioctl$TCSETA", 16},
    {"ioctl$TCSETAF", 16},
    {"ioctl$TCSETAW", 16},
    {"ioctl$TCSETS", 16},
    {"ioctl$TCSETS2", 16},
    {"ioctl$TCSETSF", 16},
    {"ioctl$TCSETSF2", 16},
    {"ioctl$TCSETSW", 16},
    {"ioctl$TCSETSW2", 16},
    {"ioctl$TCXONC", 16},
    {"ioctl$TE_IOCTL_CLOSE_CLIENT_SESSION", 16},
    {"ioctl$TE_IOCTL_LAUNCH_OPERATION", 16},
    {"ioctl$TE_IOCTL_OPEN_CLIENT_SESSION", 16},
    {"ioctl$TE_IOCTL_SS_CMD", 16},
    {"ioctl$TIOCCBRK", 16},
    {"ioctl$TIOCCONS", 16},
    {"ioctl$TIOCEXCL", 16},
    {"ioctl$TIOCGDEV", 16},
    {"ioctl$TIOCGETD", 16},
    {"ioctl$TIOCGICOUNT", 16},
    {"ioctl$TIOCGISO7816", 16},
    {"ioctl$TIOCGLCKTRMIOS", 16},
    {"ioctl$TIOCGPGRP", 16},
    {"ioctl$TIOCGPKT", 16},
    {"ioctl$TIOCGPTLCK", 16},
    {"ioctl$TIOCGPTPEER", 16},
    {"ioctl$TIOCGRS485", 16},
    {"ioctl$TIOCGSERIAL", 16},
    {"ioctl$TIOCGSID", 16},
    {"ioctl$TIOCGSOFTCAR", 16},
    {"ioctl$TIOCGWINSZ", 16},
    {"ioctl$TIOCL_BLANKSCREEN", 16},
    {"ioctl$TIOCL_GETKMSGREDIRECT", 16},
    {"ioctl$TIOCL_GETMOUSEREPORTING", 16},
    {"ioctl$TIOCL_GETSHIFTSTATE", 16},
    {"ioctl$TIOCL_PASTESEL", 16},
    {"ioctl$TIOCL_SCROLLCONSOLE", 16},
    {"ioctl$TIOCL_SELLOADLUT", 16},
    {"ioctl$TIOCL_SETSEL", 16},
    {"ioctl$TIOCL_SETVESABLANK", 16},
    {"ioctl$TIOCL_UNBLANKSCREEN", 16},
    {"ioctl$TIOCMBIC", 16},
    {"ioctl$TIOCMBIS", 16},
    {"ioctl$TIOCMGET", 16},
    {"ioctl$TIOCMIWAIT", 16},
    {"ioctl$TIOCMSET", 16},
    {"ioctl$TIOCNOTTY", 16},
    {"ioctl$TIOCNXCL", 16},
    {"ioctl$TIOCOUTQ", 16},
    {"ioctl$TIOCPKT", 16},
    {"ioctl$TIOCSBRK", 16},
    {"ioctl$TIOCSCTTY", 16},
    {"ioctl$TIOCSERGETLSR", 16},
    {"ioctl$TIOCSETD", 16},
    {"ioctl$TIOCSIG", 16},
    {"ioctl$TIOCSISO7816", 16},
    {"ioctl$TIOCSLCKTRMIOS", 16},
    {"ioctl$TIOCSPGRP", 16},
    {"ioctl$TIOCSPTLCK", 16},
    {"ioctl$TIOCSRS485", 16},
    {"ioctl$TIOCSSERIAL", 16, {1}},
    {"ioctl$TIOCSSOFTCAR", 16},
    {"ioctl$TIOCSTI", 16},
    {"ioctl$TIOCSWINSZ", 16},
    {"ioctl$TIOCVHANGUP", 16},
    {"ioctl$TIPC_IOC_CONNECT", 16},
    {"ioctl$TIPC_IOC_CONNECT_avb", 16},
    {"ioctl$TIPC_IOC_CONNECT_gatekeeper", 16},
    {"ioctl$TIPC_IOC_CONNECT_hwkey", 16},
    {"ioctl$TIPC_IOC_CONNECT_hwrng", 16},
    {"ioctl$TIPC_IOC_CONNECT_keymaster_secure", 16},
    {"ioctl$TIPC_IOC_CONNECT_km", 16},
    {"ioctl$TIPC_IOC_CONNECT_storage", 16},
    {"ioctl$TUNATTACHFILTER", 16},
    {"ioctl$TUNDETACHFILTER", 16},
    {"ioctl$TUNGETDEVNETNS", 16},
    {"ioctl$TUNGETFEATURES", 16},
    {"ioctl$TUNGETFILTER", 16},
    {"ioctl$TUNGETIFF", 16},
    {"ioctl$TUNGETSNDBUF", 16},
    {"ioctl$TUNGETVNETHDRSZ", 16},
    {"ioctl$TUNSETCARRIER", 16},
    {"ioctl$TUNSETFILTEREBPF", 16},
    {"ioctl$TUNSETGROUP", 16},
    {"ioctl$TUNSETIFF", 16},
    {"ioctl$TUNSETIFINDEX", 16},
    {"ioctl$TUNSETLINK", 16},
    {"ioctl$TUNSETNOCSUM", 16},
    {"ioctl$TUNSETOFFLOAD", 16},
    {"ioctl$TUNSETOWNER", 16},
    {"ioctl$TUNSETPERSIST", 16},
    {"ioctl$TUNSETQUEUE", 16},
    {"ioctl$TUNSETSNDBUF", 16},
    {"ioctl$TUNSETSTEERINGEBPF", 16},
    {"ioctl$TUNSETTXFILTER", 16},
    {"ioctl$TUNSETVNETBE", 16},
    {"ioctl$TUNSETVNETHDRSZ", 16},
    {"ioctl$TUNSETVNETLE", 16},
    {"ioctl$UDMABUF_CREATE", 16},
    {"ioctl$UDMABUF_CREATE_LIST", 16},
    {"ioctl$UFFDIO_API", 16},
    {"ioctl$UFFDIO_COPY", 16},
    {"ioctl$UFFDIO_REGISTER", 16},
    {"ioctl$UFFDIO_UNREGISTER", 16},
    {"ioctl$UFFDIO_WAKE", 16},
    {"ioctl$UFFDIO_ZEROPAGE", 16},
    {"ioctl$UI_ABS_SETUP", 16},
    {"ioctl$UI_BEGIN_FF_ERASE", 16},
    {"ioctl$UI_BEGIN_FF_UPLOAD", 16},
    {"ioctl$UI_DEV_CREATE", 16},
    {"ioctl$UI_DEV_DESTROY", 16},
    {"ioctl$UI_DEV_SETUP", 16},
    {"ioctl$UI_END_FF_ERASE", 16},
    {"ioctl$UI_END_FF_UPLOAD", 16},
    {"ioctl$UI_GET_SYSNAME", 16},
    {"ioctl$UI_GET_VERSION", 16},
    {"ioctl$UI_SET_ABSBIT", 16},
    {"ioctl$UI_SET_EVBIT", 16},
    {"ioctl$UI_SET_FFBIT", 16},
    {"ioctl$UI_SET_KEYBIT", 16},
    {"ioctl$UI_SET_LEDBIT", 16},
    {"ioctl$UI_SET_MSCBIT", 16},
    {"ioctl$UI_SET_PHYS", 16},
    {"ioctl$UI_SET_PROPBIT", 16},
    {"ioctl$UI_SET_RELBIT", 16},
    {"ioctl$UI_SET_SNDBIT", 16},
    {"ioctl$UI_SET_SWBIT", 16},
    {"ioctl$USBDEVFS_BULK", 16},
    {"ioctl$USBDEVFS_CLAIMINTERFACE", 16},
    {"ioctl$USBDEVFS_CLAIM_PORT", 16},
    {"ioctl$USBDEVFS_CLEAR_HALT", 16},
    {"ioctl$USBDEVFS_CONNECTINFO", 16},
    {"ioctl$USBDEVFS_CONTROL", 16},
    {"ioctl$USBDEVFS_DISCARDURB", 16},
    {"ioctl$USBDEVFS_DISCONNECT_CLAIM", 16},
    {"ioctl$USBDEVFS_DISCSIGNAL", 16},
    {"ioctl$USBDEVFS_DROP_PRIVILEGES", 16},
    {"ioctl$USBDEVFS_FREE_STREAMS", 16},
    {"ioctl$USBDEVFS_GETDRIVER", 16},
    {"ioctl$USBDEVFS_GET_CAPABILITIES", 16},
    {"ioctl$USBDEVFS_GET_SPEED", 16},
    {"ioctl$USBDEVFS_IOCTL", 16},
    {"ioctl$USBDEVFS_REAPURB", 16},
    {"ioctl$USBDEVFS_REAPURBNDELAY", 16},
    {"ioctl$USBDEVFS_RELEASEINTERFACE", 16},
    {"ioctl$USBDEVFS_RELEASE_PORT", 16},
    {"ioctl$USBDEVFS_RESET", 16},
    {"ioctl$USBDEVFS_RESETEP", 16},
    {"ioctl$USBDEVFS_SETCONFIGURATION", 16},
    {"ioctl$USBDEVFS_SETINTERFACE", 16},
    {"ioctl$USBDEVFS_SUBMITURB", 16},
    {"ioctl$VFIO_CHECK_EXTENSION", 16},
    {"ioctl$VFIO_GET_API_VERSION", 16},
    {"ioctl$VFIO_IOMMU_GET_INFO", 16},
    {"ioctl$VFIO_IOMMU_MAP_DMA", 16},
    {"ioctl$VFIO_IOMMU_UNMAP_DMA", 16},
    {"ioctl$VFIO_SET_IOMMU", 16},
    {"ioctl$VHOST_GET_FEATURES", 16},
    {"ioctl$VHOST_GET_VRING_BASE", 16},
    {"ioctl$VHOST_GET_VRING_ENDIAN", 16},
    {"ioctl$VHOST_NET_SET_BACKEND", 16},
    {"ioctl$VHOST_RESET_OWNER", 16},
    {"ioctl$VHOST_SET_FEATURES", 16},
    {"ioctl$VHOST_SET_LOG_BASE", 16},
    {"ioctl$VHOST_SET_LOG_FD", 16},
    {"ioctl$VHOST_SET_MEM_TABLE", 16},
    {"ioctl$VHOST_SET_OWNER", 16},
    {"ioctl$VHOST_SET_VRING_ADDR", 16},
    {"ioctl$VHOST_SET_VRING_BASE", 16},
    {"ioctl$VHOST_SET_VRING_BUSYLOOP_TIMEOUT", 16},
    {"ioctl$VHOST_SET_VRING_CALL", 16},
    {"ioctl$VHOST_SET_VRING_ENDIAN", 16},
    {"ioctl$VHOST_SET_VRING_ERR", 16},
    {"ioctl$VHOST_SET_VRING_KICK", 16},
    {"ioctl$VHOST_SET_VRING_NUM", 16},
    {"ioctl$VHOST_VSOCK_SET_GUEST_CID", 16},
    {"ioctl$VHOST_VSOCK_SET_RUNNING", 16},
    {"ioctl$VIDIOC_CREATE_BUFS", 16},
    {"ioctl$VIDIOC_CROPCAP", 16},
    {"ioctl$VIDIOC_DBG_G_CHIP_INFO", 16},
    {"ioctl$VIDIOC_DBG_G_REGISTER", 16},
    {"ioctl$VIDIOC_DBG_S_REGISTER", 16},
    {"ioctl$VIDIOC_DECODER_CMD", 16},
    {"ioctl$VIDIOC_DQBUF", 16},
    {"ioctl$VIDIOC_DQEVENT", 16},
    {"ioctl$VIDIOC_DV_TIMINGS_CAP", 16},
    {"ioctl$VIDIOC_ENCODER_CMD", 16},
    {"ioctl$VIDIOC_ENUMAUDIO", 16},
    {"ioctl$VIDIOC_ENUMAUDOUT", 16},
    {"ioctl$VIDIOC_ENUMINPUT", 16},
    {"ioctl$VIDIOC_ENUMOUTPUT", 16},
    {"ioctl$VIDIOC_ENUMSTD", 16},
    {"ioctl$VIDIOC_ENUM_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_ENUM_FMT", 16},
    {"ioctl$VIDIOC_ENUM_FRAMEINTERVALS", 16},
    {"ioctl$VIDIOC_ENUM_FRAMESIZES", 16},
    {"ioctl$VIDIOC_ENUM_FREQ_BANDS", 16},
    {"ioctl$VIDIOC_EXPBUF", 16},
    {"ioctl$VIDIOC_G_AUDIO", 16},
    {"ioctl$VIDIOC_G_AUDOUT", 16},
    {"ioctl$VIDIOC_G_CROP", 16},
    {"ioctl$VIDIOC_G_CTRL", 16},
    {"ioctl$VIDIOC_G_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_G_EDID", 16},
    {"ioctl$VIDIOC_G_ENC_INDEX", 16},
    {"ioctl$VIDIOC_G_EXT_CTRLS", 16},
    {"ioctl$VIDIOC_G_FBUF", 16},
    {"ioctl$VIDIOC_G_FMT", 16},
    {"ioctl$VIDIOC_G_FREQUENCY", 16},
    {"ioctl$VIDIOC_G_INPUT", 16},
    {"ioctl$VIDIOC_G_JPEGCOMP", 16},
    {"ioctl$VIDIOC_G_MODULATOR", 16},
    {"ioctl$VIDIOC_G_OUTPUT", 16},
    {"ioctl$VIDIOC_G_PARM", 16},
    {"ioctl$VIDIOC_G_PRIORITY", 16},
    {"ioctl$VIDIOC_G_SELECTION", 16},
    {"ioctl$VIDIOC_G_SLICED_VBI_CAP", 16},
    {"ioctl$VIDIOC_G_STD", 16},
    {"ioctl$VIDIOC_G_TUNER", 16},
    {"ioctl$VIDIOC_LOG_STATUS", 16},
    {"ioctl$VIDIOC_OVERLAY", 16},
    {"ioctl$VIDIOC_PREPARE_BUF", 16},
    {"ioctl$VIDIOC_QBUF", 16},
    {"ioctl$VIDIOC_QUERYBUF", 16},
    {"ioctl$VIDIOC_QUERYCAP", 16},
    {"ioctl$VIDIOC_QUERYCTRL", 16},
    {"ioctl$VIDIOC_QUERYMENU", 16},
    {"ioctl$VIDIOC_QUERYSTD", 16},
    {"ioctl$VIDIOC_QUERY_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_QUERY_EXT_CTRL", 16},
    {"ioctl$VIDIOC_REQBUFS", 16},
    {"ioctl$VIDIOC_STREAMOFF", 16},
    {"ioctl$VIDIOC_STREAMON", 16},
    {"ioctl$VIDIOC_SUBDEV_DV_TIMINGS_CAP", 16},
    {"ioctl$VIDIOC_SUBDEV_ENUM_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_SUBDEV_ENUM_FRAME_INTERVAL", 16},
    {"ioctl$VIDIOC_SUBDEV_ENUM_FRAME_SIZE", 16},
    {"ioctl$VIDIOC_SUBDEV_ENUM_MBUS_CODE", 16},
    {"ioctl$VIDIOC_SUBDEV_G_CROP", 16},
    {"ioctl$VIDIOC_SUBDEV_G_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_SUBDEV_G_EDID", 16},
    {"ioctl$VIDIOC_SUBDEV_G_FMT", 16},
    {"ioctl$VIDIOC_SUBDEV_G_FRAME_INTERVAL", 16},
    {"ioctl$VIDIOC_SUBDEV_G_SELECTION", 16},
    {"ioctl$VIDIOC_SUBDEV_QUERY_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_SUBDEV_S_CROP", 16},
    {"ioctl$VIDIOC_SUBDEV_S_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_SUBDEV_S_EDID", 16},
    {"ioctl$VIDIOC_SUBDEV_S_FMT", 16},
    {"ioctl$VIDIOC_SUBDEV_S_FRAME_INTERVAL", 16},
    {"ioctl$VIDIOC_SUBDEV_S_SELECTION", 16},
    {"ioctl$VIDIOC_SUBSCRIBE_EVENT", 16},
    {"ioctl$VIDIOC_S_AUDIO", 16},
    {"ioctl$VIDIOC_S_AUDOUT", 16},
    {"ioctl$VIDIOC_S_CROP", 16},
    {"ioctl$VIDIOC_S_CTRL", 16},
    {"ioctl$VIDIOC_S_DV_TIMINGS", 16},
    {"ioctl$VIDIOC_S_EDID", 16},
    {"ioctl$VIDIOC_S_EXT_CTRLS", 16},
    {"ioctl$VIDIOC_S_FBUF", 16},
    {"ioctl$VIDIOC_S_FMT", 16},
    {"ioctl$VIDIOC_S_FREQUENCY", 16},
    {"ioctl$VIDIOC_S_HW_FREQ_SEEK", 16},
    {"ioctl$VIDIOC_S_INPUT", 16},
    {"ioctl$VIDIOC_S_JPEGCOMP", 16},
    {"ioctl$VIDIOC_S_MODULATOR", 16},
    {"ioctl$VIDIOC_S_OUTPUT", 16},
    {"ioctl$VIDIOC_S_PARM", 16},
    {"ioctl$VIDIOC_S_PRIORITY", 16},
    {"ioctl$VIDIOC_S_SELECTION", 16},
    {"ioctl$VIDIOC_S_STD", 16},
    {"ioctl$VIDIOC_S_TUNER", 16},
    {"ioctl$VIDIOC_TRY_DECODER_CMD", 16},
    {"ioctl$VIDIOC_TRY_ENCODER_CMD", 16},
    {"ioctl$VIDIOC_TRY_EXT_CTRLS", 16},
    {"ioctl$VIDIOC_TRY_FMT", 16},
    {"ioctl$VIDIOC_UNSUBSCRIBE_EVENT", 16},
    {"ioctl$VT_ACTIVATE", 16},
    {"ioctl$VT_DISALLOCATE", 16},
    {"ioctl$VT_GETMODE", 16},
    {"ioctl$VT_GETSTATE", 16},
    {"ioctl$VT_OPENQRY", 16},
    {"ioctl$VT_RELDISP", 16},
    {"ioctl$VT_RESIZE", 16},
    {"ioctl$VT_RESIZEX", 16},
    {"ioctl$VT_SETMODE", 16},
    {"ioctl$VT_WAITACTIVE", 16},
    {"ioctl$ifreq_SIOCGIFINDEX_batadv_hard", 16},
    {"ioctl$ifreq_SIOCGIFINDEX_batadv_mesh", 16},
    {"ioctl$ifreq_SIOCGIFINDEX_team", 16},
    {"ioctl$ifreq_SIOCGIFINDEX_vcan", 16},
    {"ioctl$ifreq_SIOCGIFINDEX_wireguard", 16},
    {"ioctl$int_in", 16},
    {"ioctl$int_out", 16},
    {"ioctl$mixer_OSS_ALSAEMULVER", 16},
    {"ioctl$mixer_OSS_GETVERSION", 16},
    {"ioctl$sock_FIOGETOWN", 16},
    {"ioctl$sock_FIOSETOWN", 16},
    {"ioctl$sock_SIOCADDDLCI", 16},
    {"ioctl$sock_SIOCADDRT", 16},
    {"ioctl$sock_SIOCBRADDBR", 16},
    {"ioctl$sock_SIOCBRDELBR", 16},
    {"ioctl$sock_SIOCDELDLCI", 16},
    {"ioctl$sock_SIOCDELRT", 16},
    {"ioctl$sock_SIOCETHTOOL", 16},
    {"ioctl$sock_SIOCGIFBR", 16},
    {"ioctl$sock_SIOCGIFCONF", 16},
    {"ioctl$sock_SIOCGIFINDEX", 16},
    {"ioctl$sock_SIOCGIFINDEX_80211", 16},
    {"ioctl$sock_SIOCGIFINDEX_802154", 16},
    {"ioctl$sock_SIOCGIFVLAN_ADD_VLAN_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_DEL_VLAN_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_GET_VLAN_EGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_GET_VLAN_INGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_GET_VLAN_REALDEV_NAME_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_GET_VLAN_VID_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_SET_VLAN_EGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_SET_VLAN_FLAG_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_SET_VLAN_INGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCGIFVLAN_SET_VLAN_NAME_TYPE_CMD", 16},
    {"ioctl$sock_SIOCGPGRP", 16},
    {"ioctl$sock_SIOCGSKNS", 16},
    {"ioctl$sock_SIOCINQ", 16},
    {"ioctl$sock_SIOCOUTQ", 16},
    {"ioctl$sock_SIOCOUTQNSD", 16},
    {"ioctl$sock_SIOCSIFBR", 16},
    {"ioctl$sock_SIOCSIFVLAN_ADD_VLAN_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_DEL_VLAN_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_GET_VLAN_EGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_GET_VLAN_INGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_GET_VLAN_REALDEV_NAME_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_GET_VLAN_VID_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_SET_VLAN_EGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_SET_VLAN_FLAG_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_SET_VLAN_INGRESS_PRIORITY_CMD", 16},
    {"ioctl$sock_SIOCSIFVLAN_SET_VLAN_NAME_TYPE_CMD", 16},
    {"ioctl$sock_SIOCSPGRP", 16},
    {"ioctl$sock_TIOCINQ", 16},
    {"ioctl$sock_TIOCOUTQ", 16},
    {"ioctl$sock_ax25_SIOCADDRT", 16},
    {"ioctl$sock_ax25_SIOCDELRT", 16},
    {"ioctl$sock_bt_bnep_BNEPCONNADD", 16},
    {"ioctl$sock_bt_bnep_BNEPCONNDEL", 16},
    {"ioctl$sock_bt_bnep_BNEPGETCONNINFO", 16},
    {"ioctl$sock_bt_bnep_BNEPGETCONNLIST", 16},
    {"ioctl$sock_bt_bnep_BNEPGETSUPPFEAT", 16},
    {"ioctl$sock_bt_cmtp_CMTPCONNADD", 16},
    {"ioctl$sock_bt_cmtp_CMTPCONNDEL", 16},
    {"ioctl$sock_bt_cmtp_CMTPGETCONNINFO", 16},
    {"ioctl$sock_bt_cmtp_CMTPGETCONNLIST", 16},
    {"ioctl$sock_bt_hci", 16},
    {"ioctl$sock_bt_hidp_HIDPCONNADD", 16},
    {"ioctl$sock_bt_hidp_HIDPCONNDEL", 16},
    {"ioctl$sock_bt_hidp_HIDPGETCONNINFO", 16},
    {"ioctl$sock_bt_hidp_HIDPGETCONNLIST", 16},
    {"ioctl$sock_ifreq", 16},
    {"ioctl$sock_inet6_SIOCADDRT", 16},
    {"ioctl$sock_inet6_SIOCDELRT", 16},
    {"ioctl$sock_inet6_SIOCDIFADDR", 16},
    {"ioctl$sock_inet6_SIOCSIFADDR", 16},
    {"ioctl$sock_inet6_SIOCSIFDSTADDR", 16},
    {"ioctl$sock_inet6_tcp_SIOCATMARK", 16},
    {"ioctl$sock_inet6_tcp_SIOCINQ", 16},
    {"ioctl$sock_inet6_tcp_SIOCOUTQ", 16},
    {"ioctl$sock_inet6_tcp_SIOCOUTQNSD", 16},
    {"ioctl$sock_inet6_udp_SIOCINQ", 16},
    {"ioctl$sock_inet6_udp_SIOCOUTQ", 16},
    {"ioctl$sock_inet_SIOCADDRT", 16},
    {"ioctl$sock_inet_SIOCDARP", 16},
    {"ioctl$sock_inet_SIOCDELRT", 16},
    {"ioctl$sock_inet_SIOCGARP", 16},
    {"ioctl$sock_inet_SIOCGIFADDR", 16},
    {"ioctl$sock_inet_SIOCGIFBRDADDR", 16},
    {"ioctl$sock_inet_SIOCGIFDSTADDR", 16},
    {"ioctl$sock_inet_SIOCGIFNETMASK", 16},
    {"ioctl$sock_inet_SIOCGIFPFLAGS", 16},
    {"ioctl$sock_inet_SIOCRTMSG", 16},
    {"ioctl$sock_inet_SIOCSARP", 16},
    {"ioctl$sock_inet_SIOCSIFADDR", 16},
    {"ioctl$sock_inet_SIOCSIFBRDADDR", 16},
    {"ioctl$sock_inet_SIOCSIFDSTADDR", 16},
    {"ioctl$sock_inet_SIOCSIFFLAGS", 16},
    {"ioctl$sock_inet_SIOCSIFNETMASK", 16},
    {"ioctl$sock_inet_SIOCSIFPFLAGS", 16},
    {"ioctl$sock_inet_sctp_SIOCINQ", 16},
    {"ioctl$sock_inet_tcp_SIOCATMARK", 16},
    {"ioctl$sock_inet_tcp_SIOCINQ", 16},
    {"ioctl$sock_inet_tcp_SIOCOUTQ", 16},
    {"ioctl$sock_inet_tcp_SIOCOUTQNSD", 16},
    {"ioctl$sock_inet_udp_SIOCINQ", 16},
    {"ioctl$sock_inet_udp_SIOCOUTQ", 16},
    {"ioctl$sock_ipv4_tunnel_SIOCADDTUNNEL", 16},
    {"ioctl$sock_ipv4_tunnel_SIOCCHGTUNNEL", 16},
    {"ioctl$sock_ipv4_tunnel_SIOCDELTUNNEL", 16},
    {"ioctl$sock_ipv4_tunnel_SIOCGETTUNNEL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCADD6RD", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCADDPRL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCADDTUNNEL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCCHG6RD", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCCHGPRL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCCHGTUNNEL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCDEL6RD", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCDELPRL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCDELTUNNEL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCGET6RD", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCGETPRL", 16},
    {"ioctl$sock_ipv6_tunnel_SIOCGETTUNNEL", 16},
    {"ioctl$sock_ipx_SIOCAIPXITFCRT", 16},
    {"ioctl$sock_ipx_SIOCAIPXPRISLT", 16},
    {"ioctl$sock_ipx_SIOCGIFADDR", 16},
    {"ioctl$sock_ipx_SIOCIPXCFGDATA", 16},
    {"ioctl$sock_ipx_SIOCIPXNCPCONN", 16},
    {"ioctl$sock_ipx_SIOCSIFADDR", 16},
    {"ioctl$sock_kcm_SIOCKCMATTACH", 16},
    {"ioctl$sock_kcm_SIOCKCMCLONE", 16},
    {"ioctl$sock_kcm_SIOCKCMUNATTACH", 16},
    {"ioctl$sock_netdev_private", 16},
    {"ioctl$sock_netrom_SIOCADDRT", 16},
    {"ioctl$sock_netrom_SIOCDELRT", 16},
    {"ioctl$sock_proto_private", 16},
    {"ioctl$sock_qrtr_SIOCGIFADDR", 16},
    {"ioctl$sock_qrtr_TIOCINQ", 16},
    {"ioctl$sock_qrtr_TIOCOUTQ", 16},
    {"ioctl$sock_rose_SIOCADDRT", 16},
    {"ioctl$sock_rose_SIOCDELRT", 16},
    {"ioctl$sock_rose_SIOCRSCLRRT", 16},
    {"ioctl$sock_x25_SIOCADDRT", 16},
    {"ioctl$sock_x25_SIOCDELRT", 16},
    {"ioctl$vim2m_VIDIOC_CREATE_BUFS", 16},
    {"ioctl$vim2m_VIDIOC_DQBUF", 16},
    {"ioctl$vim2m_VIDIOC_ENUM_FMT", 16},
    {"ioctl$vim2m_VIDIOC_ENUM_FRAMESIZES", 16},
    {"ioctl$vim2m_VIDIOC_EXPBUF", 16},
    {"ioctl$vim2m_VIDIOC_G_FMT", 16},
    {"ioctl$vim2m_VIDIOC_PREPARE_BUF", 16},
    {"ioctl$vim2m_VIDIOC_QBUF", 16},
    {"ioctl$vim2m_VIDIOC_QUERYBUF", 16},
    {"ioctl$vim2m_VIDIOC_QUERYCAP", 16},
    {"ioctl$vim2m_VIDIOC_REQBUFS", 16},
    {"ioctl$vim2m_VIDIOC_STREAMOFF", 16},
    {"ioctl$vim2m_VIDIOC_STREAMON", 16},
    {"ioctl$vim2m_VIDIOC_S_CTRL", 16},
    {"ioctl$vim2m_VIDIOC_S_FMT", 16},
    {"ioctl$vim2m_VIDIOC_TRY_FMT", 16},
    {"ioperm", 173},
    {"iopl", 172},
    {"ioprio_get$pid", 252},
    {"ioprio_get$uid", 252},
    {"ioprio_set$pid", 251},
    {"ioprio_set$uid", 251},
    {"kcmp", 312},
    {"kcmp$KCMP_EPOLL_TFD", 312},
    {"kexec_load", 246},
    {"keyctl$KEYCTL_CAPABILITIES", 250},
    {"keyctl$KEYCTL_MOVE", 250},
    {"keyctl$KEYCTL_PKEY_DECRYPT", 250},
    {"keyctl$KEYCTL_PKEY_ENCRYPT", 250},
    {"keyctl$KEYCTL_PKEY_QUERY", 250},
    {"keyctl$KEYCTL_PKEY_SIGN", 250},
    {"keyctl$KEYCTL_PKEY_VERIFY", 250},
    {"keyctl$KEYCTL_RESTRICT_KEYRING", 250},
    {"keyctl$assume_authority", 250},
    {"keyctl$chown", 250},
    {"keyctl$clear", 250},
    {"keyctl$describe", 250},
    {"keyctl$dh_compute", 250},
    {"keyctl$get_keyring_id", 250},
    {"keyctl$get_persistent", 250},
    {"keyctl$get_security", 250},
    {"keyctl$instantiate", 250},
    {"keyctl$instantiate_iov", 250},
    {"keyctl$invalidate", 250},
    {"keyctl$join", 250},
    {"keyctl$link", 250},
    {"keyctl$negate", 250},
    {"keyctl$read", 250},
    {"keyctl$reject", 250},
    {"keyctl$restrict_keyring", 250},
    {"keyctl$revoke", 250},
    {"keyctl$search", 250},
    {"keyctl$session_to_parent", 250},
    {"keyctl$set_reqkey_keyring", 250},
    {"keyctl$set_timeout", 250},
    {"keyctl$setperm", 250},
    {"keyctl$unlink", 250},
    {"keyctl$update", 250},
    {"lchown", 94},
    {"lgetxattr", 192},
    {"link", 86},
    {"linkat", 265},
    {"listen", 50},
    {"listxattr", 194},
    {"llistxattr", 195},
    {"lookup_dcookie", 212},
    {"lremovexattr", 198},
    {"lseek", 8},
    {"lsetxattr", 189},
    {"lsetxattr$security_capability", 189},
    {"lsetxattr$security_evm", 189},
    {"lsetxattr$security_ima", 189},
    {"lsetxattr$security_selinux", 189},
    {"lsetxattr$security_smack_transmute", 189},
    {"lsetxattr$smack_xattr_label", 189},
    {"lsetxattr$system_posix_acl", 189},
    {"lsetxattr$trusted_overlay_nlink", 189},
    {"lsetxattr$trusted_overlay_opaque", 189},
    {"lsetxattr$trusted_overlay_origin", 189},
    {"lsetxattr$trusted_overlay_redirect", 189},
    {"lsetxattr$trusted_overlay_upper", 189},
    {"lstat", 6},
    {"madvise", 28},
    {"mbind", 237},
    {"membarrier", 324},
    {"memfd_create", 319},
    {"migrate_pages", 256},
    {"mincore", 27},
    {"mkdir", 83},
    {"mkdirat", 258},
    {"mkdirat$cgroup", 258},
    {"mkdirat$cgroup_root", 258},
    {"mknod", 133},
    {"mknod$loop", 133},
    {"mknodat", 259},
    {"mknodat$loop", 259},
    {"mknodat$null", 259},
    {"mlock", 149},
    {"mlock2", 325},
    {"mlockall", 151},
    {"mmap", 9},
    {"mmap$DRM_I915", 9},
    {"mmap$IORING_OFF_CQ_RING", 9},
    {"mmap$IORING_OFF_SQES", 9},
    {"mmap$IORING_OFF_SQ_RING", 9},
    {"mmap$bifrost", 9},
    {"mmap$binder", 9},
    {"mmap$dsp", 9},
    {"mmap$fb", 9},
    {"mmap$perf", 9},
    {"mmap$qrtrtun", 9},
    {"mmap$snddsp", 9},
    {"mmap$snddsp_control", 9},
    {"mmap$snddsp_status", 9},
    {"mmap$usbfs", 9},
    {"mmap$usbmon", 9},
    {"mmap$watch_queue", 9},
    {"mmap$xdp", 9},
    {"modify_ldt$read", 154},
    {"modify_ldt$read_default", 154},
    {"modify_ldt$write", 154},
    {"modify_ldt$write2", 154},
    {"mount", 165},
    {"mount$9p_fd", 165},
    {"mount$9p_rdma", 165},
    {"mount$9p_tcp", 165},
    {"mount$9p_unix", 165},
    {"mount$9p_virtio", 165},
    {"mount$9p_xen", 165},
    {"mount$bind", 165},
    {"mount$binder", 165},
    {"mount$bpf", 165},
    {"mount$esdfs", 165},
    {"mount$fuse", 165},
    {"mount$fuseblk", 165},
    {"mount$incfs", 165},
    {"mount$overlay", 165},
    {"mount$tmpfs", 165},
    {"mount_setattr", 442},
    {"move_mount", 429},
    {"move_pages", 279},
    {"mprotect", 10},
    {"mq_getsetattr", 245},
    {"mq_notify", 244},
    {"mq_open", 240},
    {"mq_timedreceive", 243},
    {"mq_timedsend", 242},
    {"mq_unlink", 241},
    {"mremap", 25},
    {"msgctl$IPC_INFO", 71},
    {"msgctl$IPC_RMID", 71},
    {"msgctl$IPC_SET", 71},
    {"msgctl$IPC_STAT", 71},
    {"msgctl$MSG_INFO", 71},
    {"msgctl$MSG_STAT", 71},
    {"msgctl$MSG_STAT_ANY", 71},
    {"msgget", 68},
    {"msgget$private", 68},
    {"msgrcv", 70},
    {"msgsnd", 69},
    {"msync", 26},
    {"munlock", 150},
    {"munlockall", 152},
    {"munmap", 11},
    {"name_to_handle_at", 303},
    {"nanosleep", 35},
    {"newfstatat", 262},
    {"open", 2},
    {"open$dir", 2},
    {"open_by_handle_at", 304},
    {"open_tree", 428},
    {"openat", 257},
    {"openat$6lowpan_control", 257},
    {"openat$6lowpan_enable", 257},
    {"openat$adsp1", 257},
    {"openat$apparmor_task_current", 257},
    {"openat$apparmor_task_exec", 257},
    {"openat$apparmor_thread_current", 257},
    {"openat$apparmor_thread_exec", 257},
    {"openat$ashmem", 257},
    {"openat$audio", 257},
    {"openat$audio1", 257},
    {"openat$autofs", 257},
    {"openat$bifrost", 257},
    {"openat$binder", 257},
    {"openat$binder_debug", 257},
    {"openat$bsg", 257},
    {"openat$btrfs_control", 257},
    {"openat$cachefiles", 257},
    {"openat$capi20", 257},
    {"openat$cdrom", 257},
    {"openat$cdrom1", 257},
    {"openat$cgroup", 257},
    {"openat$cgroup_devices", 257},
    {"openat$cgroup_freezer_state", 257},
    {"openat$cgroup_int", 257},
    {"openat$cgroup_netprio_ifpriomap", 257},
    {"openat$cgroup_procs", 257},
    {"openat$cgroup_ro", 257},
    {"openat$cgroup_root", 257},
    {"openat$cgroup_subtree", 257},
    {"openat$cgroup_type", 257},
    {"openat$char_raw_ctl", 257},
    {"openat$cuse", 257},
    {"openat$dir", 257},
    {"openat$dlm_control", 257},
    {"openat$dlm_monitor", 257},
    {"openat$dlm_plock", 257},
    {"openat$drirender128", 257},
    {"openat$dsp", 257},
    {"openat$dsp1", 257},
    {"openat$fb0", 257},
    {"openat$fb1", 257},
    {"openat$full", 257},
    {"openat$fuse", 257},
    {"openat$hpet", 257},
    {"openat$hwbinder", 257},
    {"openat$hwrng", 257},
    {"openat$i915", 257},
    {"openat$img_rogue", 257},
    {"openat$incfs", 257},
    {"openat$ion", 257},
    {"openat$ipvs", 257},
    {"openat$irnet", 257},
    {"openat$keychord", 257},
    {"openat$khugepaged_scan", 257},
    {"openat$kvm", 257},
    {"openat$lightnvm", 257},
    {"openat$loop_ctrl", 257},
    {"openat$md", 257},
    {"openat$mice", 257},
    {"openat$misdntimer", 257},
    {"openat$mixer", 257},
    {"openat$ndctl0", 257},
    {"openat$nmem0", 257},
    {"openat$null", 257},
    {"openat$nullb", 257},
    {"openat$nvme_fabrics", 257},
    {"openat$nvram", 257},
    {"openat$ocfs2_control", 257},
    {"openat$pfkey", 257},
    {"openat$pidfd", 257},
    {"openat$pktcdvd", 257},
    {"openat$pmem0", 257},
    {"openat$ppp", 257},
    {"openat$proc_capi20", 257},
    {"openat$proc_capi20ncci", 257},
    {"openat$proc_mixer", 257},
    {"openat$proc_reclaim", 257},
    {"openat$procfs", 257},
    {"openat$ptmx", 257},
    {"openat$ptp0", 257},
    {"openat$ptp1", 257},
    {"openat$qat_adf_ctl", 257},
    {"openat$qrtrtun", 257},
    {"openat$random", 257},
    {"openat$rdma_cm", 257},
    {"openat$rfkill", 257},
    {"openat$rtc", 257},
    {"openat$selinux_access", 257},
    {"openat$selinux_attr", 257},
    {"openat$selinux_avc_cache_stats", 257},
    {"openat$selinux_avc_cache_threshold", 257},
    {"openat$selinux_avc_hash_stats", 257},
    {"openat$selinux_checkreqprot", 257},
    {"openat$selinux_commit_pending_bools", 257},
    {"openat$selinux_context", 257},
    {"openat$selinux_create", 257},
    {"openat$selinux_enforce", 257},
    {"openat$selinux_load", 257},
    {"openat$selinux_member", 257},
    {"openat$selinux_mls", 257},
    {"openat$selinux_policy", 257},
    {"openat$selinux_relabel", 257},
    {"openat$selinux_status", 257},
    {"openat$selinux_user", 257},
    {"openat$selinux_validatetrans", 257},
    {"openat$sequencer", 257},
    {"openat$sequencer2", 257},
    {"openat$smack_task_current", 257},
    {"openat$smack_thread_current", 257},
    {"openat$smackfs_access", 257},
    {"openat$smackfs_ambient", 257},
    {"openat$smackfs_change_rule", 257},
    {"openat$smackfs_cipso", 257},
    {"openat$smackfs_cipsonum", 257},
    {"openat$smackfs_ipv6host", 257},
    {"openat$smackfs_load", 257},
    {"openat$smackfs_logging", 257},
    {"openat$smackfs_netlabel", 257},
    {"openat$smackfs_onlycap", 257},
    {"openat$smackfs_ptrace", 257},
    {"openat$smackfs_relabel_self", 257},
    {"openat$smackfs_revoke_subject", 257},
    {"openat$smackfs_syslog", 257},
    {"openat$smackfs_unconfined", 257},
    {"openat$snapshot", 257},
    {"openat$sndseq", 257},
    {"openat$sndtimer", 257},
    {"openat$sr", 257},
    {"openat$sw_sync", 257},
    {"openat$sysctl", 257},
    {"openat$tcp_congestion", 257},
    {"openat$tcp_mem", 257},
    {"openat$thread_pidfd", 257},
    {"openat$tlk_device", 257},
    {"openat$trusty", 257},
    {"openat$trusty_avb", 257},
    {"openat$trusty_gatekeeper", 257},
    {"openat$trusty_hwkey", 257},
    {"openat$trusty_hwrng", 257},
    {"openat$trusty_km", 257},
    {"openat$trusty_km_secure", 257},
    {"openat$trusty_storage", 257},
    {"openat$tty", 257},
    {"openat$ttyS3", 257},
    {"openat$ttynull", 257},
    {"openat$ttyprintk", 257},
    {"openat$tun", 257},
    {"openat$ubi_ctrl", 257},
    {"openat$udambuf", 257},
    {"openat$uhid", 257},
    {"openat$uinput", 257},
    {"openat$urandom", 257},
    {"openat$userio", 257},
    {"openat$uverbs0", 257},
    {"openat$vcs", 257},
    {"openat$vcsa", 257},
    {"openat$vcsu", 257},
    {"openat$vfio", 257},
    {"openat$vga_arbiter", 257},
    {"openat$vhost_vsock", 257},
    {"openat$vicodec0", 257},
    {"openat$vicodec1", 257},
    {"openat$vim2m", 257},
    {"openat$vimc0", 257},
    {"openat$vimc1", 257},
    {"openat$vimc2", 257},
    {"openat$vmci", 257},
    {"openat$vndbinder", 257},
    {"openat$vnet", 257},
    {"openat$vsock", 257},
    {"openat$watch_queue", 257},
    {"openat$xenevtchn", 257},
    {"openat$zero", 257},
    {"openat$zygote", 257},
    {"openat2", 437},
    {"openat2$dir", 437},
    {"pause", 34},
    {"perf_event_open", 298},
    {"perf_event_open$cgroup", 298},
    {"personality", 135},
    {"pidfd_getfd", 438},
    {"pidfd_open", 434},
    {"pidfd_send_signal", 424},
    {"pipe", 22},
    {"pipe2", 293},
    {"pipe2$9p", 293},
    {"pivot_root", 155},
    {"pkey_alloc", 330},
    {"pkey_free", 331},
    {"pkey_mprotect", 329},
    {"poll", 7},
    {"ppoll", 271},
    {"prctl$0", 157, {1}},
    {"prctl$PR_CAPBSET_DROP", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_CAPBSET_READ", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_CAP_AMBIENT", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_CHILD_SUBREAPER", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_DUMPABLE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_ENDIAN", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_FPEMU", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_FPEXC", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_FP_MODE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_KEEPCAPS", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_NAME", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_NO_NEW_PRIVS", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_PDEATHSIG", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_SECCOMP", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_SECUREBITS", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_SPECULATION_CTRL", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_THP_DISABLE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_TID_ADDRESS", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_TIMERSLACK", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_TSC", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_GET_UNALIGN", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_MCE_KILL", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_MCE_KILL_GET", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_MPX_DISABLE_MANAGEMENT", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_MPX_ENABLE_MANAGEMENT", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_CHILD_SUBREAPER", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_DUMPABLE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_ENDIAN", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_FPEMU", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_FPEXC", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_FP_MODE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_KEEPCAPS", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_MM", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_MM_AUXV", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_MM_EXE_FILE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_MM_MAP", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_MM_MAP_SIZE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_NAME", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_NO_NEW_PRIVS", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_PDEATHSIG", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_PTRACER", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_SECCOMP", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_SECUREBITS", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_SPECULATION_CTRL", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_THP_DISABLE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_TIMERSLACK", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_TSC", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SET_UNALIGN", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SVE_GET_VL", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_SVE_SET_VL", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_TASK_PERF_EVENTS_DISABLE", 157, {0, 0, 0, 1, 1}},
    {"prctl$PR_TASK_PERF_EVENTS_ENABLE", 157, {0, 0, 0, 1, 1}},
    {"pread64", 17},
    {"preadv", 295},
    {"preadv2", 327},
    {"prlimit64", 302},
    {"process_madvise", 440},
    {"process_vm_readv", 310},
    {"process_vm_writev", 311},
    {"pselect6", 270},
    {"ptrace", 101, {0, 0, 0, 0, 1}},
    {"ptrace$PTRACE_SECCOMP_GET_FILTER", 101, {0, 0, 0, 0, 1}},
    {"ptrace$PTRACE_SECCOMP_GET_METADATA", 101, {0, 0, 0, 0, 1}},
    {"ptrace$cont", 101, {0, 0, 0, 0, 1}},
    {"ptrace$getenv", 101, {0, 0, 0, 0, 1}},
    {"ptrace$getregs", 101, {0, 0, 0, 0, 1}},
    {"ptrace$getregset", 101, {0, 0, 0, 0, 1}},
    {"ptrace$getsig", 101, {0, 0, 0, 0, 1}},
    {"ptrace$peek", 101, {0, 0, 0, 0, 1}},
    {"ptrace$peeksig", 101},
    {"ptrace$peekuser", 101, {0, 0, 0, 0, 1}},
    {"ptrace$poke", 101, {0, 0, 0, 0, 1}},
    {"ptrace$pokeuser", 101, {0, 0, 0, 0, 1}},
    {"ptrace$setopts", 101, {0, 0, 0, 0, 1}},
    {"ptrace$setregs", 101, {0, 0, 0, 0, 1}},
    {"ptrace$setregset", 101, {0, 0, 0, 0, 1}},
    {"ptrace$setsig", 101, {0, 0, 0, 0, 1}},
    {"pwrite64", 18},
    {"pwritev", 296},
    {"pwritev2", 328},
    {"quotactl", 179},
    {"read", 0},
    {"read$FUSE", 0},
    {"read$alg", 0},
    {"read$char_raw", 0},
    {"read$char_usb", 0},
    {"read$dsp", 0},
    {"read$eventfd", 0},
    {"read$fb", 0},
    {"read$hiddev", 0},
    {"read$hidraw", 0},
    {"read$midi", 0},
    {"read$proc_mixer", 0},
    {"read$ptp", 0},
    {"read$qrtrtun", 0},
    {"read$rfkill", 0},
    {"read$sequencer", 0},
    {"read$smackfs_access", 0},
    {"read$smackfs_cipsonum", 0},
    {"read$smackfs_logging", 0},
    {"read$smackfs_ptrace", 0},
    {"read$snapshot", 0},
    {"read$snddsp", 0},
    {"read$sndhw", 0},
    {"read$trusty", 0},
    {"read$usbfs", 0},
    {"read$usbmon", 0},
    {"readahead", 187},
    {"readlink", 89},
    {"readlinkat", 267},
    {"readv", 19},
    {"recvfrom", 45},
    {"recvfrom$ax25", 45},
    {"recvfrom$inet", 45},
    {"recvfrom$inet6", 45},
    {"recvfrom$ipx", 45},
    {"recvfrom$l2tp", 45},
    {"recvfrom$l2tp6", 45},
    {"recvfrom$llc", 45},
    {"recvfrom$netrom", 45},
    {"recvfrom$packet", 45},
    {"recvfrom$phonet", 45},
    {"recvfrom$rose", 45},
    {"recvfrom$rxrpc", 45},
    {"recvfrom$unix", 45},
    {"recvfrom$x25", 45},
    {"recvmmsg", 299},
    {"recvmsg", 47},
    {"recvmsg$can_bcm", 47},
    {"recvmsg$can_j1939", 47},
    {"recvmsg$can_raw", 47},
    {"recvmsg$hf", 47},
    {"recvmsg$kcm", 47},
    {"recvmsg$qrtr", 47},
    {"remap_file_pages", 216},
    {"removexattr", 197},
    {"rename", 82},
    {"renameat", 264},
    {"renameat2", 316},
    {"request_key", 249},
    {"restart_syscall", 219},
    {"rmdir", 84},
    {"rseq", 334},
    {"rt_sigaction", 13},
    {"rt_sigpending", 127},
    {"rt_sigprocmask", 14},
    {"rt_sigqueueinfo", 129},
    {"rt_sigreturn", 15},
    {"rt_sigsuspend", 130},
    {"rt_sigtimedwait", 128},
    {"rt_tgsigqueueinfo", 297},
    {"sched_getaffinity", 204},
    {"sched_getattr", 315},
    {"sched_getparam", 143},
    {"sched_getscheduler", 145},
    {"sched_rr_get_interval", 148},
    {"sched_setaffinity", 203},
    {"sched_setattr", 314},
    {"sched_setparam", 142},
    {"sched_setscheduler", 144},
    {"sched_yield", 24},
    {"seccomp$SECCOMP_GET_ACTION_AVAIL", 317, {0, 0, 0, 0, 1}},
    {"seccomp$SECCOMP_GET_NOTIF_SIZES", 317, {0, 0, 0, 0, 1}},
    {"seccomp$SECCOMP_SET_MODE_FILTER", 317, {0, 0, 0, 0, 1}},
    {"seccomp$SECCOMP_SET_MODE_FILTER_LISTENER", 317, {0, 0, 0, 0, 1}},
    {"seccomp$SECCOMP_SET_MODE_STRICT", 317, {0, 0, 0, 0, 1}},
    {"select", 23},
    {"semctl$GETALL", 66, {0, 0, 0, 1}},
    {"semctl$GETNCNT", 66, {0, 0, 0, 1}},
    {"semctl$GETPID", 66, {0, 0, 0, 1}},
    {"semctl$GETVAL", 66, {0, 0, 0, 1}},
    {"semctl$GETZCNT", 66, {0, 0, 0, 1}},
    {"semctl$IPC_INFO", 66, {0, 0, 0, 1}},
    {"semctl$IPC_RMID", 66, {0, 0, 0, 1}},
    {"semctl$IPC_SET", 66, {0, 0, 0, 1}},
    {"semctl$IPC_STAT", 66, {0, 0, 0, 1}},
    {"semctl$SEM_INFO", 66, {0, 0, 0, 1}},
    {"semctl$SEM_STAT", 66, {0, 0, 0, 1}},
    {"semctl$SEM_STAT_ANY", 66, {0, 0, 0, 1}},
    {"semctl$SETALL", 66, {0, 0, 0, 1}},
    {"semctl$SETVAL", 66, {0, 0, 0, 1}},
    {"semget", 64},
    {"semget$private", 64},
    {"semop", 65},
    {"semtimedop", 220},
    {"sendfile", 40},
    {"sendmmsg", 307},
    {"sendmmsg$alg", 307},
    {"sendmmsg$inet", 307},
    {"sendmmsg$inet6", 307},
    {"sendmmsg$inet_sctp", 307},
    {"sendmmsg$nfc_llcp", 307},
    {"sendmmsg$sock", 307},
    {"sendmmsg$unix", 307},
    {"sendmsg", 46},
    {"sendmsg$802154_dgram", 46},
    {"sendmsg$802154_raw", 46},
    {"sendmsg$AUDIT_ADD_RULE", 46},
    {"sendmsg$AUDIT_DEL_RULE", 46},
    {"sendmsg$AUDIT_GET", 46},
    {"sendmsg$AUDIT_GET_FEATURE", 46},
    {"sendmsg$AUDIT_LIST_RULES", 46},
    {"sendmsg$AUDIT_MAKE_EQUIV", 46},
    {"sendmsg$AUDIT_SET", 46},
    {"sendmsg$AUDIT_SET_FEATURE", 46},
    {"sendmsg$AUDIT_SIGNAL_INFO", 46},
    {"sendmsg$AUDIT_TRIM", 46},
    {"sendmsg$AUDIT_TTY_GET", 46},
    {"sendmsg$AUDIT_TTY_SET", 46},
    {"sendmsg$AUDIT_USER", 46},
    {"sendmsg$AUDIT_USER_AVC", 46},
    {"sendmsg$AUDIT_USER_TTY", 46},
    {"sendmsg$BATADV_CMD_GET_BLA_BACKBONE", 46},
    {"sendmsg$BATADV_CMD_GET_BLA_CLAIM", 46},
    {"sendmsg$BATADV_CMD_GET_DAT_CACHE", 46},
    {"sendmsg$BATADV_CMD_GET_GATEWAYS", 46},
    {"sendmsg$BATADV_CMD_GET_HARDIF", 46},
    {"sendmsg$BATADV_CMD_GET_MCAST_FLAGS", 46},
    {"sendmsg$BATADV_CMD_GET_MESH", 46},
    {"sendmsg$BATADV_CMD_GET_NEIGHBORS", 46},
    {"sendmsg$BATADV_CMD_GET_ORIGINATORS", 46},
    {"sendmsg$BATADV_CMD_GET_ROUTING_ALGOS", 46},
    {"sendmsg$BATADV_CMD_GET_TRANSTABLE_GLOBAL", 46},
    {"sendmsg$BATADV_CMD_GET_TRANSTABLE_LOCAL", 46},
    {"sendmsg$BATADV_CMD_GET_VLAN", 46},
    {"sendmsg$BATADV_CMD_SET_HARDIF", 46},
    {"sendmsg$BATADV_CMD_SET_MESH", 46},
    {"sendmsg$BATADV_CMD_SET_VLAN", 46},
    {"sendmsg$BATADV_CMD_TP_METER", 46},
    {"sendmsg$BATADV_CMD_TP_METER_CANCEL", 46},
    {"sendmsg$DCCPDIAG_GETSOCK", 46},
    {"sendmsg$DEVLINK_CMD_GET", 46},
    {"sendmsg$DEVLINK_CMD_PORT_GET", 46},
    {"sendmsg$DEVLINK_CMD_PORT_SET", 46},
    {"sendmsg$DEVLINK_CMD_PORT_SPLIT", 46},
    {"sendmsg$DEVLINK_CMD_PORT_UNSPLIT", 46},
    {"sendmsg$DEVLINK_CMD_RELOAD", 46},
    {"sendmsg$DEVLINK_CMD_SB_GET", 46},
    {"sendmsg$DEVLINK_CMD_SB_OCC_MAX_CLEAR", 46},
    {"sendmsg$DEVLINK_CMD_SB_OCC_SNAPSHOT", 46},
    {"sendmsg$DEVLINK_CMD_SB_POOL_GET", 46},
    {"sendmsg$DEVLINK_CMD_SB_POOL_SET", 46},
    {"sendmsg$DEVLINK_CMD_SB_PORT_POOL_GET", 46},
    {"sendmsg$DEVLINK_CMD_SB_PORT_POOL_SET", 46},
    {"sendmsg$DEVLINK_CMD_SB_TC_POOL_BIND_GET", 46},
    {"sendmsg$DEVLINK_CMD_SB_TC_POOL_BIND_SET", 46},
    {"sendmsg$DEVLINK_CMD_TRAP_GET", 46},
    {"sendmsg$DEVLINK_CMD_TRAP_GROUP_GET", 46},
    {"sendmsg$DEVLINK_CMD_TRAP_GROUP_SET", 46},
    {"sendmsg$DEVLINK_CMD_TRAP_POLICER_GET", 46},
    {"sendmsg$DEVLINK_CMD_TRAP_POLICER_SET", 46},
    {"sendmsg$DEVLINK_CMD_TRAP_SET", 46},
    {"sendmsg$ETHTOOL_MSG_CHANNELS_GET", 46},
    {"sendmsg$ETHTOOL_MSG_CHANNELS_SET", 46},
    {"sendmsg$ETHTOOL_MSG_COALESCE_GET", 46},
    {"sendmsg$ETHTOOL_MSG_COALESCE_SET", 46},
    {"sendmsg$ETHTOOL_MSG_DEBUG_GET", 46},
    {"sendmsg$ETHTOOL_MSG_DEBUG_SET", 46},
    {"sendmsg$ETHTOOL_MSG_EEE_GET", 46},
    {"sendmsg$ETHTOOL_MSG_EEE_SET", 46},
    {"sendmsg$ETHTOOL_MSG_FEATURES_GET", 46},
    {"sendmsg$ETHTOOL_MSG_FEATURES_SET", 46},
    {"sendmsg$ETHTOOL_MSG_LINKINFO_GET", 46},
    {"sendmsg$ETHTOOL_MSG_LINKINFO_SET", 46},
    {"sendmsg$ETHTOOL_MSG_LINKMODES_GET", 46},
    {"sendmsg$ETHTOOL_MSG_LINKMODES_SET", 46},
    {"sendmsg$ETHTOOL_MSG_LINKSTATE_GET", 46},
    {"sendmsg$ETHTOOL_MSG_PAUSE_GET", 46},
    {"sendmsg$ETHTOOL_MSG_PAUSE_SET", 46},
    {"sendmsg$ETHTOOL_MSG_PRIVFLAGS_GET", 46},
    {"sendmsg$ETHTOOL_MSG_PRIVFLAGS_SET", 46},
    {"sendmsg$ETHTOOL_MSG_RINGS_GET", 46},
    {"sendmsg$ETHTOOL_MSG_RINGS_SET", 46},
    {"sendmsg$ETHTOOL_MSG_STRSET_GET", 46},
    {"sendmsg$ETHTOOL_MSG_TSINFO_GET", 46},
    {"sendmsg$ETHTOOL_MSG_WOL_GET", 46},
    {"sendmsg$ETHTOOL_MSG_WOL_SET", 46},
    {"sendmsg$FOU_CMD_ADD", 46},
    {"sendmsg$FOU_CMD_DEL", 46},
    {"sendmsg$FOU_CMD_GET", 46},
    {"sendmsg$GTP_CMD_DELPDP", 46},
    {"sendmsg$GTP_CMD_GETPDP", 46},
    {"sendmsg$GTP_CMD_NEWPDP", 46},
    {"sendmsg$IEEE802154_ADD_IFACE", 46},
    {"sendmsg$IEEE802154_ASSOCIATE_REQ", 46},
    {"sendmsg$IEEE802154_ASSOCIATE_RESP", 46},
    {"sendmsg$IEEE802154_DISASSOCIATE_REQ", 46},
    {"sendmsg$IEEE802154_LIST_IFACE", 46},
    {"sendmsg$IEEE802154_LIST_PHY", 46},
    {"sendmsg$IEEE802154_LLSEC_ADD_DEV", 46},
    {"sendmsg$IEEE802154_LLSEC_ADD_DEVKEY", 46},
    {"sendmsg$IEEE802154_LLSEC_ADD_KEY", 46},
    {"sendmsg$IEEE802154_LLSEC_ADD_SECLEVEL", 46},
    {"sendmsg$IEEE802154_LLSEC_DEL_DEV", 46},
    {"sendmsg$IEEE802154_LLSEC_DEL_DEVKEY", 46},
    {"sendmsg$IEEE802154_LLSEC_DEL_KEY", 46},
    {"sendmsg$IEEE802154_LLSEC_DEL_SECLEVEL", 46},
    {"sendmsg$IEEE802154_LLSEC_GETPARAMS", 46},
    {"sendmsg$IEEE802154_LLSEC_LIST_DEV", 46},
    {"sendmsg$IEEE802154_LLSEC_LIST_DEVKEY", 46},
    {"sendmsg$IEEE802154_LLSEC_LIST_KEY", 46},
    {"sendmsg$IEEE802154_LLSEC_LIST_SECLEVEL", 46},
    {"sendmsg$IEEE802154_LLSEC_SETPARAMS", 46},
    {"sendmsg$IEEE802154_SCAN_REQ", 46},
    {"sendmsg$IEEE802154_SET_MACPARAMS", 46},
    {"sendmsg$IEEE802154_START_REQ", 46},
    {"sendmsg$IPCTNL_MSG_CT_DELETE", 46},
    {"sendmsg$IPCTNL_MSG_CT_GET", 46},
    {"sendmsg$IPCTNL_MSG_CT_GET_CTRZERO", 46},
    {"sendmsg$IPCTNL_MSG_CT_GET_DYING", 46},
    {"sendmsg$IPCTNL_MSG_CT_GET_STATS", 46},
    {"sendmsg$IPCTNL_MSG_CT_GET_STATS_CPU", 46},
    {"sendmsg$IPCTNL_MSG_CT_GET_UNCONFIRMED", 46},
    {"sendmsg$IPCTNL_MSG_CT_NEW", 46},
    {"sendmsg$IPCTNL_MSG_EXP_DELETE", 46},
    {"sendmsg$IPCTNL_MSG_EXP_GET", 46},
    {"sendmsg$IPCTNL_MSG_EXP_GET_STATS_CPU", 46},
    {"sendmsg$IPCTNL_MSG_EXP_NEW", 46},
    {"sendmsg$IPCTNL_MSG_TIMEOUT_DEFAULT_GET", 46},
    {"sendmsg$IPCTNL_MSG_TIMEOUT_DEFAULT_SET", 46},
    {"sendmsg$IPCTNL_MSG_TIMEOUT_DELETE", 46},
    {"sendmsg$IPCTNL_MSG_TIMEOUT_GET", 46},
    {"sendmsg$IPCTNL_MSG_TIMEOUT_NEW", 46},
    {"sendmsg$IPSET_CMD_ADD", 46},
    {"sendmsg$IPSET_CMD_CREATE", 46},
    {"sendmsg$IPSET_CMD_DEL", 46},
    {"sendmsg$IPSET_CMD_DESTROY", 46},
    {"sendmsg$IPSET_CMD_FLUSH", 46},
    {"sendmsg$IPSET_CMD_GET_BYINDEX", 46},
    {"sendmsg$IPSET_CMD_GET_BYNAME", 46},
    {"sendmsg$IPSET_CMD_HEADER", 46},
    {"sendmsg$IPSET_CMD_LIST", 46},
    {"sendmsg$IPSET_CMD_PROTOCOL", 46},
    {"sendmsg$IPSET_CMD_RENAME", 46},
    {"sendmsg$IPSET_CMD_SAVE", 46},
    {"sendmsg$IPSET_CMD_SWAP", 46},
    {"sendmsg$IPSET_CMD_TEST", 46},
    {"sendmsg$IPSET_CMD_TYPE", 46},
    {"sendmsg$IPVS_CMD_DEL_DAEMON", 46},
    {"sendmsg$IPVS_CMD_DEL_DEST", 46},
    {"sendmsg$IPVS_CMD_DEL_SERVICE", 46},
    {"sendmsg$IPVS_CMD_FLUSH", 46},
    {"sendmsg$IPVS_CMD_GET_CONFIG", 46},
    {"sendmsg$IPVS_CMD_GET_DAEMON", 46},
    {"sendmsg$IPVS_CMD_GET_DEST", 46},
    {"sendmsg$IPVS_CMD_GET_INFO", 46},
    {"sendmsg$IPVS_CMD_GET_SERVICE", 46},
    {"sendmsg$IPVS_CMD_NEW_DAEMON", 46},
    {"sendmsg$IPVS_CMD_NEW_DEST", 46},
    {"sendmsg$IPVS_CMD_NEW_SERVICE", 46},
    {"sendmsg$IPVS_CMD_SET_CONFIG", 46},
    {"sendmsg$IPVS_CMD_SET_DEST", 46},
    {"sendmsg$IPVS_CMD_SET_INFO", 46},
    {"sendmsg$IPVS_CMD_SET_SERVICE", 46},
    {"sendmsg$IPVS_CMD_ZERO", 46},
    {"sendmsg$L2TP_CMD_NOOP", 46},
    {"sendmsg$L2TP_CMD_SESSION_CREATE", 46},
    {"sendmsg$L2TP_CMD_SESSION_DELETE", 46},
    {"sendmsg$L2TP_CMD_SESSION_GET", 46},
    {"sendmsg$L2TP_CMD_SESSION_MODIFY", 46},
    {"sendmsg$L2TP_CMD_TUNNEL_CREATE", 46},
    {"sendmsg$L2TP_CMD_TUNNEL_DELETE", 46},
    {"sendmsg$L2TP_CMD_TUNNEL_GET", 46},
    {"sendmsg$L2TP_CMD_TUNNEL_MODIFY", 46},
    {"sendmsg$MPTCP_PM_CMD_ADD_ADDR", 46},
    {"sendmsg$MPTCP_PM_CMD_DEL_ADDR", 46},
    {"sendmsg$MPTCP_PM_CMD_FLUSH_ADDRS", 46},
    {"sendmsg$MPTCP_PM_CMD_GET_ADDR", 46},
    {"sendmsg$MPTCP_PM_CMD_GET_LIMITS", 46},
    {"sendmsg$MPTCP_PM_CMD_SET_LIMITS", 46},
    {"sendmsg$NBD_CMD_CONNECT", 46},
    {"sendmsg$NBD_CMD_DISCONNECT", 46},
    {"sendmsg$NBD_CMD_RECONFIGURE", 46},
    {"sendmsg$NBD_CMD_STATUS", 46},
    {"sendmsg$NET_DM_CMD_START", 46},
    {"sendmsg$NET_DM_CMD_STOP", 46},
    {"sendmsg$NFNL_MSG_ACCT_DEL", 46},
    {"sendmsg$NFNL_MSG_ACCT_GET", 46},
    {"sendmsg$NFNL_MSG_ACCT_GET_CTRZERO", 46},
    {"sendmsg$NFNL_MSG_ACCT_NEW", 46},
    {"sendmsg$NFNL_MSG_COMPAT_GET", 46},
    {"sendmsg$NFNL_MSG_CTHELPER_DEL", 46},
    {"sendmsg$NFNL_MSG_CTHELPER_GET", 46},
    {"sendmsg$NFNL_MSG_CTHELPER_NEW", 46},
    {"sendmsg$NFQNL_MSG_CONFIG", 46},
    {"sendmsg$NFQNL_MSG_VERDICT", 46},
    {"sendmsg$NFQNL_MSG_VERDICT_BATCH", 46},
    {"sendmsg$NFT_BATCH", 46},
    {"sendmsg$NFT_MSG_GETCHAIN", 46},
    {"sendmsg$NFT_MSG_GETFLOWTABLE", 46},
    {"sendmsg$NFT_MSG_GETGEN", 46},
    {"sendmsg$NFT_MSG_GETOBJ", 46},
    {"sendmsg$NFT_MSG_GETOBJ_RESET", 46},
    {"sendmsg$NFT_MSG_GETRULE", 46},
    {"sendmsg$NFT_MSG_GETSET", 46},
    {"sendmsg$NFT_MSG_GETSETELEM", 46},
    {"sendmsg$NFT_MSG_GETTABLE", 46},
    {"sendmsg$NFULNL_MSG_CONFIG", 46},
    {"sendmsg$NL80211_CMD_ABORT_SCAN", 46},
    {"sendmsg$NL80211_CMD_ADD_NAN_FUNCTION", 46},
    {"sendmsg$NL80211_CMD_ADD_TX_TS", 46},
    {"sendmsg$NL80211_CMD_ASSOCIATE", 46},
    {"sendmsg$NL80211_CMD_AUTHENTICATE", 46},
    {"sendmsg$NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL", 46},
    {"sendmsg$NL80211_CMD_CHANGE_NAN_CONFIG", 46},
    {"sendmsg$NL80211_CMD_CHANNEL_SWITCH", 46},
    {"sendmsg$NL80211_CMD_CONNECT", 46},
    {"sendmsg$NL80211_CMD_CONTROL_PORT_FRAME", 46},
    {"sendmsg$NL80211_CMD_CRIT_PROTOCOL_START", 46},
    {"sendmsg$NL80211_CMD_CRIT_PROTOCOL_STOP", 46},
    {"sendmsg$NL80211_CMD_DEAUTHENTICATE", 46},
    {"sendmsg$NL80211_CMD_DEL_INTERFACE", 46},
    {"sendmsg$NL80211_CMD_DEL_KEY", 46},
    {"sendmsg$NL80211_CMD_DEL_MPATH", 46},
    {"sendmsg$NL80211_CMD_DEL_NAN_FUNCTION", 46},
    {"sendmsg$NL80211_CMD_DEL_PMK", 46},
    {"sendmsg$NL80211_CMD_DEL_PMKSA", 46},
    {"sendmsg$NL80211_CMD_DEL_STATION", 46},
    {"sendmsg$NL80211_CMD_DEL_TX_TS", 46},
    {"sendmsg$NL80211_CMD_DISASSOCIATE", 46},
    {"sendmsg$NL80211_CMD_DISCONNECT", 46},
    {"sendmsg$NL80211_CMD_EXTERNAL_AUTH", 46},
    {"sendmsg$NL80211_CMD_FLUSH_PMKSA", 46},
    {"sendmsg$NL80211_CMD_FRAME", 46},
    {"sendmsg$NL80211_CMD_FRAME_WAIT_CANCEL", 46},
    {"sendmsg$NL80211_CMD_GET_COALESCE", 46},
    {"sendmsg$NL80211_CMD_GET_FTM_RESPONDER_STATS", 46},
    {"sendmsg$NL80211_CMD_GET_INTERFACE", 46},
    {"sendmsg$NL80211_CMD_GET_KEY", 46},
    {"sendmsg$NL80211_CMD_GET_MESH_CONFIG", 46},
    {"sendmsg$NL80211_CMD_GET_MPATH", 46},
    {"sendmsg$NL80211_CMD_GET_MPP", 46},
    {"sendmsg$NL80211_CMD_GET_POWER_SAVE", 46},
    {"sendmsg$NL80211_CMD_GET_PROTOCOL_FEATURES", 46},
    {"sendmsg$NL80211_CMD_GET_REG", 46},
    {"sendmsg$NL80211_CMD_GET_SCAN", 46},
    {"sendmsg$NL80211_CMD_GET_STATION", 46},
    {"sendmsg$NL80211_CMD_GET_SURVEY", 46},
    {"sendmsg$NL80211_CMD_GET_WIPHY", 46},
    {"sendmsg$NL80211_CMD_GET_WOWLAN", 46},
    {"sendmsg$NL80211_CMD_JOIN_IBSS", 46},
    {"sendmsg$NL80211_CMD_JOIN_MESH", 46},
    {"sendmsg$NL80211_CMD_JOIN_OCB", 46},
    {"sendmsg$NL80211_CMD_LEAVE_IBSS", 46},
    {"sendmsg$NL80211_CMD_LEAVE_MESH", 46},
    {"sendmsg$NL80211_CMD_LEAVE_OCB", 46},
    {"sendmsg$NL80211_CMD_NEW_INTERFACE", 46},
    {"sendmsg$NL80211_CMD_NEW_KEY", 46},
    {"sendmsg$NL80211_CMD_NEW_MPATH", 46},
    {"sendmsg$NL80211_CMD_NEW_STATION", 46},
    {"sendmsg$NL80211_CMD_NOTIFY_RADAR", 46},
    {"sendmsg$NL80211_CMD_PEER_MEASUREMENT_START", 46},
    {"sendmsg$NL80211_CMD_PROBE_CLIENT", 46},
    {"sendmsg$NL80211_CMD_PROBE_MESH_LINK", 46},
    {"sendmsg$NL80211_CMD_RADAR_DETECT", 46},
    {"sendmsg$NL80211_CMD_REGISTER_BEACONS", 46},
    {"sendmsg$NL80211_CMD_REGISTER_FRAME", 46},
    {"sendmsg$NL80211_CMD_RELOAD_REGDB", 46},
    {"sendmsg$NL80211_CMD_REMAIN_ON_CHANNEL", 46},
    {"sendmsg$NL80211_CMD_REQ_SET_REG", 46},
    {"sendmsg$NL80211_CMD_SET_BEACON", 46},
    {"sendmsg$NL80211_CMD_SET_BSS", 46},
    {"sendmsg$NL80211_CMD_SET_CHANNEL", 46},
    {"sendmsg$NL80211_CMD_SET_COALESCE", 46},
    {"sendmsg$NL80211_CMD_SET_CQM", 46},
    {"sendmsg$NL80211_CMD_SET_INTERFACE", 46},
    {"sendmsg$NL80211_CMD_SET_KEY", 46},
    {"sendmsg$NL80211_CMD_SET_MAC_ACL", 46},
    {"sendmsg$NL80211_CMD_SET_MCAST_RATE", 46},
    {"sendmsg$NL80211_CMD_SET_MESH_CONFIG", 46},
    {"sendmsg$NL80211_CMD_SET_MPATH", 46},
    {"sendmsg$NL80211_CMD_SET_MULTICAST_TO_UNICAST", 46},
    {"sendmsg$NL80211_CMD_SET_NOACK_MAP", 46},
    {"sendmsg$NL80211_CMD_SET_PMK", 46},
    {"sendmsg$NL80211_CMD_SET_PMKSA", 46},
    {"sendmsg$NL80211_CMD_SET_POWER_SAVE", 46},
    {"sendmsg$NL80211_CMD_SET_QOS_MAP", 46},
    {"sendmsg$NL80211_CMD_SET_REG", 46},
    {"sendmsg$NL80211_CMD_SET_REKEY_OFFLOAD", 46},
    {"sendmsg$NL80211_CMD_SET_STATION", 46},
    {"sendmsg$NL80211_CMD_SET_TID_CONFIG", 46},
    {"sendmsg$NL80211_CMD_SET_TX_BITRATE_MASK", 46},
    {"sendmsg$NL80211_CMD_SET_WDS_PEER", 46},
    {"sendmsg$NL80211_CMD_SET_WIPHY", 46},
    {"sendmsg$NL80211_CMD_SET_WIPHY_NETNS", 46},
    {"sendmsg$NL80211_CMD_SET_WOWLAN", 46},
    {"sendmsg$NL80211_CMD_START_AP", 46},
    {"sendmsg$NL80211_CMD_START_NAN", 46},
    {"sendmsg$NL80211_CMD_START_P2P_DEVICE", 46},
    {"sendmsg$NL80211_CMD_START_SCHED_SCAN", 46},
    {"sendmsg$NL80211_CMD_STOP_AP", 46},
    {"sendmsg$NL80211_CMD_STOP_NAN", 46},
    {"sendmsg$NL80211_CMD_STOP_P2P_DEVICE", 46},
    {"sendmsg$NL80211_CMD_STOP_SCHED_SCAN", 46},
    {"sendmsg$NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH", 46},
    {"sendmsg$NL80211_CMD_TDLS_CHANNEL_SWITCH", 46},
    {"sendmsg$NL80211_CMD_TDLS_MGMT", 46},
    {"sendmsg$NL80211_CMD_TDLS_OPER", 46},
    {"sendmsg$NL80211_CMD_TESTMODE", 46},
    {"sendmsg$NL80211_CMD_TRIGGER_SCAN", 46},
    {"sendmsg$NL80211_CMD_UNEXPECTED_FRAME", 46},
    {"sendmsg$NL80211_CMD_UPDATE_CONNECT_PARAMS", 46},
    {"sendmsg$NL80211_CMD_UPDATE_FT_IES", 46},
    {"sendmsg$NL80211_CMD_UPDATE_OWE_INFO", 46},
    {"sendmsg$NL80211_CMD_VENDOR", 46},
    {"sendmsg$NL802154_CMD_DEL_SEC_DEV", 46},
    {"sendmsg$NL802154_CMD_DEL_SEC_DEVKEY", 46},
    {"sendmsg$NL802154_CMD_DEL_SEC_KEY", 46},
    {"sendmsg$NL802154_CMD_DEL_SEC_LEVEL", 46},
    {"sendmsg$NL802154_CMD_GET_INTERFACE", 46},
    {"sendmsg$NL802154_CMD_GET_SEC_DEV", 46},
    {"sendmsg$NL802154_CMD_GET_SEC_DEVKEY", 46},
    {"sendmsg$NL802154_CMD_GET_SEC_KEY", 46},
    {"sendmsg$NL802154_CMD_GET_SEC_LEVEL", 46},
    {"sendmsg$NL802154_CMD_GET_WPAN_PHY", 46},
    {"sendmsg$NL802154_CMD_NEW_INTERFACE", 46},
    {"sendmsg$NL802154_CMD_NEW_SEC_DEV", 46},
    {"sendmsg$NL802154_CMD_NEW_SEC_DEVKEY", 46},
    {"sendmsg$NL802154_CMD_NEW_SEC_KEY", 46},
    {"sendmsg$NL802154_CMD_NEW_SEC_LEVEL", 46},
    {"sendmsg$NL802154_CMD_SET_ACKREQ_DEFAULT", 46},
    {"sendmsg$NL802154_CMD_SET_BACKOFF_EXPONENT", 46},
    {"sendmsg$NL802154_CMD_SET_CCA_ED_LEVEL", 46},
    {"sendmsg$NL802154_CMD_SET_CCA_MODE", 46},
    {"sendmsg$NL802154_CMD_SET_CHANNEL", 46},
    {"sendmsg$NL802154_CMD_SET_LBT_MODE", 46},
    {"sendmsg$NL802154_CMD_SET_MAX_CSMA_BACKOFFS", 46},
    {"sendmsg$NL802154_CMD_SET_MAX_FRAME_RETRIES", 46},
    {"sendmsg$NL802154_CMD_SET_PAN_ID", 46},
    {"sendmsg$NL802154_CMD_SET_SEC_PARAMS", 46},
    {"sendmsg$NL802154_CMD_SET_SHORT_ADDR", 46},
    {"sendmsg$NL802154_CMD_SET_TX_POWER", 46},
    {"sendmsg$NL802154_CMD_SET_WPAN_PHY_NETNS", 46},
    {"sendmsg$NLBL_CALIPSO_C_ADD", 46},
    {"sendmsg$NLBL_CALIPSO_C_LIST", 46},
    {"sendmsg$NLBL_CALIPSO_C_LISTALL", 46},
    {"sendmsg$NLBL_CALIPSO_C_REMOVE", 46},
    {"sendmsg$NLBL_CIPSOV4_C_ADD", 46},
    {"sendmsg$NLBL_CIPSOV4_C_LIST", 46},
    {"sendmsg$NLBL_CIPSOV4_C_LISTALL", 46},
    {"sendmsg$NLBL_CIPSOV4_C_REMOVE", 46},
    {"sendmsg$NLBL_MGMT_C_ADD", 46},
    {"sendmsg$NLBL_MGMT_C_ADDDEF", 46},
    {"sendmsg$NLBL_MGMT_C_LISTALL", 46},
    {"sendmsg$NLBL_MGMT_C_LISTDEF", 46},
    {"sendmsg$NLBL_MGMT_C_PROTOCOLS", 46},
    {"sendmsg$NLBL_MGMT_C_REMOVE", 46},
    {"sendmsg$NLBL_MGMT_C_REMOVEDEF", 46},
    {"sendmsg$NLBL_MGMT_C_VERSION", 46},
    {"sendmsg$NLBL_UNLABEL_C_ACCEPT", 46},
    {"sendmsg$NLBL_UNLABEL_C_LIST", 46},
    {"sendmsg$NLBL_UNLABEL_C_STATICADD", 46},
    {"sendmsg$NLBL_UNLABEL_C_STATICADDDEF", 46},
    {"sendmsg$NLBL_UNLABEL_C_STATICLIST", 46},
    {"sendmsg$NLBL_UNLABEL_C_STATICLISTDEF", 46},
    {"sendmsg$NLBL_UNLABEL_C_STATICREMOVE", 46},
    {"sendmsg$NLBL_UNLABEL_C_STATICREMOVEDEF", 46},
    {"sendmsg$OSF_MSG_ADD", 46},
    {"sendmsg$OSF_MSG_REMOVE", 46},
    {"sendmsg$RDMA_NLDEV_CMD_DELLINK", 46},
    {"sendmsg$RDMA_NLDEV_CMD_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_GET_CHARDEV", 46},
    {"sendmsg$RDMA_NLDEV_CMD_NEWLINK", 46},
    {"sendmsg$RDMA_NLDEV_CMD_PORT_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_RES_CM_ID_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_RES_CQ_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_RES_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_RES_MR_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_RES_PD_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_RES_QP_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_SET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_STAT_DEL", 46},
    {"sendmsg$RDMA_NLDEV_CMD_STAT_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_STAT_SET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_SYS_GET", 46},
    {"sendmsg$RDMA_NLDEV_CMD_SYS_SET", 46},
    {"sendmsg$SEG6_CMD_DUMPHMAC", 46},
    {"sendmsg$SEG6_CMD_GET_TUNSRC", 46},
    {"sendmsg$SEG6_CMD_SETHMAC", 46},
    {"sendmsg$SEG6_CMD_SET_TUNSRC", 46},
    {"sendmsg$SMC_PNETID_ADD", 46},
    {"sendmsg$SMC_PNETID_DEL", 46},
    {"sendmsg$SMC_PNETID_FLUSH", 46},
    {"sendmsg$SMC_PNETID_GET", 46},
    {"sendmsg$SOCK_DESTROY", 46},
    {"sendmsg$SOCK_DIAG_BY_FAMILY", 46},
    {"sendmsg$TCPDIAG_GETSOCK", 46},
    {"sendmsg$TEAM_CMD_NOOP", 46},
    {"sendmsg$TEAM_CMD_OPTIONS_GET", 46},
    {"sendmsg$TEAM_CMD_OPTIONS_SET", 46},
    {"sendmsg$TEAM_CMD_PORT_LIST_GET", 46},
    {"sendmsg$TIPC_CMD_DISABLE_BEARER", 46},
    {"sendmsg$TIPC_CMD_ENABLE_BEARER", 46},
    {"sendmsg$TIPC_CMD_GET_BEARER_NAMES", 46},
    {"sendmsg$TIPC_CMD_GET_LINKS", 46},
    {"sendmsg$TIPC_CMD_GET_MAX_PORTS", 46},
    {"sendmsg$TIPC_CMD_GET_MEDIA_NAMES", 46},
    {"sendmsg$TIPC_CMD_GET_NETID", 46},
    {"sendmsg$TIPC_CMD_GET_NODES", 46},
    {"sendmsg$TIPC_CMD_GET_REMOTE_MNG", 46},
    {"sendmsg$TIPC_CMD_RESET_LINK_STATS", 46},
    {"sendmsg$TIPC_CMD_SET_LINK_PRI", 46},
    {"sendmsg$TIPC_CMD_SET_LINK_TOL", 46},
    {"sendmsg$TIPC_CMD_SET_LINK_WINDOW", 46},
    {"sendmsg$TIPC_CMD_SET_NETID", 46},
    {"sendmsg$TIPC_CMD_SET_NODE_ADDR", 46},
    {"sendmsg$TIPC_CMD_SHOW_LINK_STATS", 46},
    {"sendmsg$TIPC_CMD_SHOW_NAME_TABLE", 46},
    {"sendmsg$TIPC_CMD_SHOW_PORTS", 46},
    {"sendmsg$TIPC_CMD_SHOW_STATS", 46},
    {"sendmsg$TIPC_NL_BEARER_ADD", 46},
    {"sendmsg$TIPC_NL_BEARER_DISABLE", 46},
    {"sendmsg$TIPC_NL_BEARER_ENABLE", 46},
    {"sendmsg$TIPC_NL_BEARER_GET", 46},
    {"sendmsg$TIPC_NL_BEARER_SET", 46},
    {"sendmsg$TIPC_NL_KEY_FLUSH", 46},
    {"sendmsg$TIPC_NL_KEY_SET", 46},
    {"sendmsg$TIPC_NL_LINK_GET", 46},
    {"sendmsg$TIPC_NL_LINK_RESET_STATS", 46},
    {"sendmsg$TIPC_NL_LINK_SET", 46},
    {"sendmsg$TIPC_NL_MEDIA_GET", 46},
    {"sendmsg$TIPC_NL_MEDIA_SET", 46},
    {"sendmsg$TIPC_NL_MON_GET", 46},
    {"sendmsg$TIPC_NL_MON_PEER_GET", 46},
    {"sendmsg$TIPC_NL_MON_SET", 46},
    {"sendmsg$TIPC_NL_NAME_TABLE_GET", 46},
    {"sendmsg$TIPC_NL_NET_GET", 46},
    {"sendmsg$TIPC_NL_NET_SET", 46},
    {"sendmsg$TIPC_NL_NODE_GET", 46},
    {"sendmsg$TIPC_NL_PEER_REMOVE", 46},
    {"sendmsg$TIPC_NL_PUBL_GET", 46},
    {"sendmsg$TIPC_NL_SOCK_GET", 46},
    {"sendmsg$TIPC_NL_UDP_GET_REMOTEIP", 46},
    {"sendmsg$WG_CMD_GET_DEVICE", 46},
    {"sendmsg$WG_CMD_SET_DEVICE", 46},
    {"sendmsg$alg", 46},
    {"sendmsg$can_bcm", 46},
    {"sendmsg$can_j1939", 46},
    {"sendmsg$can_raw", 46},
    {"sendmsg$hf", 46},
    {"sendmsg$inet", 46},
    {"sendmsg$inet6", 46},
    {"sendmsg$inet_sctp", 46},
    {"sendmsg$kcm", 46},
    {"sendmsg$key", 46},
    {"sendmsg$netlink", 46},
    {"sendmsg$nfc_llcp", 46},
    {"sendmsg$nl_crypto", 46},
    {"sendmsg$nl_generic", 46},
    {"sendmsg$nl_netfilter", 46},
    {"sendmsg$nl_route", 46},
    {"sendmsg$nl_route_sched", 46},
    {"sendmsg$nl_xfrm", 46},
    {"sendmsg$qrtr", 46},
    {"sendmsg$rds", 46},
    {"sendmsg$sock", 46},
    {"sendmsg$tipc", 46},
    {"sendmsg$unix", 46},
    {"sendmsg$xdp", 46},
    {"sendto", 44},
    {"sendto$ax25", 44},
    {"sendto$inet", 44},
    {"sendto$inet6", 44},
    {"sendto$ipx", 44},
    {"sendto$isdn", 44},
    {"sendto$l2tp", 44},
    {"sendto$l2tp6", 44},
    {"sendto$llc", 44},
    {"sendto$netrom", 44},
    {"sendto$packet", 44},
    {"sendto$phonet", 44},
    {"sendto$rose", 44},
    {"sendto$rxrpc", 44},
    {"sendto$unix", 44},
    {"sendto$x25", 44},
    {"set_mempolicy", 238},
    {"set_robust_list", 273},
    {"set_thread_area", 205},
    {"set_tid_address", 218},
    {"setfsgid", 123},
    {"setfsuid", 122},
    {"setgid", 106},
    {"setgroups", 116},
    {"setitimer", 38},
    {"setns", 308},
    {"setpgid", 109},
    {"setpriority", 141},
    {"setregid", 114},
    {"setresgid", 119},
    {"setresuid", 117},
    {"setreuid", 113},
    {"setrlimit", 160},
    {"setsockopt", 54},
    {"setsockopt$ALG_SET_AEAD_AUTHSIZE", 54},
    {"setsockopt$ALG_SET_KEY", 54},
    {"setsockopt$ARPT_SO_SET_ADD_COUNTERS", 54},
    {"setsockopt$ARPT_SO_SET_REPLACE", 54},
    {"setsockopt$CAIFSO_LINK_SELECT", 54},
    {"setsockopt$CAIFSO_REQ_PARAM", 54},
    {"setsockopt$CAN_RAW_ERR_FILTER", 54},
    {"setsockopt$CAN_RAW_FD_FRAMES", 54},
    {"setsockopt$CAN_RAW_FILTER", 54},
    {"setsockopt$CAN_RAW_JOIN_FILTERS", 54},
    {"setsockopt$CAN_RAW_LOOPBACK", 54},
    {"setsockopt$CAN_RAW_RECV_OWN_MSGS", 54},
    {"setsockopt$EBT_SO_SET_COUNTERS", 54},
    {"setsockopt$EBT_SO_SET_ENTRIES", 54},
    {"setsockopt$IP6T_SO_SET_ADD_COUNTERS", 54},
    {"setsockopt$IP6T_SO_SET_REPLACE", 54},
    {"setsockopt$IPT_SO_SET_ADD_COUNTERS", 54},
    {"setsockopt$IPT_SO_SET_REPLACE", 54},
    {"setsockopt$IP_VS_SO_SET_ADD", 54},
    {"setsockopt$IP_VS_SO_SET_ADDDEST", 54},
    {"setsockopt$IP_VS_SO_SET_DEL", 54},
    {"setsockopt$IP_VS_SO_SET_DELDEST", 54},
    {"setsockopt$IP_VS_SO_SET_EDIT", 54},
    {"setsockopt$IP_VS_SO_SET_EDITDEST", 54},
    {"setsockopt$IP_VS_SO_SET_FLUSH", 54},
    {"setsockopt$IP_VS_SO_SET_STARTDAEMON", 54},
    {"setsockopt$IP_VS_SO_SET_STOPDAEMON", 54},
    {"setsockopt$IP_VS_SO_SET_TIMEOUT", 54},
    {"setsockopt$IP_VS_SO_SET_ZERO", 54},
    {"setsockopt$MISDN_TIME_STAMP", 54},
    {"setsockopt$PNPIPE_ENCAP", 54},
    {"setsockopt$PNPIPE_HANDLE", 54},
    {"setsockopt$PNPIPE_INITSTATE", 54},
    {"setsockopt$RDS_CANCEL_SENT_TO", 54},
    {"setsockopt$RDS_CONG_MONITOR", 54},
    {"setsockopt$RDS_FREE_MR", 54},
    {"setsockopt$RDS_GET_MR", 54},
    {"setsockopt$RDS_GET_MR_FOR_DEST", 54},
    {"setsockopt$RDS_RECVERR", 54},
    {"setsockopt$RXRPC_EXCLUSIVE_CONNECTION", 54},
    {"setsockopt$RXRPC_MIN_SECURITY_LEVEL", 54},
    {"setsockopt$RXRPC_SECURITY_KEY", 54},
    {"setsockopt$RXRPC_SECURITY_KEYRING", 54},
    {"setsockopt$RXRPC_UPGRADEABLE_SERVICE", 54},
    {"setsockopt$SO_ATTACH_FILTER", 54},
    {"setsockopt$SO_BINDTODEVICE", 54},
    {"setsockopt$SO_BINDTODEVICE_wg", 54},
    {"setsockopt$SO_J1939_ERRQUEUE", 54},
    {"setsockopt$SO_J1939_FILTER", 54},
    {"setsockopt$SO_J1939_PROMISC", 54},
    {"setsockopt$SO_J1939_SEND_PRIO", 54},
    {"setsockopt$SO_RDS_MSG_RXPATH_LATENCY", 54},
    {"setsockopt$SO_RDS_TRANSPORT", 54},
    {"setsockopt$SO_TIMESTAMP", 54},
    {"setsockopt$SO_TIMESTAMPING", 54},
    {"setsockopt$SO_VM_SOCKETS_BUFFER_MAX_SIZE", 54},
    {"setsockopt$SO_VM_SOCKETS_BUFFER_MIN_SIZE", 54},
    {"setsockopt$SO_VM_SOCKETS_BUFFER_SIZE", 54},
    {"setsockopt$SO_VM_SOCKETS_CONNECT_TIMEOUT", 54},
    {"setsockopt$TIPC_CONN_TIMEOUT", 54},
    {"setsockopt$TIPC_DEST_DROPPABLE", 54},
    {"setsockopt$TIPC_GROUP_JOIN", 54},
    {"setsockopt$TIPC_GROUP_LEAVE", 54},
    {"setsockopt$TIPC_IMPORTANCE", 54},
    {"setsockopt$TIPC_MCAST_BROADCAST", 54},
    {"setsockopt$TIPC_MCAST_REPLICAST", 54},
    {"setsockopt$TIPC_SRC_DROPPABLE", 54},
    {"setsockopt$WPAN_SECURITY", 54},
    {"setsockopt$WPAN_SECURITY_LEVEL", 54},
    {"setsockopt$WPAN_WANTACK", 54},
    {"setsockopt$WPAN_WANTLQI", 54},
    {"setsockopt$X25_QBITINCL", 54},
    {"setsockopt$XDP_RX_RING", 54},
    {"setsockopt$XDP_TX_RING", 54},
    {"setsockopt$XDP_UMEM_COMPLETION_RING", 54},
    {"setsockopt$XDP_UMEM_FILL_RING", 54},
    {"setsockopt$XDP_UMEM_REG", 54},
    {"setsockopt$ax25_SO_BINDTODEVICE", 54},
    {"setsockopt$ax25_int", 54},
    {"setsockopt$bt_BT_CHANNEL_POLICY", 54},
    {"setsockopt$bt_BT_DEFER_SETUP", 54},
    {"setsockopt$bt_BT_FLUSHABLE", 54},
    {"setsockopt$bt_BT_POWER", 54},
    {"setsockopt$bt_BT_RCVMTU", 54},
    {"setsockopt$bt_BT_SECURITY", 54},
    {"setsockopt$bt_BT_SNDMTU", 54},
    {"setsockopt$bt_BT_VOICE", 54},
    {"setsockopt$bt_hci_HCI_DATA_DIR", 54},
    {"setsockopt$bt_hci_HCI_FILTER", 54},
    {"setsockopt$bt_hci_HCI_TIME_STAMP", 54},
    {"setsockopt$bt_l2cap_L2CAP_CONNINFO", 54},
    {"setsockopt$bt_l2cap_L2CAP_LM", 54},
    {"setsockopt$bt_l2cap_L2CAP_OPTIONS", 54},
    {"setsockopt$bt_rfcomm_RFCOMM_LM", 54},
    {"setsockopt$inet6_IPV6_ADDRFORM", 54},
    {"setsockopt$inet6_IPV6_DSTOPTS", 54},
    {"setsockopt$inet6_IPV6_FLOWLABEL_MGR", 54},
    {"setsockopt$inet6_IPV6_HOPOPTS", 54},
    {"setsockopt$inet6_IPV6_IPSEC_POLICY", 54},
    {"setsockopt$inet6_IPV6_PKTINFO", 54},
    {"setsockopt$inet6_IPV6_RTHDR", 54},
    {"setsockopt$inet6_IPV6_RTHDRDSTOPTS", 54},
    {"setsockopt$inet6_IPV6_XFRM_POLICY", 54},
    {"setsockopt$inet6_MCAST_JOIN_GROUP", 54},
    {"setsockopt$inet6_MCAST_LEAVE_GROUP", 54},
    {"setsockopt$inet6_MCAST_MSFILTER", 54},
    {"setsockopt$inet6_MRT6_ADD_MFC", 54},
    {"setsockopt$inet6_MRT6_ADD_MFC_PROXY", 54},
    {"setsockopt$inet6_MRT6_ADD_MIF", 54},
    {"setsockopt$inet6_MRT6_DEL_MFC", 54},
    {"setsockopt$inet6_MRT6_DEL_MFC_PROXY", 54},
    {"setsockopt$inet6_buf", 54},
    {"setsockopt$inet6_dccp_buf", 54},
    {"setsockopt$inet6_dccp_int", 54},
    {"setsockopt$inet6_group_source_req", 54},
    {"setsockopt$inet6_icmp_ICMP_FILTER", 54},
    {"setsockopt$inet6_int", 54},
    {"setsockopt$inet6_mreq", 54},
    {"setsockopt$inet6_mtu", 54},
    {"setsockopt$inet6_opts", 54},
    {"setsockopt$inet6_tcp_TCP_CONGESTION", 54},
    {"setsockopt$inet6_tcp_TCP_FASTOPEN_KEY", 54},
    {"setsockopt$inet6_tcp_TCP_MD5SIG", 54},
    {"setsockopt$inet6_tcp_TCP_QUEUE_SEQ", 54},
    {"setsockopt$inet6_tcp_TCP_REPAIR", 54},
    {"setsockopt$inet6_tcp_TCP_REPAIR_OPTIONS", 54},
    {"setsockopt$inet6_tcp_TCP_REPAIR_QUEUE", 54},
    {"setsockopt$inet6_tcp_TCP_REPAIR_WINDOW", 54},
    {"setsockopt$inet6_tcp_TCP_ULP", 54},
    {"setsockopt$inet6_tcp_TLS_RX", 54},
    {"setsockopt$inet6_tcp_TLS_TX", 54},
    {"setsockopt$inet6_tcp_buf", 54},
    {"setsockopt$inet6_tcp_int", 54},
    {"setsockopt$inet6_udp_encap", 54},
    {"setsockopt$inet6_udp_int", 54},
    {"setsockopt$inet_IP_IPSEC_POLICY", 54},
    {"setsockopt$inet_IP_XFRM_POLICY", 54},
    {"setsockopt$inet_MCAST_JOIN_GROUP", 54},
    {"setsockopt$inet_MCAST_LEAVE_GROUP", 54},
    {"setsockopt$inet_MCAST_MSFILTER", 54},
    {"setsockopt$inet_buf", 54},
    {"setsockopt$inet_dccp_buf", 54},
    {"setsockopt$inet_dccp_int", 54},
    {"setsockopt$inet_group_source_req", 54},
    {"setsockopt$inet_icmp_ICMP_FILTER", 54},
    {"setsockopt$inet_int", 54},
    {"setsockopt$inet_mreq", 54},
    {"setsockopt$inet_mreqn", 54},
    {"setsockopt$inet_mreqsrc", 54},
    {"setsockopt$inet_msfilter", 54},
    {"setsockopt$inet_mtu", 54},
    {"setsockopt$inet_opts", 54},
    {"setsockopt$inet_pktinfo", 54},
    {"setsockopt$inet_sctp6_SCTP_ADAPTATION_LAYER", 54},
    {"setsockopt$inet_sctp6_SCTP_ADD_STREAMS", 54},
    {"setsockopt$inet_sctp6_SCTP_ASSOCINFO", 54},
    {"setsockopt$inet_sctp6_SCTP_AUTH_ACTIVE_KEY", 54},
    {"setsockopt$inet_sctp6_SCTP_AUTH_CHUNK", 54},
    {"setsockopt$inet_sctp6_SCTP_AUTH_DEACTIVATE_KEY", 54},
    {"setsockopt$inet_sctp6_SCTP_AUTH_DELETE_KEY", 54},
    {"setsockopt$inet_sctp6_SCTP_AUTH_KEY", 54},
    {"setsockopt$inet_sctp6_SCTP_AUTOCLOSE", 54},
    {"setsockopt$inet_sctp6_SCTP_AUTO_ASCONF", 54},
    {"setsockopt$inet_sctp6_SCTP_CONTEXT", 54},
    {"setsockopt$inet_sctp6_SCTP_DEFAULT_PRINFO", 54},
    {"setsockopt$inet_sctp6_SCTP_DEFAULT_SEND_PARAM", 54},
    {"setsockopt$inet_sctp6_SCTP_DEFAULT_SNDINFO", 54},
    {"setsockopt$inet_sctp6_SCTP_DELAYED_SACK", 54},
    {"setsockopt$inet_sctp6_SCTP_DISABLE_FRAGMENTS", 54},
    {"setsockopt$inet_sctp6_SCTP_ENABLE_STREAM_RESET", 54},
    {"setsockopt$inet_sctp6_SCTP_EVENTS", 54},
    {"setsockopt$inet_sctp6_SCTP_FRAGMENT_INTERLEAVE", 54},
    {"setsockopt$inet_sctp6_SCTP_HMAC_IDENT", 54},
    {"setsockopt$inet_sctp6_SCTP_INITMSG", 54},
    {"setsockopt$inet_sctp6_SCTP_I_WANT_MAPPED_V4_ADDR", 54},
    {"setsockopt$inet_sctp6_SCTP_MAXSEG", 54},
    {"setsockopt$inet_sctp6_SCTP_MAX_BURST", 54},
    {"setsockopt$inet_sctp6_SCTP_NODELAY", 54},
    {"setsockopt$inet_sctp6_SCTP_PARTIAL_DELIVERY_POINT", 54},
    {"setsockopt$inet_sctp6_SCTP_PEER_ADDR_PARAMS", 54},
    {"setsockopt$inet_sctp6_SCTP_PEER_ADDR_THLDS", 54},
    {"setsockopt$inet_sctp6_SCTP_PRIMARY_ADDR", 54},
    {"setsockopt$inet_sctp6_SCTP_PR_SUPPORTED", 54},
    {"setsockopt$inet_sctp6_SCTP_RECONFIG_SUPPORTED", 54},
    {"setsockopt$inet_sctp6_SCTP_RECVNXTINFO", 54},
    {"setsockopt$inet_sctp6_SCTP_RECVRCVINFO", 54},
    {"setsockopt$inet_sctp6_SCTP_RESET_ASSOC", 54},
    {"setsockopt$inet_sctp6_SCTP_RESET_STREAMS", 54},
    {"setsockopt$inet_sctp6_SCTP_RTOINFO", 54},
    {"setsockopt$inet_sctp6_SCTP_SET_PEER_PRIMARY_ADDR", 54},
    {"setsockopt$inet_sctp6_SCTP_SOCKOPT_BINDX_ADD", 54},
    {"setsockopt$inet_sctp6_SCTP_SOCKOPT_BINDX_REM", 54},
    {"setsockopt$inet_sctp6_SCTP_SOCKOPT_CONNECTX", 54},
    {"setsockopt$inet_sctp6_SCTP_SOCKOPT_CONNECTX_OLD", 54},
    {"setsockopt$inet_sctp6_SCTP_STREAM_SCHEDULER", 54},
    {"setsockopt$inet_sctp6_SCTP_STREAM_SCHEDULER_VALUE", 54},
    {"setsockopt$inet_sctp_SCTP_ADAPTATION_LAYER", 54},
    {"setsockopt$inet_sctp_SCTP_ADD_STREAMS", 54},
    {"setsockopt$inet_sctp_SCTP_ASSOCINFO", 54},
    {"setsockopt$inet_sctp_SCTP_AUTH_ACTIVE_KEY", 54},
    {"setsockopt$inet_sctp_SCTP_AUTH_CHUNK", 54},
    {"setsockopt$inet_sctp_SCTP_AUTH_DEACTIVATE_KEY", 54},
    {"setsockopt$inet_sctp_SCTP_AUTH_DELETE_KEY", 54},
    {"setsockopt$inet_sctp_SCTP_AUTH_KEY", 54},
    {"setsockopt$inet_sctp_SCTP_AUTOCLOSE", 54},
    {"setsockopt$inet_sctp_SCTP_AUTO_ASCONF", 54},
    {"setsockopt$inet_sctp_SCTP_CONTEXT", 54},
    {"setsockopt$inet_sctp_SCTP_DEFAULT_PRINFO", 54},
    {"setsockopt$inet_sctp_SCTP_DEFAULT_SEND_PARAM", 54},
    {"setsockopt$inet_sctp_SCTP_DEFAULT_SNDINFO", 54},
    {"setsockopt$inet_sctp_SCTP_DELAYED_SACK", 54},
    {"setsockopt$inet_sctp_SCTP_DISABLE_FRAGMENTS", 54},
    {"setsockopt$inet_sctp_SCTP_ENABLE_STREAM_RESET", 54},
    {"setsockopt$inet_sctp_SCTP_EVENTS", 54},
    {"setsockopt$inet_sctp_SCTP_FRAGMENT_INTERLEAVE", 54},
    {"setsockopt$inet_sctp_SCTP_HMAC_IDENT", 54},
    {"setsockopt$inet_sctp_SCTP_INITMSG", 54},
    {"setsockopt$inet_sctp_SCTP_I_WANT_MAPPED_V4_ADDR", 54},
    {"setsockopt$inet_sctp_SCTP_MAXSEG", 54},
    {"setsockopt$inet_sctp_SCTP_MAX_BURST", 54},
    {"setsockopt$inet_sctp_SCTP_NODELAY", 54},
    {"setsockopt$inet_sctp_SCTP_PARTIAL_DELIVERY_POINT", 54},
    {"setsockopt$inet_sctp_SCTP_PEER_ADDR_PARAMS", 54},
    {"setsockopt$inet_sctp_SCTP_PEER_ADDR_THLDS", 54},
    {"setsockopt$inet_sctp_SCTP_PRIMARY_ADDR", 54},
    {"setsockopt$inet_sctp_SCTP_PR_SUPPORTED", 54},
    {"setsockopt$inet_sctp_SCTP_RECONFIG_SUPPORTED", 54},
    {"setsockopt$inet_sctp_SCTP_RECVNXTINFO", 54},
    {"setsockopt$inet_sctp_SCTP_RECVRCVINFO", 54},
    {"setsockopt$inet_sctp_SCTP_RESET_ASSOC", 54},
    {"setsockopt$inet_sctp_SCTP_RESET_STREAMS", 54},
    {"setsockopt$inet_sctp_SCTP_RTOINFO", 54},
    {"setsockopt$inet_sctp_SCTP_SET_PEER_PRIMARY_ADDR", 54},
    {"setsockopt$inet_sctp_SCTP_SOCKOPT_BINDX_ADD", 54},
    {"setsockopt$inet_sctp_SCTP_SOCKOPT_BINDX_REM", 54},
    {"setsockopt$inet_sctp_SCTP_SOCKOPT_CONNECTX", 54},
    {"setsockopt$inet_sctp_SCTP_SOCKOPT_CONNECTX_OLD", 54},
    {"setsockopt$inet_sctp_SCTP_STREAM_SCHEDULER", 54},
    {"setsockopt$inet_sctp_SCTP_STREAM_SCHEDULER_VALUE", 54},
    {"setsockopt$inet_tcp_TCP_CONGESTION", 54},
    {"setsockopt$inet_tcp_TCP_FASTOPEN_KEY", 54},
    {"setsockopt$inet_tcp_TCP_MD5SIG", 54},
    {"setsockopt$inet_tcp_TCP_QUEUE_SEQ", 54},
    {"setsockopt$inet_tcp_TCP_REPAIR", 54},
    {"setsockopt$inet_tcp_TCP_REPAIR_OPTIONS", 54},
    {"setsockopt$inet_tcp_TCP_REPAIR_QUEUE", 54},
    {"setsockopt$inet_tcp_TCP_REPAIR_WINDOW", 54},
    {"setsockopt$inet_tcp_TCP_ULP", 54},
    {"setsockopt$inet_tcp_TLS_RX", 54},
    {"setsockopt$inet_tcp_TLS_TX", 54},
    {"setsockopt$inet_tcp_buf", 54},
    {"setsockopt$inet_tcp_int", 54},
    {"setsockopt$inet_udp_encap", 54},
    {"setsockopt$inet_udp_int", 54},
    {"setsockopt$ipx_IPX_TYPE", 54},
    {"setsockopt$kcm_KCM_RECV_DISABLE", 54},
    {"setsockopt$llc_int", 54},
    {"setsockopt$netlink_NETLINK_ADD_MEMBERSHIP", 54},
    {"setsockopt$netlink_NETLINK_BROADCAST_ERROR", 54},
    {"setsockopt$netlink_NETLINK_CAP_ACK", 54},
    {"setsockopt$netlink_NETLINK_DROP_MEMBERSHIP", 54},
    {"setsockopt$netlink_NETLINK_LISTEN_ALL_NSID", 54},
    {"setsockopt$netlink_NETLINK_NO_ENOBUFS", 54},
    {"setsockopt$netlink_NETLINK_PKTINFO", 54},
    {"setsockopt$netlink_NETLINK_RX_RING", 54},
    {"setsockopt$netlink_NETLINK_TX_RING", 54},
    {"setsockopt$netrom_NETROM_IDLE", 54},
    {"setsockopt$netrom_NETROM_N2", 54},
    {"setsockopt$netrom_NETROM_T1", 54},
    {"setsockopt$netrom_NETROM_T2", 54},
    {"setsockopt$netrom_NETROM_T4", 54},
    {"setsockopt$nfc_llcp_NFC_LLCP_MIUX", 54},
    {"setsockopt$nfc_llcp_NFC_LLCP_RW", 54},
    {"setsockopt$packet_add_memb", 54},
    {"setsockopt$packet_buf", 54},
    {"setsockopt$packet_drop_memb", 54},
    {"setsockopt$packet_fanout", 54},
    {"setsockopt$packet_fanout_data", 54},
    {"setsockopt$packet_int", 54},
    {"setsockopt$packet_rx_ring", 54},
    {"setsockopt$packet_tx_ring", 54},
    {"setsockopt$pppl2tp_PPPOL2TP_SO_DEBUG", 54},
    {"setsockopt$pppl2tp_PPPOL2TP_SO_LNSMODE", 54},
    {"setsockopt$pppl2tp_PPPOL2TP_SO_RECVSEQ", 54},
    {"setsockopt$pppl2tp_PPPOL2TP_SO_REORDERTO", 54},
    {"setsockopt$pppl2tp_PPPOL2TP_SO_SENDSEQ", 54},
    {"setsockopt$rose", 54},
    {"setsockopt$sock_attach_bpf", 54},
    {"setsockopt$sock_cred", 54},
    {"setsockopt$sock_int", 54},
    {"setsockopt$sock_linger", 54},
    {"setsockopt$sock_timeval", 54},
    {"setsockopt$sock_void", 54},
    {"setuid", 105},
    {"setxattr", 188},
    {"setxattr$incfs_id", 188},
    {"setxattr$incfs_metadata", 188},
    {"setxattr$incfs_size", 188},
    {"setxattr$security_capability", 188},
    {"setxattr$security_evm", 188},
    {"setxattr$security_ima", 188},
    {"setxattr$security_selinux", 188},
    {"setxattr$security_smack_transmute", 188},
    {"setxattr$smack_xattr_label", 188},
    {"setxattr$system_posix_acl", 188},
    {"setxattr$trusted_overlay_nlink", 188},
    {"setxattr$trusted_overlay_opaque", 188},
    {"setxattr$trusted_overlay_origin", 188},
    {"setxattr$trusted_overlay_redirect", 188},
    {"setxattr$trusted_overlay_upper", 188},
    {"shmat", 30},
    {"shmctl$IPC_INFO", 31},
    {"shmctl$IPC_RMID", 31},
    {"shmctl$IPC_SET", 31},
    {"shmctl$IPC_STAT", 31},
    {"shmctl$SHM_INFO", 31},
    {"shmctl$SHM_LOCK", 31},
    {"shmctl$SHM_STAT", 31},
    {"shmctl$SHM_STAT_ANY", 31},
    {"shmctl$SHM_UNLOCK", 31},
    {"shmdt", 67},
    {"shmget", 29},
    {"shmget$private", 29},
    {"shutdown", 48},
    {"sigaltstack", 131},
    {"signalfd", 282},
    {"signalfd4", 289},
    {"socket", 41},
    {"socket$alg", 41},
    {"socket$bt_bnep", 41},
    {"socket$bt_cmtp", 41},
    {"socket$bt_hidp", 41},
    {"socket$bt_rfcomm", 41},
    {"socket$caif_seqpacket", 41},
    {"socket$caif_stream", 41},
    {"socket$can_bcm", 41},
    {"socket$can_j1939", 41},
    {"socket$can_raw", 41},
    {"socket$hf", 41},
    {"socket$inet", 41},
    {"socket$inet6", 41},
    {"socket$inet6_dccp", 41},
    {"socket$inet6_icmp", 41},
    {"socket$inet6_icmp_raw", 41},
    {"socket$inet6_mptcp", 41},
    {"socket$inet6_sctp", 41},
    {"socket$inet6_tcp", 41},
    {"socket$inet6_udp", 41},
    {"socket$inet6_udplite", 41},
    {"socket$inet_dccp", 41},
    {"socket$inet_icmp", 41},
    {"socket$inet_icmp_raw", 41},
    {"socket$inet_mptcp", 41},
    {"socket$inet_sctp", 41},
    {"socket$inet_smc", 41},
    {"socket$inet_tcp", 41},
    {"socket$inet_udp", 41},
    {"socket$inet_udplite", 41},
    {"socket$ipx", 41},
    {"socket$isdn", 41},
    {"socket$isdn_base", 41},
    {"socket$kcm", 41},
    {"socket$key", 41},
    {"socket$l2tp", 41},
    {"socket$l2tp6", 41},
    {"socket$netlink", 41},
    {"socket$nl_audit", 41},
    {"socket$nl_crypto", 41},
    {"socket$nl_generic", 41},
    {"socket$nl_netfilter", 41},
    {"socket$nl_rdma", 41},
    {"socket$nl_route", 41},
    {"socket$nl_sock_diag", 41},
    {"socket$nl_xfrm", 41},
    {"socket$packet", 41},
    {"socket$phonet", 41},
    {"socket$phonet_pipe", 41},
    {"socket$pppl2tp", 41},
    {"socket$pppoe", 41},
    {"socket$pptp", 41},
    {"socket$qrtr", 41},
    {"socket$rds", 41},
    {"socket$rxrpc", 41},
    {"socket$tipc", 41},
    {"socket$unix", 41},
    {"socket$vsock_dgram", 41},
    {"socket$vsock_stream", 41},
    {"socket$xdp", 41},
    {"socketpair", 53},
    {"socketpair$nbd", 53},
    {"socketpair$tipc", 53},
    {"socketpair$unix", 53},
    {"splice", 275},
    {"stat", 4},
    {"statfs", 137},
    {"statx", 332},
    {"symlink", 88},
    {"symlinkat", 266},
    {"sync", 162},
    {"sync_file_range", 277},
    {"syncfs", 306},
    {"sysfs$1", 139},
    {"sysfs$2", 139},
    {"sysfs$3", 139},
    {"sysinfo", 99},
    {"syslog", 103},
    {"syz_80211_inject_frame", 0, {}},
    {"syz_80211_join_ibss", 0, {}},
    {"syz_btf_id_by_name$bpf_lsm", 0, {0, 500}},
    {"syz_builtin0", 0, {1}},
    {"syz_builtin1", 0, {1}},
    {"syz_emit_ethernet", 0, {}},
    {"syz_emit_vhci", 0, {}},
    {"syz_execute_func", 0, {}},
    {"syz_extract_tcp_res", 0, {}},
    {"syz_extract_tcp_res$synack", 0, {}},
    {"syz_fuse_handle_req", 0, {}},
    {"syz_genetlink_get_family_id$SEG6", 0, {}},
    {"syz_genetlink_get_family_id$batadv", 0, {}},
    {"syz_genetlink_get_family_id$devlink", 0, {}},
    {"syz_genetlink_get_family_id$ethtool", 0, {}},
    {"syz_genetlink_get_family_id$fou", 0, {}},
    {"syz_genetlink_get_family_id$gtp", 0, {}},
    {"syz_genetlink_get_family_id$ieee802154", 0, {}},
    {"syz_genetlink_get_family_id$ipvs", 0, {}},
    {"syz_genetlink_get_family_id$l2tp", 0, {}},
    {"syz_genetlink_get_family_id$mptcp", 0, {}},
    {"syz_genetlink_get_family_id$nbd", 0, {}},
    {"syz_genetlink_get_family_id$net_dm", 0, {}},
    {"syz_genetlink_get_family_id$netlbl_calipso", 0, {}},
    {"syz_genetlink_get_family_id$netlbl_cipso", 0, {}},
    {"syz_genetlink_get_family_id$netlbl_mgmt", 0, {}},
    {"syz_genetlink_get_family_id$netlbl_unlabel", 0, {}},
    {"syz_genetlink_get_family_id$nl80211", 0, {}},
    {"syz_genetlink_get_family_id$nl802154", 0, {}},
    {"syz_genetlink_get_family_id$smc", 0, {}},
    {"syz_genetlink_get_family_id$team", 0, {}},
    {"syz_genetlink_get_family_id$tipc", 0, {}},
    {"syz_genetlink_get_family_id$tipc2", 0, {}},
    {"syz_genetlink_get_family_id$wireguard", 0, {}},
    {"syz_init_net_socket$802154_dgram", 0, {}},
    {"syz_init_net_socket$802154_raw", 0, {}},
    {"syz_init_net_socket$ax25", 0, {}},
    {"syz_init_net_socket$bt_hci", 0, {}},
    {"syz_init_net_socket$bt_l2cap", 0, {}},
    {"syz_init_net_socket$bt_sco", 0, {}},
    {"syz_init_net_socket$llc", 0, {}},
    {"syz_init_net_socket$netrom", 0, {}},
    {"syz_init_net_socket$nfc_llcp", 0, {}},
    {"syz_init_net_socket$nfc_raw", 0, {}},
    {"syz_init_net_socket$nl_generic", 0, {}},
    {"syz_init_net_socket$nl_rdma", 0, {}},
    {"syz_init_net_socket$rose", 0, {}},
    {"syz_init_net_socket$x25", 0, {}},
    {"syz_io_uring_complete", 0, {}},
    {"syz_io_uring_setup", 0, {}},
    {"syz_io_uring_submit", 0, {}},
    {"syz_kvm_setup_cpu$arm64", 0, {}},
    {"syz_kvm_setup_cpu$ppc64", 0, {}},
    {"syz_kvm_setup_cpu$x86", 0, {}},
    {"syz_memcpy_off$IO_URING_METADATA_FLAGS", 0, {}},
    {"syz_memcpy_off$IO_URING_METADATA_GENERIC", 0, {}},
    {"syz_mount_image$adfs", 0, {0, 50}},
    {"syz_mount_image$affs", 0, {0, 50}},
    {"syz_mount_image$afs", 0, {0, 50}},
    {"syz_mount_image$befs", 0, {0, 50}},
    {"syz_mount_image$bfs", 0, {0, 50}},
    {"syz_mount_image$btrfs", 0, {0, 50}},
    {"syz_mount_image$cramfs", 0, {0, 50}},
    {"syz_mount_image$efs", 0, {0, 50}},
    {"syz_mount_image$erofs", 0, {0, 50}},
    {"syz_mount_image$exfat", 0, {0, 50}},
    {"syz_mount_image$ext4", 0, {0, 50}},
    {"syz_mount_image$f2fs", 0, {0, 50}},
    {"syz_mount_image$fuse", 0, {}},
    {"syz_mount_image$gfs2", 0, {0, 50}},
    {"syz_mount_image$gfs2meta", 0, {0, 50}},
    {"syz_mount_image$hfs", 0, {0, 50}},
    {"syz_mount_image$hfsplus", 0, {0, 50}},
    {"syz_mount_image$hpfs", 0, {0, 50}},
    {"syz_mount_image$iso9660", 0, {0, 50}},
    {"syz_mount_image$jffs2", 0, {0, 50}},
    {"syz_mount_image$jfs", 0, {0, 50}},
    {"syz_mount_image$minix", 0, {0, 50}},
    {"syz_mount_image$msdos", 0, {0, 50}},
    {"syz_mount_image$nfs", 0, {0, 50}},
    {"syz_mount_image$nfs4", 0, {0, 50}},
    {"syz_mount_image$nilfs2", 0, {0, 50}},
    {"syz_mount_image$ntfs", 0, {0, 50}},
    {"syz_mount_image$ocfs2", 0, {0, 50}},
    {"syz_mount_image$omfs", 0, {0, 50}},
    {"syz_mount_image$pvfs2", 0, {0, 50}},
    {"syz_mount_image$qnx4", 0, {0, 50}},
    {"syz_mount_image$qnx6", 0, {0, 50}},
    {"syz_mount_image$reiserfs", 0, {0, 50}},
    {"syz_mount_image$romfs", 0, {0, 50}},
    {"syz_mount_image$squashfs", 0, {0, 50}},
    {"syz_mount_image$sysv", 0, {0, 50}},
    {"syz_mount_image$tmpfs", 0, {0, 50}},
    {"syz_mount_image$ubifs", 0, {0, 50}},
    {"syz_mount_image$udf", 0, {0, 50}},
    {"syz_mount_image$ufs", 0, {0, 50}},
    {"syz_mount_image$v7", 0, {0, 50}},
    {"syz_mount_image$vfat", 0, {0, 50}},
    {"syz_mount_image$vxfs", 0, {0, 50}},
    {"syz_mount_image$xfs", 0, {0, 50}},
    {"syz_mount_image$zonefs", 0, {0, 50}},
    {"syz_open_dev$I2C", 0, {}},
    {"syz_open_dev$admmidi", 0, {}},
    {"syz_open_dev$amidi", 0, {}},
    {"syz_open_dev$audion", 0, {}},
    {"syz_open_dev$binderN", 0, {}},
    {"syz_open_dev$cec", 0, {}},
    {"syz_open_dev$char_raw", 0, {}},
    {"syz_open_dev$char_usb", 0, {}},
    {"syz_open_dev$dmmidi", 0, {}},
    {"syz_open_dev$dri", 0, {}},
    {"syz_open_dev$dricontrol", 0, {}},
    {"syz_open_dev$drirender", 0, {}},
    {"syz_open_dev$evdev", 0, {}},
    {"syz_open_dev$floppy", 0, {}},
    {"syz_open_dev$hiddev", 0, {0, 50}},
    {"syz_open_dev$hidraw", 0, {}},
    {"syz_open_dev$ircomm", 0, {}},
    {"syz_open_dev$loop", 0, {}},
    {"syz_open_dev$media", 0, {}},
    {"syz_open_dev$midi", 0, {}},
    {"syz_open_dev$mouse", 0, {}},
    {"syz_open_dev$ndb", 0, {}},
    {"syz_open_dev$ptys", 0, {}},
    {"syz_open_dev$radio", 0, {}},
    {"syz_open_dev$rtc", 0, {}},
    {"syz_open_dev$sg", 0, {}},
    {"syz_open_dev$sndctrl", 0, {}},
    {"syz_open_dev$sndhw", 0, {}},
    {"syz_open_dev$sndmidi", 0, {}},
    {"syz_open_dev$sndpcmc", 0, {}},
    {"syz_open_dev$sndpcmp", 0, {}},
    {"syz_open_dev$swradio", 0, {}},
    {"syz_open_dev$tty1", 0, {}},
    {"syz_open_dev$tty20", 0, {}},
    {"syz_open_dev$ttys", 0, {}},
    {"syz_open_dev$usbfs", 0, {}},
    {"syz_open_dev$usbmon", 0, {}},
    {"syz_open_dev$vbi", 0, {}},
    {"syz_open_dev$vcsa", 0, {}},
    {"syz_open_dev$vcsn", 0, {}},
    {"syz_open_dev$vcsu", 0, {}},
    {"syz_open_dev$video", 0, {}},
    {"syz_open_dev$video4linux", 0, {}},
    {"syz_open_dev$vim2m", 0, {}},
    {"syz_open_dev$vivid", 0, {}},
    {"syz_open_procfs", 0, {}},
    {"syz_open_procfs$namespace", 0, {}},
    {"syz_open_procfs$userns", 0, {}},
    {"syz_open_pts", 0, {}},
    {"syz_read_part_table", 0, {}},
    {"syz_usb_connect", 0, {0, 3000, 3000}},
    {"syz_usb_connect$cdc_ecm", 0, {0, 3000, 3000}},
    {"syz_usb_connect$cdc_ncm", 0, {0, 3000, 3000}},
    {"syz_usb_connect$hid", 0, {0, 3000, 3000}},
    {"syz_usb_connect$printer", 0, {0, 3000, 3000}},
    {"syz_usb_connect$uac1", 0, {0, 3000, 3000}},
    {"syz_usb_connect_ath9k", 0, {0, 3000, 3000}},
    {"syz_usb_control_io", 0, {0, 300}},
    {"syz_usb_control_io$cdc_ecm", 0, {0, 300}},
    {"syz_usb_control_io$cdc_ncm", 0, {0, 300}},
    {"syz_usb_control_io$hid", 0, {0, 300}},
    {"syz_usb_control_io$printer", 0, {0, 300}},
    {"syz_usb_control_io$uac1", 0, {0, 300}},
    {"syz_usb_disconnect", 0, {0, 300}},
    {"syz_usb_ep_read", 0, {0, 300}},
    {"syz_usb_ep_write", 0, {0, 300}},
    {"syz_usb_ep_write$ath9k_ep1", 0, {0, 300}},
    {"syz_usb_ep_write$ath9k_ep2", 0, {0, 300}},
    {"syz_usbip_server_init", 0, {}},
    {"tee", 276},
    {"tgkill", 234},
    {"time", 201},
    {"timer_create", 222},
    {"timer_delete", 226},
    {"timer_getoverrun", 225},
    {"timer_gettime", 224},
    {"timer_settime", 223},
    {"timerfd_create", 283},
    {"timerfd_gettime", 287},
    {"timerfd_settime", 286},
    {"times", 100},
    {"tkill", 200},
    {"truncate", 76},
    {"umount2", 166},
    {"uname", 63},
    {"unlink", 87},
    {"unlinkat", 263},
    {"unshare", 272},
    {"uselib", 134},
    {"userfaultfd", 323},
    {"ustat", 136},
    {"utime", 132},
    {"utimensat", 280},
    {"utimes", 235},
    {"vmsplice", 278},
    {"wait4", 61},
    {"waitid", 247},
    {"waitid$P_PIDFD", 247},
    {"watch_devices", 436},
    {"write", 1},
    {"write$6lowpan_control", 1},
    {"write$6lowpan_enable", 1},
    {"write$9p", 1},
    {"write$ALLOC_MW", 1},
    {"write$ALLOC_PD", 1},
    {"write$ATTACH_MCAST", 1},
    {"write$CLOSE_XRCD", 1},
    {"write$CREATE_AH", 1},
    {"write$CREATE_COMP_CHANNEL", 1},
    {"write$CREATE_CQ", 1},
    {"write$CREATE_CQ_EX", 1},
    {"write$CREATE_FLOW", 1},
    {"write$CREATE_QP", 1},
    {"write$CREATE_RWQ_IND_TBL", 1},
    {"write$CREATE_SRQ", 1},
    {"write$CREATE_WQ", 1},
    {"write$DEALLOC_MW", 1},
    {"write$DEALLOC_PD", 1},
    {"write$DEREG_MR", 1},
    {"write$DESTROY_AH", 1},
    {"write$DESTROY_CQ", 1},
    {"write$DESTROY_FLOW", 1},
    {"write$DESTROY_QP", 1},
    {"write$DESTROY_RWQ_IND_TBL", 1},
    {"write$DESTROY_SRQ", 1},
    {"write$DESTROY_WQ", 1},
    {"write$DETACH_MCAST", 1},
    {"write$FUSE_ATTR", 1},
    {"write$FUSE_BMAP", 1},
    {"write$FUSE_CREATE_OPEN", 1},
    {"write$FUSE_DIRENT", 1},
    {"write$FUSE_DIRENTPLUS", 1},
    {"write$FUSE_ENTRY", 1},
    {"write$FUSE_GETXATTR", 1},
    {"write$FUSE_INIT", 1},
    {"write$FUSE_INTERRUPT", 1},
    {"write$FUSE_IOCTL", 1},
    {"write$FUSE_LK", 1},
    {"write$FUSE_LSEEK", 1},
    {"write$FUSE_NOTIFY_DELETE", 1},
    {"write$FUSE_NOTIFY_INVAL_ENTRY", 1},
    {"write$FUSE_NOTIFY_INVAL_INODE", 1},
    {"write$FUSE_NOTIFY_POLL", 1},
    {"write$FUSE_NOTIFY_RETRIEVE", 1},
    {"write$FUSE_NOTIFY_STORE", 1},
    {"write$FUSE_OPEN", 1},
    {"write$FUSE_POLL", 1},
    {"write$FUSE_STATFS", 1},
    {"write$FUSE_WRITE", 1},
    {"write$MLX5_ALLOC_PD", 1},
    {"write$MLX5_CREATE_CQ", 1},
    {"write$MLX5_CREATE_DV_QP", 1},
    {"write$MLX5_CREATE_QP", 1},
    {"write$MLX5_CREATE_SRQ", 1},
    {"write$MLX5_CREATE_WQ", 1},
    {"write$MLX5_GET_CONTEXT", 1},
    {"write$MLX5_MODIFY_WQ", 1},
    {"write$MODIFY_QP", 1},
    {"write$MODIFY_SRQ", 1},
    {"write$OPEN_XRCD", 1},
    {"write$P9_RATTACH", 1},
    {"write$P9_RAUTH", 1},
    {"write$P9_RCLUNK", 1},
    {"write$P9_RCREATE", 1},
    {"write$P9_RFLUSH", 1},
    {"write$P9_RFSYNC", 1},
    {"write$P9_RGETATTR", 1},
    {"write$P9_RGETLOCK", 1},
    {"write$P9_RLCREATE", 1},
    {"write$P9_RLERROR", 1},
    {"write$P9_RLERRORu", 1},
    {"write$P9_RLINK", 1},
    {"write$P9_RLOCK", 1},
    {"write$P9_RLOPEN", 1},
    {"write$P9_RMKDIR", 1},
    {"write$P9_RMKNOD", 1},
    {"write$P9_ROPEN", 1},
    {"write$P9_RREAD", 1},
    {"write$P9_RREADDIR", 1},
    {"write$P9_RREADLINK", 1},
    {"write$P9_RREMOVE", 1},
    {"write$P9_RRENAME", 1},
    {"write$P9_RRENAMEAT", 1},
    {"write$P9_RSETATTR", 1},
    {"write$P9_RSTAT", 1},
    {"write$P9_RSTATFS", 1},
    {"write$P9_RSTATu", 1},
    {"write$P9_RSYMLINK", 1},
    {"write$P9_RUNLINKAT", 1},
    {"write$P9_RVERSION", 1},
    {"write$P9_RWALK", 1},
    {"write$P9_RWRITE", 1},
    {"write$P9_RWSTAT", 1},
    {"write$P9_RXATTRCREATE", 1},
    {"write$P9_RXATTRWALK", 1},
    {"write$POLL_CQ", 1},
    {"write$POST_RECV", 1},
    {"write$POST_SEND", 1},
    {"write$POST_SRQ_RECV", 1},
    {"write$QUERY_DEVICE_EX", 1},
    {"write$QUERY_PORT", 1},
    {"write$QUERY_QP", 1},
    {"write$QUERY_SRQ", 1},
    {"write$RDMA_USER_CM_CMD_ACCEPT", 1},
    {"write$RDMA_USER_CM_CMD_BIND", 1},
    {"write$RDMA_USER_CM_CMD_BIND_IP", 1},
    {"write$RDMA_USER_CM_CMD_CONNECT", 1},
    {"write$RDMA_USER_CM_CMD_CREATE_ID", 1},
    {"write$RDMA_USER_CM_CMD_DESTROY_ID", 1},
    {"write$RDMA_USER_CM_CMD_DISCONNECT", 1},
    {"write$RDMA_USER_CM_CMD_GET_EVENT", 1},
    {"write$RDMA_USER_CM_CMD_INIT_QP_ATTR", 1},
    {"write$RDMA_USER_CM_CMD_JOIN_IP_MCAST", 1},
    {"write$RDMA_USER_CM_CMD_JOIN_MCAST", 1},
    {"write$RDMA_USER_CM_CMD_LEAVE_MCAST", 1},
    {"write$RDMA_USER_CM_CMD_LISTEN", 1},
    {"write$RDMA_USER_CM_CMD_MIGRATE_ID", 1},
    {"write$RDMA_USER_CM_CMD_NOTIFY", 1},
    {"write$RDMA_USER_CM_CMD_QUERY", 1},
    {"write$RDMA_USER_CM_CMD_QUERY_ROUTE", 1},
    {"write$RDMA_USER_CM_CMD_REJECT", 1},
    {"write$RDMA_USER_CM_CMD_RESOLVE_ADDR", 1},
    {"write$RDMA_USER_CM_CMD_RESOLVE_IP", 1},
    {"write$RDMA_USER_CM_CMD_RESOLVE_ROUTE", 1},
    {"write$RDMA_USER_CM_CMD_SET_OPTION", 1},
    {"write$REG_MR", 1},
    {"write$REQ_NOTIFY_CQ", 1},
    {"write$REREG_MR", 1},
    {"write$RESIZE_CQ", 1},
    {"write$UHID_CREATE", 1},
    {"write$UHID_CREATE2", 1},
    {"write$UHID_DESTROY", 1},
    {"write$UHID_GET_REPORT_REPLY", 1},
    {"write$UHID_INPUT", 1},
    {"write$UHID_INPUT2", 1},
    {"write$UHID_SET_REPORT_REPLY", 1},
    {"write$USERIO_CMD_REGISTER", 1},
    {"write$USERIO_CMD_SEND_INTERRUPT", 1},
    {"write$USERIO_CMD_SET_PORT_TYPE", 1},
    {"write$apparmor_current", 1},
    {"write$apparmor_exec", 1},
    {"write$binfmt_aout", 1},
    {"write$binfmt_elf32", 1},
    {"write$binfmt_elf64", 1},
    {"write$binfmt_misc", 1},
    {"write$binfmt_script", 1},
    {"write$bt_hci", 1},
    {"write$capi20", 1},
    {"write$capi20_data", 1},
    {"write$cgroup_devices", 1},
    {"write$cgroup_freezer_state", 1},
    {"write$cgroup_int", 1},
    {"write$cgroup_netprio_ifpriomap", 1},
    {"write$cgroup_pid", 1},
    {"write$cgroup_subtree", 1},
    {"write$cgroup_type", 1},
    {"write$char_raw", 1},
    {"write$char_usb", 1},
    {"write$dsp", 1},
    {"write$evdev", 1},
    {"write$eventfd", 1},
    {"write$fb", 1},
    {"write$hidraw", 1},
    {"write$input_event", 1},
    {"write$khugepaged_scan", 1},
    {"write$midi", 1},
    {"write$nbd", 1},
    {"write$ppp", 1},
    {"write$proc_mixer", 1},
    {"write$proc_reclaim", 1},
    {"write$qrtrtun", 1},
    {"write$rfkill", 1},
    {"write$selinux_access", 1},
    {"write$selinux_attr", 1},
    {"write$selinux_context", 1},
    {"write$selinux_create", 1},
    {"write$selinux_load", 1},
    {"write$selinux_user", 1},
    {"write$selinux_validatetrans", 1},
    {"write$sequencer", 1},
    {"write$smack_current", 1},
    {"write$smackfs_access", 1},
    {"write$smackfs_change_rule", 1},
    {"write$smackfs_cipso", 1},
    {"write$smackfs_cipsonum", 1},
    {"write$smackfs_ipv6host", 1},
    {"write$smackfs_label", 1},
    {"write$smackfs_labels_list", 1},
    {"write$smackfs_load", 1},
    {"write$smackfs_logging", 1},
    {"write$smackfs_netlabel", 1},
    {"write$smackfs_ptrace", 1},
    {"write$snapshot", 1},
    {"write$snddsp", 1},
    {"write$sndhw", 1},
    {"write$sndhw_fireworks", 1},
    {"write$sndseq", 1},
    {"write$sysctl", 1},
    {"write$tcp_congestion", 1},
    {"write$tcp_mem", 1},
    {"write$trusty", 1},
    {"write$trusty_avb", 1},
    {"write$trusty_gatekeeper", 1},
    {"write$trusty_hwkey", 1},
    {"write$trusty_hwrng", 1},
    {"write$trusty_km", 1},
    {"write$trusty_km_secure", 1},
    {"write$trusty_storage", 1},
    {"write$tun", 1},
    {"write$uinput_user_dev", 1},
    {"write$usbip_server", 1},
    {"write$vga_arbiter", 1},
    {"write$vhost_msg", 1},
    {"write$vhost_msg_v2", 1},
    {"writev", 20},
};




std::ofstream syscall_success;

int main(int argc, char** argv)
{
	memset(input_data, 0, sizeof(input_data));
    if (mmap((char *) SYZ_DATA_OFFSET - SYZ_PAGE_SIZE, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != ((char *) SYZ_DATA_OFFSET) - SYZ_PAGE_SIZE)
        printf("mmap of left data PROT_NONE page failed");
    if (mmap((char *) SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != ((char *) SYZ_DATA_OFFSET))
        printf("mmap of data segment failed");
    if (mmap((char *) SYZ_DATA_OFFSET + SYZ_NUM_PAGES * SYZ_PAGE_SIZE, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != ((char *) SYZ_DATA_OFFSET) + SYZ_NUM_PAGES * SYZ_PAGE_SIZE)
        printf("mmap of right data PROT_NONE page failed");

	current_thread = &threads[0];


    DefaultFsFns default_fns;
    cm_ = new PassthroughCmFsOps (&default_fns, mount_point);
	debug("NOT USING SHMEM BREH\n");

	
    auto progfile = std::ifstream("prog");
    int i = 0;
    while(!progfile.eof()) {
        progfile.get(input_data[i]);
        i++;
    }

    printf("MOUNT POINT: %s\n", mount_point.c_str());
	int status = execute_test();


	syscall_success.close();
	return status;
}









void reply_execute(int status)
{
	execute_reply reply = {};
	reply.magic = kOutMagic;
	reply.done = true;
	reply.status = status;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe write failed");
}

std::string getcwd_string( void ) {
    char buff[PATH_MAX];
    char *r = getcwd( buff, PATH_MAX );
	if (!r) {
		failmsg("getcwd", "fail");		
	}
    std::string cwd( buff );
    return cwd;
}

// execute_test executes program stored in input_data.
int execute_test()
{
	// Duplicate global collide variable on stack.
	// Fuzzer once come up with ioctl(fd, FIONREAD, 0x920000),
	// where 0x920000 was exactly collide address, so every iteration reset collide to 0.
	bool colliding = false;
    int res;
    thread_t *th;
    DefaultFsFns default_fns;
    std::string cwd, test_sandbox, dest;
    std::vector<int> failed_calls;

    dest = "/root/tmpdir/testzone";

    input_pos = (uint64*)input_data;

    cwd = getcwd_string();
    // debug("MAKING DIR: %s\n", dest.c_str());
    res = mkdir(dest.c_str(), 0777);
    if (res < 0) {
        debug("error making directory: %s", strerror(res));
    }
    res = chdir(dest.c_str());
    printf("CHDIR: %s\n", dest.c_str());
    if (res < 0) {
        debug("failed to chdir: %s\n", strerror(errno));
    }

	// if (cm.CmMark() < 0) {
    //     debug("Error marking: %s\n", strerror(errno));
    // }
	int call_index = 0;
	uint64 prog_extra_cover_timeout = 0;
    for(;;) {
          uint64_t call_num = read_input(&input_pos);
          printf("CALL NUM: %d\n", call_num);
          if (call_num == instr_eof)
            break;
          if (call_num == instr_copyin) {
            printf("COPY IN\n");
            char *addr = (char *) read_input(&input_pos);
            uint64 typ = read_input(&input_pos);
            switch (typ) {
              case arg_const: {
                printf("ARG CONST\n");
                uint64 size, bf, bf_off, bf_len;
                uint64 arg = read_const_arg(&input_pos, &size, &bf, &bf_off, &bf_len);
                copyin(addr, arg, size, bf, bf_off, bf_len);
                break;
              }
              case arg_result: {
                printf("ARG RESULT\n");
                uint64 meta = read_input(&input_pos);
                uint64 size = meta & 0xff;
                uint64 bf = meta >> 8;
                uint64 val = read_result(&input_pos);
                copyin(addr, val, size, bf, 0, 0);
                break;
              }
              case arg_data: {
                printf("ARG DATA\n");
                uint64_t size = read_input(&input_pos);
                size &= ~(1ull << 63); // readable flag
                printf("SIZE: %llu\n", size);
                printf("ADDR: %p %p %d\n", addr, input_pos, size);
                NONFAILING(memcpy(addr, input_pos, size));
                // Read out the data.
                for (uint64_t i = 0; i < (size + 7) / 8; i++)
                  read_input(&input_pos);
                break;
              }
              case arg_csum: {
                  printf("CHECKSUM\n");
              }
              default:
                printf("bad argument type", "type=%llu", typ);
            }
            continue;
          }
          if (call_num == instr_copyout) {
            printf("COPY OUT\n");
            read_input(&input_pos); // index
            read_input(&input_pos); // addr
            read_input(&input_pos); // size
            // The copyout will happen when/if the call completes.
            continue;
          }

          // Normal syscall.
          if (call_num >= ARRAY_SIZE(syscalls))
            printf("invalid syscall number, call_num=%d", call_num);
          const call_t *call = &syscalls[call_num];
          if (call->attrs.disabled)
            printf("executing disabled syscall, syscall=%s", call->name);
          uint64_t copyout_index = read_input(&input_pos);
          uint64_t num_args = read_input(&input_pos);
          if (num_args > kMaxArgs)
            printf("command has bad number of arguments", "args=%llu", num_args);
          uint64 args[kMaxArgs] = {};
          for (uint64_t i = 0; i < num_args; i++)
            args[i] = read_arg(&input_pos);
          for (uint64_t i = num_args; i < kMaxArgs; i++)
            args[i] = 0;
        th = schedule_call(call_index++, call_num, colliding, copyout_index,
					     num_args, args, input_pos);
		// debug("CHECKPT: %d\n", checkpt);
		// Execute directly.
		execute_call(th);
        res = th->res;
        if (res < 0) {
            printf("RES: %d %d", res, call_index-1);
            failed_calls.push_back(call_index-1);
        }
    }
	
    res = chdir(cwd.c_str());
    if (res < 0) {
        failmsg("Failed to chdir", "error code=%d\n", res);
    }
	res = system(("rm -rf " + dest).c_str());
	if (res < 0) {
		failmsg("Failed to rmdir", "error code=%d\n", res);
	}
    std::ofstream outfile("failedcalls");

    for (auto &i : failed_calls) {
        outfile << i << endl;
    }
#if SYZ_HAVE_CLOSE_FDS
	debug("Closing fds\n");
	close_fds();
#endif
    return res;
}

thread_t* schedule_call(int call_index, int call_num, bool colliding, uint64 copyout_index, uint64 num_args, uint64* args, uint64* pos)
{
	// Find a spare thread to execute the call.
	int i = 0;
	if (i == kMaxThreads)
		exitf("out of threads");
	thread_t* th = &threads[i];
	last_scheduled = th;
	th->colliding = colliding;
	th->copyout_pos = pos;
	th->copyout_index = copyout_index;
	th->executing = true;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
	return th;
}



std::string getString(uint64_t arg) {
	if ((int64_t) arg < 0)
		return "";
    char *a = (char *) arg;
    if (a == NULL)
        return "";
    else
        return std::string(a);
}

std::string getPath(uint64_t arg) {
	std::string rel_path = getString(arg);
	return rel_path;
}

intptr_t execute_cc_syscall(const call_t* call, intptr_t args[kMaxArgs]) {
    int ret = 0;
	unsigned long max_change = 1024*32;
	unsigned long len, offset;
	unsigned int mode, flags;
	errno = 0;
    switch(call->sys_nr) {
        case SYS_write:
			len = (unsigned long)args[2];
			len = len > max_change ? max_change : len;
            ret = cm_->CmWrite((int) args[0], (void *) args[1], len);
            break;
        case SYS_pwrite64:
			len = (unsigned long)args[3];
			len = len > max_change ? max_change : len;
			ret = cm_->CmPwrite((int)args[0], (void*)args[1], (size_t)args[2], len);
            break;
        case SYS_open:
			flags = (unsigned int)args[1];
			flags &= ~O_PATH;
			mode = (unsigned int)args[2];
			if (flags == 0) {
				debug("open flags are 0\n");
			} 
			if (flags & O_RDWR) {
				debug("O_RDWR\n");
			} else if (flags & O_RDONLY) {
				debug("O_RDONLY\n");
			} else if (flags & O_WRONLY) {
				debug("O_WRONLY\n");
			}
			if (flags & O_CLOEXEC) {
				debug("O_CLOEXEC\n");
			} 
			if (flags & O_CREAT) {
				debug("O_CREAT\n");
			}
			if (flags & O_DIRECTORY) {
				debug("O_DIRECTORY\n");
			}
			if (flags & O_EXCL) {
				debug("O_EXCL\n");
			}
			if (flags & O_NOCTTY) {
				debug("O_NOCTTY\n");
			}
			if (flags & O_NOFOLLOW) {
				debug("O_NOFOLLOW\n");
			}
			if (flags & O_TMPFILE) {
				debug("O_TMPFILE\n");
			}
			if (flags & O_TRUNC) {
				debug("O_TRUNC\n");
			}
			if (flags & O_APPEND) {
				debug("O_APPEND\n");
			}
			if (flags & O_ASYNC) {
				debug("O_ASYNC\n");
			}
			if (flags & O_DIRECT) {
				debug("O_DIRECT\n");
			}
			if (flags & O_DSYNC) {
				debug("O_DSYNC\n");
			}
			if (flags & O_LARGEFILE) {
				debug("O_LARGEFILE\n");
			}
			if (flags & O_NOATIME) {
				debug("O_NOATIME\n");
			}
			if (flags & O_NONBLOCK) {
				debug("O_NONBLOCK\n");
			}
			if (flags & O_NDELAY) {
				debug("O_NDELAY\n");
			}
			if (flags & O_PATH) {
				debug("O_PATH\n");
			}
			if (flags & O_SYNC) {
				debug("O_SYNC\n");
			}
			ret = cm_->CmOpen(getPath(args[0]), flags | O_CREAT, mode);
            printf("ERROR: %s %d\n", strerror(errno), ret);
            break;
        case SYS_mkdir:
			ret = cm_->CmMkdir(getPath(args[0]), (mode_t)args[1]);
            break;
        case SYS_symlink:
			ret = cm_->CmSymlink(getPath(args[0]), getPath(args[1]));
            break;
        case SYS_link:
			ret = cm_->CmLink(getPath(args[0]), getPath(args[1]));
            break;
        case SYS_fdatasync:
            ret = cm_->CmFdatasync((int)args[0]);
            break;
        case SYS_fsync:
            ret = cm_->CmFsync((int)args[0]);
            break;
		// case SYS_fchmod:
		// 	ret = cm_->CmFchmod((int) args[0], (mode_t) args[1]);
		// 	break;
        case SYS_truncate:
			len = (unsigned long)args[1];
			len = len > max_change ? max_change : len;;
            ret = cm_->CmTruncate(getPath(args[0]).c_str(), len);
            break;
		case SYS_ftruncate:
			len = (unsigned long)args[1];
			len = len > max_change ? max_change : len;
			ret = cm_->CmFtruncate((int)args[0], len);
			break;
        case SYS_rmdir:
            ret = cm_->CmRmdir(getPath(args[0]));
            break;
		case SYS_unlink:
            ret = cm_->CmUnlink(getPath(args[0]));
            break;
        case SYS_fallocate:
			offset = (unsigned long)args[3];
		 	len = (unsigned long)args[4];
			offset = offset > max_change ? max_change : offset;
			len = len > max_change ? max_change : len;
			mode = (int)args[1];
			if (mode == 0) {
				debug("default fallocate mode\n");
			} 
			if (mode & FALLOC_FL_KEEP_SIZE) {
				debug("FALLOC_FL_KEEPS_SIZE\n");
			}
			if (mode & FALLOC_FL_UNSHARE_RANGE) {
				debug("FALLOC_FL_UNSHARE_RANGE\n");
			}
			if (mode & FALLOC_FL_PUNCH_HOLE) {
				debug("FALLOC_FL_PUNCH_HOLE\n");
			}
			if (mode & FALLOC_FL_COLLAPSE_RANGE) {
				debug("FALLOC_FL_COLLAPSE_RANGE\n");
			}
			if (mode & FALLOC_FL_ZERO_RANGE) {
				debug("FALLOC_FL_ZERO_RANGE\n");
			}
			if (mode & FALLOC_FL_INSERT_RANGE) {
				debug("FALLOC_FL_INSERT_RANGE\ns");
			}
            ret = cm_->CmFallocate((int)args[0], mode, offset, len);
            break;
        case SYS_close:
            ret = cm_->CmClose((int) args[0]);
            break;
        case SYS_rename:
			// skip it if we are trying to rename the mount point
			if (!(getPath(args[0]) == mount_point + "/" || getPath(args[1]) == mount_point + "/")) {
            	ret = cm_->CmRename(getPath(args[0]), getPath(args[1]));
			} else {
				ret = -1;
			}
            break;
        case SYS_sync:
            syscall(call->sys_nr, (intptr_t) args[0], (intptr_t) args[1], (intptr_t) args[2], (intptr_t) args[3], (intptr_t) args[4], (intptr_t) args[5]);
            break;
		case SYS_read:
			ret = syscall(call->sys_nr, (intptr_t) args[0], (intptr_t) args[1], (intptr_t) args[2], (intptr_t) args[3], (intptr_t) args[4], (intptr_t) args[5]);
			break;
        default:
            ret = syscall(call->sys_nr, (intptr_t) args[0], (intptr_t) args[1], (intptr_t) args[2], (intptr_t) args[3], (intptr_t) args[4], (intptr_t) args[5]);
            break;
    }
	// if (checkpt) {
	// 	if (cm_->CmCheckpoint() < 0) {
	// 		ret = -1;
	// 		fail("Failed to checkpoint\n");
	// 	}
	// }
	if (ret < 0) {
        printf("ERROR: %s\n", strerror(errno));
		syscall_success << "FAILED" << endl;
	} else {
		syscall_success << "SUCCEEDED" << endl;
	}
    return ret;
}

void execute_call(thread_t* th)
{
	const call_t* call = &syscalls[th->call_num];
	// memset(th->args, 0, th->num_args*sizeof(intptr_t));
	debug("EXECUTE CALL\n");
	debug("#%d -> %s(",
	      th->id, call->name);
	for (int i = 0; i < th->num_args; i++) {
		if (i != 0)
			debug(", ");
		debug("0x%llx", (uint64)th->args[i]);
	}
	debug(")\n");

	int fail_fd = -1;
	th->soft_fail_state = false;

	// For pseudo-syscalls and user-space functions NONFAILING can abort before assigning to th->res.
	// Arrange for res = -1 and errno = EFAULT result for such case.
	th->res = -1;
	errno = EFAULT;
	NONFAILING(th->res = execute_cc_syscall(call, th->args));
	// debug("SYSCALL RES: %ld\n", th->res);
	th->reserrno = errno;
	// Our pseudo-syscalls may misbehave.
	if ((th->res == -1 && th->reserrno == 0) || call->attrs.ignore_return)
		th->reserrno = EINVAL;
	// Reset the flag before the first possible fail().
	th->soft_fail_state = false;

	th->fault_injected = false;


	debug("#%d <- %s=0x%llx errno=%d ",
	      th->id, call->name, (uint64)th->res, th->reserrno);
	if (flag_coverage)
		debug("cover=%u ", th->cov.size);
	if (flag_fault && th->call_index == flag_fault_call)
		debug("fault=%d ", th->fault_injected);
	debug("\n");
}




template <typename T>
void copyin_int(char* addr, uint64 val, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	if (bf_off == 0 && bf_len == 0) {
		*(T*)addr = swap(val, sizeof(T), bf);
		return;
	}
	T x = swap(*(T*)addr, sizeof(T), bf);
	debug_verbose("copyin_int<%zu>: old x=0x%llx\n", sizeof(T), (uint64)x);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	const uint64 shift = sizeof(T) * CHAR_BIT - bf_off - bf_len;
#else
	const uint64 shift = bf_off;
#endif
	x = (x & ~BITMASK(shift, bf_len)) | ((val << shift) & BITMASK(shift, bf_len));
	debug_verbose("copyin_int<%zu>: new x=0x%llx\n", sizeof(T), (uint64)x);
	*(T*)addr = swap(x, sizeof(T), bf);
}

void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	debug_verbose("copyin: addr=%p val=0x%llx size=%llu bf=%llu bf_off=%llu bf_len=%llu\n",
		      addr, val, size, bf, bf_off, bf_len);
	if (bf != binary_format_native && bf != binary_format_bigendian && (bf_off != 0 || bf_len != 0))
		failmsg("bitmask for string format", "off=%llu, len=%llu", bf_off, bf_len);
	switch (bf) {
	case binary_format_native:
	case binary_format_bigendian:
		switch (size) {
			case 1:
				copyin_int<uint8>(addr, val, bf, bf_off, bf_len);
				break;
			case 2:
				copyin_int<uint16>(addr, val, bf, bf_off, bf_len);
				break;
			case 4:
				copyin_int<uint32>(addr, val, bf, bf_off, bf_len);
				break;
			case 8:
				copyin_int<uint64>(addr, val, bf, bf_off, bf_len);
				break;
			default:
				failmsg("copyin: bad argument size", "size=%llu", size);
		};
		break;
	case binary_format_strdec:
		if (size != 20)
			failmsg("bad strdec size", "size=%llu", size);
		sprintf((char*)addr, "%020llu", val);
		break;
	case binary_format_strhex:
		if (size != 18)
			failmsg("bad strhex size", "size=%llu", size);
		sprintf((char*)addr, "0x%016llx", val);
		break;
	case binary_format_stroct:
		if (size != 23)
			failmsg("bad stroct size", "size=%llu", size);
		sprintf((char*)addr, "%023llo", val);
		break;
	default:
		failmsg("unknown binary format", "format=%llu", bf);
	}
}

bool copyout(char* addr, uint64 size, uint64* res)
{
    switch (size) {
		    case 1:
			    *res = *(uint8*)addr;
			    break;
		    case 2:
			    *res = *(uint16*)addr;
			    break;
		    case 4:
			    *res = *(uint32*)addr;
			    break;
		    case 8:
			    *res = *(uint64*)addr;
			    break;
		    default:
			    failmsg("copyout: bad argument size", "size=%llu", size);
	    };
	return true; 
	    
}

uint64 read_arg(uint64** input_posp)
{
	uint64 typ = read_input(input_posp);
	switch (typ) {
	case arg_const: {
		uint64 size, bf, bf_off, bf_len;
		uint64 val = read_const_arg(input_posp, &size, &bf, &bf_off, &bf_len);
		if (bf != binary_format_native && bf != binary_format_bigendian)
			failmsg("bad argument binary format", "format=%llu", bf);
		if (bf_off != 0 || bf_len != 0)
			failmsg("bad argument bitfield", "off=%llu, len=%llu", bf_off, bf_len);
		return swap(val, size, bf);
	}
	case arg_result: {
		uint64 meta = read_input(input_posp);
		uint64 bf = meta >> 8;
		if (bf != binary_format_native)
			failmsg("bad result argument format", "format=%llu", bf);
		return read_result(input_posp);
	}
	default:
		failmsg("bad argument type", "type=%llu", typ);
	}
}

uint64 swap(uint64 v, uint64 size, uint64 bf)
{
	if (bf == binary_format_native)
		return v;
	if (bf != binary_format_bigendian)
		failmsg("bad binary format in swap", "format=%llu", bf);
	switch (size) {
	case 2:
		return htobe16(v);
	case 4:
		return htobe32(v);
	case 8:
		return htobe64(v);
	default:
		failmsg("bad big-endian int size", "size=%llu", size);
	}
}

uint64 read_const_arg(uint64** input_posp, uint64* size_p, uint64* bf_p, uint64* bf_off_p, uint64* bf_len_p)
{
	uint64 meta = read_input(input_posp);
	uint64 val = read_input(input_posp);
	*size_p = meta & 0xff;
	uint64 bf = (meta >> 8) & 0xff;
	*bf_off_p = (meta >> 16) & 0xff;
	*bf_len_p = (meta >> 24) & 0xff;
	uint64 pid_stride = meta >> 32;
	val += pid_stride * 8;
	*bf_p = bf;
	return val;
}

uint64 read_result(uint64** input_posp)
{
	uint64 idx = read_input(input_posp);
	uint64 op_div = read_input(input_posp);
	uint64 op_add = read_input(input_posp);
	uint64 arg = read_input(input_posp);
	if (idx >= kMaxCommands)
		failmsg("command refers to bad result", "result=%lld", idx);
	if (results[idx].executed) {
		arg = results[idx].val;
		if (op_div != 0)
			arg = arg / op_div;
		arg += op_add;
	}
	return arg;
}

uint64 read_input(uint64** input_posp, bool peek)
{
	uint64* input_pos = *input_posp;
	if ((char*)input_pos >= input_data + kMaxInput)
		failmsg("input command overflows input", "pos=%p: [%p:%p)", input_pos, input_data, input_data + kMaxInput);
	if (!peek)
		*input_posp = input_pos + 1;
    printf("READ INPUT\n");
	return *input_pos;
}

// int set_up_imgs(std::string pm_device) {
//     int ret;
//     std::string command;

//     // in past testing scripts, we've zeroed the PM device and then 
//     // used dd to copy the base image onto it; use the same approach
//     command = ZERO1 + pm_device + ZERO2;
//     ret = system(command.c_str());
//     if (ret < 0) {
//         perror("system (dd zero)");
//         return ret;
//     }

//     // remove("/tmp/nova_replay.img");

//     // int fd = open("/tmp/nova_replay.img", O_RDWR | O_CREAT, 0777);
//     // if (fd < 0) {
//     //     perror("open");
//     //     return fd;
//     // }
    
//     // ret = ftruncate(fd, pm_size);
//     // if (ret < 0) {
//     //     perror("truncate");
//     //     return ret;
//     // }

//     // close(fd);

//     return 0;
// }


void failmsg(const char* err, const char* msg, ...)
{
	int e = errno;
	fprintf(stderr, "SYZFAIL: %s\n", err);
	if (msg) {
		va_list args;
		va_start(args, msg);
		vfprintf(stderr, msg, args);
		va_end(args);
	}
	fprintf(stderr, " (errno %d: %s)\n", e, strerror(e));

	// fail()'s are often used during the validation of kernel reactions to queries
	// that were issued by pseudo syscalls implementations. As fault injection may
	// cause the kernel not to succeed in handling these queries (e.g. socket writes
	// or reads may fail), this could ultimately lead to unwanted "lost connection to
	// test machine" crashes.
	// In order to avoid this and, on the other hand, to still have the ability to
	// signal a disastrous situation, the exit code of this function depends on the
	// current context.
	// All fail() invocations during system call execution with enabled fault injection
	// lead to termination with zero exit code. In all other cases, the exit code is
	// kFailStatus.
	if (current_thread && current_thread->soft_fail_state)
		doexit(0);
	doexit(kFailStatus);
}

void fail(const char* err)
{
	failmsg(err, 0);
}

void exitf(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	doexit(0);
}

void debug(const char* msg, ...)
{
	if (!flag_debug)
		return;
	int err = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
	errno = err;
}

void debug_dump_data(const char* data, int length)
{
	if (!flag_debug)
		return;
	int i = 0;
	for (; i < length; i++) {
		debug("%02x ", data[i] & 0xff);
		if (i % 16 == 15)
			debug("\n");
	}
	if (i % 16 != 0)
		debug("\n");
}
