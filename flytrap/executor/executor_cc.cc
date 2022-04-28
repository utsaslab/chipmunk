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
#include <chrono>


#include <iostream>


#include "user_tools/api/wrapper.h"
#include "tester_defs.h"

using std::endl;
using namespace fs_testing;
using namespace fs_testing::user_tools::api;
using std::chrono::steady_clock;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::microseconds;
using std::chrono::time_point;


#if !GOOS_windows
#include <unistd.h>
#endif

#include "defs.h"
#include "harness/Tester.h"
#include "harness/SyzTester.h"
#include "ioctl.h"

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

// Logical error (e.g. invalid input program), use as an assert() alternative.
// If such error happens 10+ times in a row, it will be detected as a bug by syz-fuzzer.
// syz-fuzzer will fail and syz-manager will create a bug for this.
// Note: err is used for bug deduplication, thus distinction between err (constant message)
// and msg (varying part).
static NORETURN void fail(const char* err);
static NORETURN PRINTF(2, 3) void failmsg(const char* err, const char* msg, ...);
// Just exit (e.g. due to temporal ENOMEM error).
static NORETURN PRINTF(1, 2) void exitf(const char* msg, ...);
static NORETURN void doexit(int status);

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

static void receive_execute();
static std::string receive_name();
static void reply_execute(int status);

#if GOOS_akaros
static void resend_execute(int fd);
#endif


#define ZERO1 "dd if=/dev/zero of="
#define ZERO2 " status=noxfer > /dev/null 2>&1"

#define IMG1 "sudo dd if=/dev/zero of="
#define IMG2 "/code/replay/nova_replay.img bs=128M count=1 status=noxfer > /dev/null 2>&1"

bool reorder = true;

#if SYZ_EXECUTOR_USES_FORK_SERVER
static void receive_handshake();
static void reply_handshake();
#endif

#if SYZ_EXECUTOR_USES_SHMEM
const int kMaxOutput = 16 << 20;
const int kMaxMountOutput = 16 << 22;
const int kInFd = 3;
const int kOutFd = 4;
const int kOutFdMmap = 5;
static uint32* output_data;
static uint32* output_pos;
static uint32* output_data_mount;
static uint32* write_output(uint32 v);
static uint32* write_output_64(uint64 v);
static void write_completed(uint32 completed);
static uint32 hash(uint32 a);
static bool dedup(uint32 sig);
#endif

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
#include "common.h"


const int kMaxInput = 4 << 20; // keep in sync with prog.ExecBufferSize
const int kMaxCommands = 1000; // prog package knows about this constant (prog.execMaxCommands)

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

static constexpr char kChangePath[] = "/root/tmpdir/run_changes";

static CmFsOps *cm_;


std::string mount_point = "/mnt/pmem";
std::string mount_point_replay = "/mnt/pmem_replay";

static std::string logger;
static std::string fs_module;
static std::string FS;

static unsigned long pm_start = 0x100000000;
const unsigned long replay_pm_start = 0x108000000; // TODO: make this command line arg or get it dynamically
static unsigned long pm_size = 0x7ffffff;


typedef intptr_t(SYSCALLAPI* syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);

struct call_t {
	const char* name;
	int sys_nr;
	call_attrs_t attrs;
	syscall_t call;
};

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
int max_k = 5; // TODO: make this a command line argument

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
static void execute_call(thread_t* th, bool collectCoverage);
static void thread_create(thread_t* th, int id);
static void* worker_thread(void* arg);
static int execute_test(int change_fd, bool writeCoverage);
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
static int test_loop();
static Tester *syz_tester;

#include "syscalls.h"

#if GOOS_linux
#include "executor_linux.h"
#elif GOOS_fuchsia
#include "executor_fuchsia.h"
#elif GOOS_akaros
#include "executor_akaros.h"
#elif GOOS_freebsd || GOOS_netbsd || GOOS_openbsd
#include "executor_bsd.h"
#elif GOOS_windows
#include "executor_windows.h"
#elif GOOS_test
#include "executor_test.h"
#else
#error "unknown OS"
#endif

#include "cov_filter.h"

#include "test.h"

std::ofstream syscall_success;

int main(int argc, char** argv)
{
	// TODO: these should potentially be handled differently if we don't want fs module to be 
	// a required argument
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "setup") == 0) {
		setup_features(argv + 2, argc - 2);
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "leak") == 0) {
#if SYZ_HAVE_LEAK_CHECK
		check_leaks(argv + 2, argc - 2);
#else
		fail("leak checking is not implemented");
#endif
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "setup_kcsan_filterlist") == 0) {
#if SYZ_HAVE_KCSAN
		setup_kcsan_filterlist(argv + 2, argc - 2, true);
#else
		fail("KCSAN is not implemented");
#endif
		return 0;
	}
	if (argc >= 2)
		instanceId = std::string(argv[1]);

	if (argc >= 3) {
		logger = std::string(argv[2]);
	}
	
	if (argc >= 4) {
		FS = std::string(argv[3]);
	}

	if (argc >= 5) {
		fs_module = std::string(argv[4]);
	}

	if (argc >= 6 ) {
		if (strcmp(argv[5], "mountCov") == 0)
			mountCov = true;
		if (strcmp(argv[5], "-module") == 0)
			loadModule = true;
	}



	if (argc >= 7) {
		if (strcmp(argv[6], "reload") == 0)
			reloadFS = true;
		if (strcmp(argv[6], "-module") == 0)
			loadModule = true;
	}
	if (argc >= 8) {
		if (strcmp(argv[7], "reload") == 0)
			reloadFS = true;
	}

	debug("MOUNT COV BREH: %d\n", mountCov);
	start_time_ms = current_time_ms();
	srand (time(NULL));

	os_init(argc, argv, (char*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE);
	current_thread = &threads[0];

	// TODO: unmount the file systems if they are still mounted from a past run
	// it's fine if these fail; the systems may not be mounted
	umount("/dev/pmem0");
	umount("/dev/pmem1");

	// // TODO: automatically set loadmodule properly if we are using ext4 or xfs
	// // TODO: this isn't necessary, is it? we load it again shortly
	// if (loadModule && FS.compare("ext4") != 0 && FS.compare("xfs") != 0) {
	// 	cout << "reloading fs module 3" << endl;
	// 	int r = system(std::string("insmod " + fs_module).c_str());
	// 	if (r < 0) {
	// 		debug("Failed to load module\n");
	// 	}
	// }

	std::string command = "dd if=/dev/zero of=/dev/pmem1 bs=100M > /dev/null 2>&1";
	system(command.c_str());

	if (FS.compare("ext4") == 0 || FS.compare("xfs") == 0) {
		reorder = false;
	}
	debug("LOGGER: %s\n", logger.c_str());
	if (FS.compare("xfs") == 0) {
		logger = "/logger-ext4.ko";
	}

	// clean up leftover state
	// these will fail if nothing is loaded, but that's fine
	int r = system((std::string("rmmod ") + logger).c_str());
	if (FS.compare("ext4") != 0 && FS.compare("xfs") != 0) {
		r = system((std::string("rmmod ") + FS + " -f").c_str());
	}

	umount("/dev/pmem0");
	umount("/dev/pmem1");

	//load logger
	// TODO: we end up redoing this if reload is on. set it up so we aren't doing extra work
	if (FS.compare("ext4") != 0 && FS.compare("xfs") != 0) {
		debug("reloading fs module 1\n");
		r = system(std::string("insmod " + fs_module).c_str());
		if (r < 0) {
			debug("Failed to load module");
		}
	}
	r = system((std::string("insmod ") + logger).c_str());
	if (r < 0) {
		debug("Failed to load logger\n");
	}

    DefaultFsFns default_fns;
    cm_ = new RecordCmFsOps (&default_fns, mount_point);
	debug("NOT USING SHMEM BREH\n");

#if SYZ_EXECUTOR_USES_SHMEM
	if (mmap(&input_data[0], kMaxInput, PROT_READ, MAP_PRIVATE | MAP_FIXED, kInFd, 0) != &input_data[0])
		fail("mmap of input file failed");
	// The output region is the only thing in executor process for which consistency matters.
	// If it is corrupted ipc package will fail to parse its contents and panic.
	// But fuzzer constantly invents new ways of how to currupt the region,
	// so we map the region at a (hopefully) hard to guess address with random offset,
	// surrounded by unmapped pages.
	// The address chosen must also work on 32-bit kernels with 1GB user address space.
	void* preferred = (void*)(0x1b2bc20000ull + (1 << 20) * (getpid() % 128));

	void* preferredMount = (void*)(0x2b2bc20000ull + (1 << 20) * (getpid() % 128));

	output_data = (uint32*)mmap(preferred, kMaxOutput,
				    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0);
	if (output_data != preferred)
		fail("mmap of output file failed");

	output_data_mount = (uint32*)mmap(preferredMount, kMaxMountOutput,
				    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFdMmap, 0);
	
	if (preferredMount != output_data_mount)
		fail("mmap of output mount file failed");

	// Prevent test programs to mess with these fds.
	// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
	// which will cause fuzzer to crash.
	close(kInFd);
	close(kOutFd);
#endif
	std::string fs_type;
	if (FS.compare(std::string("nova")) == 0) {
		fs_type = std::string("NOVA");
	} else {
		fs_type = FS;
	}

	syz_tester = new SyzTester(std::string("/dev/pmem0"), 
                                std::string("/dev/pmem1"), 
                                mount_point, 
								mount_point_replay,
                                pm_start, 
								pm_size, 
								fs_type,
								false, 
                                std::string(""), 
								0, 
								1, 
								false,
								(unsigned long) input_data, output_data_mount, flag_collect_cover, flag_dedup_cover, 
								&threads[0], 
								mountCov, 
								replay_pm_start,
								instanceId,
								max_k);

	syscall_success.open("/root/tmpdir/syscall_result_" + instanceId, std::ofstream::out | std::ofstream::app);
	
	syz_tester->setup();
	use_temporary_dir();
	install_segv_handler();
	setup_control_pipes();
#if SYZ_EXECUTOR_USES_FORK_SERVER
	receive_handshake();
#else
	receive_execute();
#endif
	if (flag_coverage) {
		for (int i = 0; i < kMaxThreads; i++) {
			threads[i].cov.fd = kCoverFd + i;
			cover_open(&threads[i].cov, false);
			cover_protect(&threads[i].cov);
		}
		cover_open(&extra_cov, true);
		cover_protect(&extra_cov);
		if (flag_extra_coverage) {
			// Don't enable comps because we don't use them in the fuzzer yet.
			cover_enable(&extra_cov, false, true);
		}
		init_coverage_filter();
	}

    debug("MOUNT POINT: %s\n", mount_point.c_str());
	int status = 0;
	if (flag_sandbox_none)
		status = run_test();
#if SYZ_HAVE_SANDBOX_SETUID
	else if (flag_sandbox_setuid)
		status = do_sandbox_setuid();
#endif
#if SYZ_HAVE_SANDBOX_NAMESPACE
	else if (flag_sandbox_namespace)
		status = do_sandbox_namespace();
#endif
#if SYZ_HAVE_SANDBOX_ANDROID
	else if (flag_sandbox_android)
		status = do_sandbox_android();
#endif
	else
		fail("unknown sandbox type");

#if SYZ_EXECUTOR_USES_FORK_SERVER
	fprintf(stderr, "loop exited with status %d\n", status);
	// Other statuses happen when fuzzer processes manages to kill loop, e.g. with:
	// ptrace(PTRACE_SEIZE, 1, 0, 0x100040)
	if (status != kFailStatus)
		status = 0;
    debug("STATUS: %d\n", status);
	// If an external sandbox process wraps executor, the out pipe will be closed
	// before the sandbox process exits this will make ipc package kill the sandbox.
	// As the result sandbox process will exit with exit status 9 instead of the executor
	// exit status (notably kFailStatus). So we duplicate the exit status on the pipe.
	reply_execute(status);
	doexit(status);
	// Unreachable.
	return 1;
#else
	reply_execute(status);
	syscall_success.close();
	return status;
#endif
}

void setup_control_pipes()
{
	if (dup2(0, kInPipeFd) < 0)
		fail("dup2(0, kInPipeFd) failed");
	if (dup2(1, kOutPipeFd) < 0)
		fail("dup2(1, kOutPipeFd) failed");
	if (dup2(2, 1) < 0)
		fail("dup2(2, 1) failed");
	// We used to close(0), but now we dup stderr to stdin to keep fd numbers
	// stable across executor and C programs generated by pkg/csource.
	if (dup2(2, 0) < 0)
		fail("dup2(2, 0) failed");
}

void parse_env_flags(uint64 flags)
{
	// Note: Values correspond to ordering in pkg/ipc/ipc.go, e.g. FlagSandboxNamespace
	flag_debug = flags & (1 << 0);
	flag_coverage = flags & (1 << 1);
	if (flags & (1 << 2))
		flag_sandbox_setuid = true;
	else if (flags & (1 << 3))
		flag_sandbox_namespace = true;
	else if (flags & (1 << 4))
		flag_sandbox_android = true;
	else
		flag_sandbox_none = true;
	flag_extra_coverage = flags & (1 << 5);
	flag_net_injection = flags & (1 << 6);
	flag_net_devices = flags & (1 << 7);
	flag_net_reset = flags & (1 << 8);
	flag_cgroups = flags & (1 << 9);
	flag_close_fds = flags & (1 << 10);
	flag_devlink_pci = flags & (1 << 11);
	flag_vhci_injection = flags & (1 << 12);
	flag_wifi = flags & (1 << 13);
}

#if SYZ_EXECUTOR_USES_FORK_SERVER
void receive_handshake()
{
    debug("RECEIVED HANDSHAKE");
	handshake_req req = {};
	int n = read(kInPipeFd, &req, sizeof(req));
	if (n != sizeof(req))
		failmsg("handshake read failed", "read=%d", n);
	if (req.magic != kInMagic)
		failmsg("bad handshake magic", "magic=0x%llx", req.magic);
	parse_env_flags(req.flags);
	procid = req.pid;
    debug("RECEIVED HANDSHAKE");
}

void reply_handshake()
{
	handshake_reply reply = {};
	reply.magic = kOutMagic;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe write failed");
}
#endif

static execute_req last_execute_req;

std::ofstream genLog(std::string test_name)
{
	time_t now = time(0);
    char time_st[18];
    strftime(time_st, sizeof(time_st), "%Y%m%d_%H%M%S", localtime(&now));
    std::string s = "/root/tmpdir/logs/workloads/" + std::string(time_st) + "-" + test_name + ".log";
	std::ofstream logfile(s);
	return logfile;
}

int run_test()
{
	int iter, ret;
	
	iter = 0;
	debug("MOUNT COV: %d\n", mountCov);
	debug("INSTANCE ID: %s\n", instanceId.c_str());
	debug("FS MODULE PATH: %s", fs_module.c_str());
    reply_handshake();
	if (mountCov) {
		cover_open(&threads[0].mount_cov, false);
		cover_enable(&threads[0].mount_cov, false, false);
	}
	for (;;iter++) {
		ret = syz_tester->resetLogger();
		if (ret < 0) {
			debug("Error resetting logger at start of loop\n");
		}
		debug("========================= NEW TEST =========================");
		ret = test_loop();
		std::string fs_type;
		if (FS.compare(std::string("nova")) == 0) {
			fs_type = std::string("NOVA");
		} else {
			fs_type = FS;
		}
		// delete syz_tester; // TODO: this causes a double free bug in syz-execprog
		// but it seems like it would be a memory leak if we didn't do it....
		syz_tester = new SyzTester(std::string("/dev/pmem0"), 
                                std::string("/dev/pmem1"), 
                                mount_point, mount_point_replay,
                                pm_start, pm_size, 
                                fs_type, false, 
                                std::string(""), 0, 1, false,
								(unsigned long) input_data, output_data_mount, flag_collect_cover, flag_dedup_cover, &threads[0], mountCov,
								replay_pm_start, instanceId, max_k);
	} 
}

int test_loop() {
	int ret, change_fd, fd, status;
    pid_t child, waitres;
	std::string test_name;

    receive_execute();
    debug("RECEIVED EXECUTE\n");
	test_name = receive_name();
	test_name = test_name + "_" + instanceId;
	debug("TEST NAME: %s\n", test_name.c_str());
	int shouldCheckpoint = 0;
	// std::ofstream log = genLog(test_name);
	waitres = 0;
	checkpt = false;

	time_t now = time(0);
    char time_st[18];
    strftime(time_st, sizeof(time_st), "%Y%m%d_%H%M%S", localtime(&now));
    std::string s = "/root/tmpdir/logs/workloads/" + std::string(time_st) + "-" + test_name + ".log";
	std::ofstream log(s);


	std::string fs_type;
	if (FS.compare("nova") == 0) {
		fs_type == std::string("NOVA");
	} else {
		fs_type = FS;
	}
	
	
	// TODO: automatically set configurations properly if we are using ext4 or xfs
	if (reloadFS) {
		//load logger
		int r;
		if (FS.compare("xfs") == 0) {
			r = system(std::string("rmmod logger-ext4 -f").c_str());
		} else {
			r = system((std::string("rmmod logger-") + FS + " -f").c_str());
		}
		if (r < 0) {
			debug("Failed to remove logger\n");
		}
		if (FS.compare("ext4") != 0 && FS.compare("xfs") != 0) {
			r = system((std::string("rmmod ") + FS + " -f").c_str());
			if (r < 0) {
				debug("Failed to delete module");
			}
			debug("reloading fs module 2\n");
			r = system(std::string("insmod " + fs_module).c_str());
			if (r < 0) {
				debug("Failed to load module");
			}
		}
		//load logger
		r = system((std::string("insmod ") + logger).c_str());
		if (r < 0) {
			debug("Failed to load logger\n");
		}
	}

	if (mountCov && SYZ_EXECUTOR_USES_SHMEM) {
		// reset mount coverage
		memset(output_data_mount, 0, kMaxOutput);
	}
	syz_tester->set_test_name(test_name);

	fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        log << "Unable to open IOCTL device; is logger module loaded?" << endl;
        syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
        return fd;
    }

	// make sure logging is turned off
    // TODO: this may not be necessary, but probably a good idea to make sure we don't 
    // try to add to the log while it's being freed
    ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning on logging" << endl;
        close(fd);
        syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
        return ret;
    }
    // free the log now to ensure any remaining data from the last test is cleaned up
    ret = ioctl(fd, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error freeing log via IOCTL" << endl;
        close(fd);
        syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
        return ret;
    }

	ret = ioctl(fd, LOGGER_SET_PM_START, pm_start);
    if (ret < 0) {
        perror("ioctl");
        log << "Error setting PM address" << endl;
        close(fd);
        syz_tester->cleanup(log);
        log.close();
        return ret;
    }

    // now turn logging on for the test
    ret = ioctl(fd, LOGGER_LOG_ON, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning on logging" << endl;
        close(fd);
        syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
        return ret;
    }
    close(fd); // TODO: do we have to close it here? Maybe not, but do this for now to avoid issues with child process writing checkpoints

	// mount the FS, making sure to create a new one since we haven't copied anything in
	ret = syz_tester->mount_fs(true);
	if (ret != 0) {
		perror("mount_fs");
		log << "Unable to mount file system for profiling, error code " << ret << std::endl;
		syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
		return ret;
	} else {
		log << "Successfully mounted" << endl;
	}

	// fork a process to run the entire workload
	child = fork();
	if (child < 0) {
		perror("fork");
		syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
		return child;
	}
	// parent process
	else if (child != 0) {
		debug("PARENT PROC COLLECT COVER: %d", (int) flag_collect_cover);
		while (waitres == 0) {
			waitres = waitpid(child, &status, WNOHANG);
		}
		// if the child didn't exit normally
		if (WIFEXITED(status) == 0) {
			debug("Error terminating test_run process, status %d\n", status);
			log << "Child process exited with error " << WEXITSTATUS(status) << std::endl;
			syz_tester->cleanup(log);
			log.close();
			reply_execute(1);
			return 1;
		} 
		else {
			// the child should run the process in its entirety so the return value 
			// should always be 0, but check just in case
			if (WEXITSTATUS(status) != 0) {
				// printf("Something weird happened! The child returned %d during profiling", status);
				debug("Child process terminated with status %d\n", status);
				log << "Child process exited with error " << status << std::endl;
				syz_tester->cleanup(log);
				log.close();
				reply_execute(1);
				return 1;
			}
		}
		// otherwise, evething happened correctly
	}
	// forked process
	else {
		change_fd = open(kChangePath, O_CREAT | O_WRONLY | O_TRUNC,
						S_IRUSR | S_IWUSR);
		if (change_fd < 0) {
			log << "Test workload returned " << change_fd << std::endl;
			perror("open");
			return change_fd;
		}
		// debug("COVER OPENING\n");
		cover_open(&threads[0].cov, false);
		cover_enable(&threads[0].cov, false, false);
		// debug("COVER ENABLED\n");
		cover_protect(&threads[0].cov);
		// debug("EXECUTING TEST\n");
		// ret = execute_test(change_fd, false, true, checkpoint);
		ret = execute_test(change_fd, true);
		debug("CHILD RET: %d\n", ret);
		close (change_fd);
		// debug("EXITING\n");
		doexit(0);
	}

	// unmount the file system
	debug("ABOUT TO UNMOUNT\n");
	ret = syz_tester->unmount_fs();
	if (ret != 0) {
		perror("unmount_fs");
		debug("Error unmounting file system, error code %d\n", ret);
		log << "Error unmounting file system, error code " << ret << std::endl;
		syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
		return ret;
	}
	debug("UNMOUNTED FILE SYSTEM\n");
	shouldCheckpoint = true;

	fd = open("/dev/ioctl_dummy", 0);
	debug("IOCTL FD: %d\n", fd);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        log << "Unable to open IOCTL device; is logger module loaded?" << endl;
        syz_tester->cleanup(log);
		log.close();
		reply_execute(0);
        return fd;
    }

	ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning on logging" << endl;
        close(fd);
        syz_tester->cleanup(log);
        log.close();
        return ret;
    }

    ret = ioctl(fd, LOGGER_CHECK_MISSED, NULL);
    if (ret < 0) {
        debug("At least one kprobe was missed during testing; results are unreliable, so test is failed by default\n");
        log << "At least one kprobe was missed during testing; results are unreliable, so test is failed by default\n" << endl;
        syz_tester->cleanup(log);
		log.close();
		close(fd);
		reply_execute(0);
        return 2; // indicates that we failed specifically due to kprobe issue so the python wrapper can handle it
    }

	ret = ioctl(fd, LOGGER_SET_PM_START, replay_pm_start);
    if (ret < 0) {
        perror("ioctl");
        log << "Error setting PM address" << endl;
        close(fd);
		syz_tester->cleanup(log);
		log.close();
		reply_execute(0);
        return ret;
    }

    // load profile into tester->object BEFORE running tests so we only have to do it once
    change_fd = open(kChangePath, O_RDONLY);
    if (change_fd < 0) {
        perror("open");
        log << "Error opening profile file, error code " << change_fd << endl;
        log.close();
        syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
        return change_fd;
    }

    ret = lseek(change_fd, 0, SEEK_SET);
    if (ret < 0) {
        perror("lseek");
        log << "Error seeking in profile file, error code " << ret << endl;
        log.close();
        close(change_fd);
        syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
        return ret;
    }

    ret = syz_tester->GetChangeData(change_fd);
    if (ret != 0) {
        log << "Error getting workload profile, error code " << ret << endl;
        log.close();
        close(change_fd);
        syz_tester->cleanup(log);
		log.close();
		reply_execute(1);
        return ret;
    }

    close(fd);
	close(change_fd);
    log << "running tester.replay" << endl;

	debug("ABOUT TO RUN REPLAY\n");
	if (SYZ_EXECUTOR_USES_SHMEM) {
		syz_tester->setOutputPos(output_data_mount);
	}
	if (mountCov)
		syz_tester->collect_cover = true;
	time_point<steady_clock> replay_start = steady_clock::now();
    ret = syz_tester->replay(log, shouldCheckpoint, test_name, false, reorder, s);

	time_point<steady_clock> replay_end = steady_clock::now();
    milliseconds elapsed = duration_cast<milliseconds>(replay_end - replay_start);
    log << "time to build full replay " << elapsed.count() << endl;
    log << "----------------------------" << endl;
	
    // ret = tester->replay(checkpoint, test_name, make_trace);
    if (ret != 0) {
        // perror("replay");
        // log << "Error replaying writes, error code " << ret << endl;
		log << "FAILED" << endl;
        syz_tester->cleanup(log);
		log.close();
		reply_execute(0);
        return ret;
    }

    fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        log << "Unable to open IOCTL device; is logger module loaded?" << endl;
        syz_tester->cleanup(log);
		log.close();
		reply_execute(0);
        return fd;
    }
    ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning on logging" << endl;
        close(fd);
        syz_tester->cleanup(log);
		log.close();
		reply_execute(0);
        return ret;
    }
    ret = ioctl(fd, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error freeing log via IOCTL" << endl;
        close(fd);
        syz_tester->cleanup(log);
		log.close();
		reply_execute(0);
        return ret;
    }
    close(fd);
	log << "finished running tester.replay" << endl;

	flag_collect_cover = true;

    debug("Cleaning up\n");

    syz_tester->cleanup(log);
	log.close();
	debug("Run profiling\n");
	reply_execute(0);
	return ret;
}

std::string receive_name()
{
	char buf[1024];
	if (read(kInPipeFd, buf, sizeof(buf)) < 0)
		fail("read name failed");
	return std::string(buf);
}


void receive_execute()
{
    debug("READING FROM PIPE: %d\n", kInPipeFd);
	execute_req& req = last_execute_req;
	int r = 0;
	if ((r = read(kInPipeFd, &req, sizeof(req))) != (ssize_t)sizeof(req))
		failmsg("control pipe read failed", "debug: %d %lu\n", r, sizeof(req));
	if (req.magic != kInMagic)
		failmsg("bad execute request magic", "magic=0x%llx", req.magic);
	if (req.prog_size > kMaxInput)
		failmsg("bad execute prog size", "size=0x%llx", req.prog_size);
    debug("READ FROM PIPE\n");
	debug("RECEIVE EXEC FLAGS: %llu\n", req.exec_flags);
	parse_env_flags(req.env_flags);
	procid = req.pid;
	syscall_timeout_ms = req.syscall_timeout_ms;
	program_timeout_ms = req.program_timeout_ms;
	slowdown_scale = req.slowdown_scale;
	flag_collect_cover = req.exec_flags & (1 << 0);
	flag_dedup_cover = req.exec_flags & (1 << 1);
	flag_fault = req.exec_flags & (1 << 2);
	flag_comparisons = req.exec_flags & (1 << 3);
	flag_coverage_filter = req.exec_flags & (1 << 6);
	debug("FLAG COLLECT COVER RECEIVE: %d\n", (int) flag_collect_cover);
	if (!flag_threaded)
		flag_collide = false;
	debug("[%llums] exec opts: procid=%llu threaded=%d collide=%d cover=%d comps=%d dedup=%d fault=%d/%d/%d"
	      " timeouts=%llu/%llu/%llu prog=%llu filter=%d size=%llu\n",
	      current_time_ms() - start_time_ms, procid, flag_threaded, flag_collide,
	      flag_collect_cover, flag_comparisons, flag_dedup_cover, flag_fault,
	      flag_fault_call, flag_fault_nth, syscall_timeout_ms, program_timeout_ms, slowdown_scale,
	      req.prog_size, flag_coverage_filter, req.prog_size);
	if (syscall_timeout_ms == 0 || program_timeout_ms <= syscall_timeout_ms || slowdown_scale == 0)
		failmsg("bad timeouts", "syscall=%llu, program=%llu, scale=%llu",
			syscall_timeout_ms, program_timeout_ms, slowdown_scale);
	if (SYZ_EXECUTOR_USES_SHMEM) {
		debug("USES SHMEM BREH\n");
		if (req.prog_size)
			fail("need_prog: no program");
		return;
	}
	if (req.prog_size == 0)
		fail("need_prog: no program");
	uint64 pos = 0;
	for (;;) {
		ssize_t rv = read(kInPipeFd, input_data + pos, sizeof(input_data) - pos);
		if (rv < 0)
			fail("read failed");
		pos += rv;
		if (rv == 0 || pos >= req.prog_size)
			break;
	}
	if (pos != req.prog_size)
		failmsg("bad input size", "size=%lld, want=%lld", pos, req.prog_size);
}

#if GOOS_akaros
void resend_execute(int fd)
{
	execute_req& req = last_execute_req;
	if (write(fd, &req, sizeof(req)) != sizeof(req))
		fail("child pipe header write failed");
	if (write(fd, input_data, req.prog_size) != (ssize_t)req.prog_size)
		fail("child pipe program write failed");
}
#endif

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
int execute_test(int change_fd,  bool writeCoverage)
{
	// Duplicate global collide variable on stack.
	// Fuzzer once come up with ioctl(fd, FIONREAD, 0x920000),
	// where 0x920000 was exactly collide address, so every iteration reset collide to 0.
	bool colliding = false;
    int res;
    thread_t *th;
    uint64 *input_pos;
    DefaultFsFns default_fns;
    std::string cwd, test_sandbox, dest;

#if SYZ_EXECUTOR_USES_SHMEM
	if (writeCoverage) {
		output_pos = output_data;
		write_output(0); // Number of execute.
	}
	
	
#endif
    th = &threads[0];
	input_pos = (uint64*)input_data;
    cwd = getcwd_string();
    test_sandbox = "test_sandbox";
    dest = mount_point + "/" + test_sandbox;
    RecordCmFsOps cm(&default_fns, mount_point);
    PassthroughCmFsOps pcm(&default_fns, mount_point);
    // if (!shouldCheckpoint) {
	// 	debug ("USING RECORD\n");
    //     cm_ = &cm;
    // } else {
	// 	debug("USING PASSTHROUGH\n");
    //     cm_ = &pcm;
    // }
	cm_ = &cm;
    // debug("MAKING DIR: %s\n", dest.c_str());
    // res = mkdir(dest.c_str(), 0777);
    // if (res < 0) {
    //     debug("error making directory: %s", strerror(res));
    // }
    // res = chdir(dest.c_str());
    // debug("CHDIR: %s\n", dest.c_str());
    // if (res < 0) {
    //     debug("failed to chdir: %s\n", strerror(errno));
    // }
	// if (cm.CmMark() < 0) {
    //     debug("Error marking: %s\n", strerror(errno));
    // }
	int call_index = 0;
	uint64 prog_extra_cover_timeout = 0;
	for (;;) {
		// ctr++;
		uint64 call_num = read_input(&input_pos);
		if (call_num == instr_eof)
			break;
		if (call_num == instr_copyin) {
			char* addr = (char*)read_input(&input_pos);
			uint64 typ = read_input(&input_pos);
			switch (typ) {
			case arg_const: {
				uint64 size, bf, bf_off, bf_len;
				uint64 arg = read_const_arg(&input_pos, &size, &bf, &bf_off, &bf_len);
				copyin(addr, arg, size, bf, bf_off, bf_len);
				break;
			}
			case arg_result: {
				uint64 meta = read_input(&input_pos);
				uint64 size = meta & 0xff;
				uint64 bf = meta >> 8;
				uint64 val = read_result(&input_pos);
				copyin(addr, val, size, bf, 0, 0);
				break;
			}
			case arg_data: {
				uint64 size = read_input(&input_pos);
				size &= ~(1ull << 63); // readable flag
				NONFAILING(memcpy(addr, input_pos, size));
				// Read out the data.
				for (uint64 i = 0; i < (size + 7) / 8; i++)
					read_input(&input_pos);
				break;
			}
			case arg_csum: {
				debug_verbose("checksum found at %p\n", addr);
				uint64 size = read_input(&input_pos);
				char* csum_addr = addr;
				uint64 csum_kind = read_input(&input_pos);
				switch (csum_kind) {
				case arg_csum_inet: {
					if (size != 2)
						failmsg("bag inet checksum size", "size=%llu", size);
					debug_verbose("calculating checksum for %p\n", csum_addr);
					struct csum_inet csum;
					csum_inet_init(&csum);
					uint64 chunks_num = read_input(&input_pos);
					uint64 chunk;
					for (chunk = 0; chunk < chunks_num; chunk++) {
						uint64 chunk_kind = read_input(&input_pos);
						uint64 chunk_value = read_input(&input_pos);
						uint64 chunk_size = read_input(&input_pos);
						switch (chunk_kind) {
						case arg_csum_chunk_data:
							debug_verbose("#%lld: data chunk, addr: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							NONFAILING(csum_inet_update(&csum, (const uint8*)chunk_value, chunk_size));
							break;
						case arg_csum_chunk_const:
							if (chunk_size != 2 && chunk_size != 4 && chunk_size != 8)
								failmsg("bad checksum const chunk size", "size=%lld", chunk_size);
							// Here we assume that const values come to us big endian.
							debug_verbose("#%lld: const chunk, value: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							csum_inet_update(&csum, (const uint8*)&chunk_value, chunk_size);
							break;
						default:
							failmsg("bad checksum chunk kind", "kind=%llu", chunk_kind);
						}
					}
					uint16 csum_value = csum_inet_digest(&csum);
					debug_verbose("writing inet checksum %hx to %p\n", csum_value, csum_addr);
					copyin(csum_addr, csum_value, 2, binary_format_native, 0, 0);
					break;
				}
				default:
					failmsg("bad checksum kind", "kind=%llu", csum_kind);
				}
				break;
			}
			default:
				failmsg("bad argument type", "type=%llu", typ);
			}
			continue;
		}
		if (call_num == instr_copyout) {
			read_input(&input_pos); // index
			read_input(&input_pos); // addr
			read_input(&input_pos); // size
			// The copyout will happen when/if the call completes.
			continue;
		}

		// Normal syscall.
		if (call_num >= ARRAY_SIZE(syscalls))
			failmsg("invalid syscall number", "call_num=%llu", call_num);
		uint64 copyout_index = read_input(&input_pos);
		uint64 num_args = read_input(&input_pos);
		if (num_args > kMaxArgs)
			failmsg("command has bad number of arguments", "args=%llu", num_args);
		uint64 args[kMaxArgs] = {};
		for (uint64 i = 0; i < num_args; i++)
			args[i] = read_arg(&input_pos);
		for (uint64 i = num_args; i < kMaxArgs; i++)
			args[i] = 0;
        th = schedule_call(call_index++, call_num, colliding, copyout_index,
					     num_args, args, input_pos);
		// debug("CHECKPT: %d\n", checkpt);
		// Execute directly.
		execute_call(th, writeCoverage);
        res = th->res;
		handle_completion(th, writeCoverage);
	}

	// if we are testing ext4-dax or xfs-dax, add a sync at the end to make 
	// sure there will be a point for us to crash at. 
	if (!reorder) {
		cm_->CmSync();
	}

	// serialize the profile
	int res_2 = cm.Serialize(change_fd);
	if (res_2 < 0) {
		return res_2;
	}

    res = chdir(cwd.c_str());
    if (res < 0) {
        failmsg("Failed to chdir", "error code=%d\n", res);
    }
	// res = system("rm -rf /mnt/pmem/*");
	// if (res < 0) {
	// 	failmsg("Failed to rmdir", "error code=%d\n", res);
	// }
#if SYZ_HAVE_CLOSE_FDS
	debug("Closing fds\n");
	close_fds();
#endif

	if (!colliding && !collide) {
		write_extra_output();
		// Check for new extra coverage in small intervals to avoid situation
		// that we were killed on timeout before we write any.
		// Check for extra coverage is very cheap, effectively a memory load.
		const uint64 kSleepMs = 100;
		for (uint64 i = 0; i < prog_extra_cover_timeout / kSleepMs; i++) {
			sleep_ms(kSleepMs);
			write_extra_output();
		}
	}
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

#if SYZ_EXECUTOR_USES_SHMEM
template <typename cover_data_t>
void write_coverage_signal(cover_t* cov, uint32* signal_count_pos, uint32* cover_count_pos)
{
	// Write out feedback signals.
	// Currently it is code edges computed as xor of two subsequent basic block PCs.
	// debug("WRITING COVERAGE SIGNAL\n");
	// debug("COVERAGE SIZE: %d\n", cov->size);

	cover_data_t* cover_data = ((cover_data_t*)cov->data) + 1;
	uint32 nsig = 0;
	cover_data_t prev_pc = 0;
	bool prev_filter = true;
	int num_wrote_signal_output = 0;
	for (uint32 i = 0; i < cov->size; i++) {
		cover_data_t pc = cover_data[i];
		// debug("pc: %llu\n",(long long unsigned int) pc);
		uint32 sig = pc;
		if (use_cover_edges(pc))
			sig ^= hash(prev_pc);
		bool filter = coverage_filter(pc);
		// Ignore the edge only if both current and previous PCs are filtered out
		// to capture all incoming and outcoming edges into the interesting code.
		bool ignore = !filter && !prev_filter;
		prev_pc = pc;
		prev_filter = filter;
		if (ignore || dedup(sig)) {
			// debug("IGNORING OR DEDUPED: %d\n", dedup(sig));
			continue;
		}
		write_output(sig);
		num_wrote_signal_output++;
		nsig++;
	}
	debug("WROTE SIGNAL OUTPUT: %d\n", num_wrote_signal_output);
	// Write out number of signals.
	*signal_count_pos = nsig;

	if (!flag_collect_cover) {
		debug("NO FLAG COLLECT COVER\n");
		return;
	}
	// Write out real coverage (basic block PCs).
	uint32 cover_size = cov->size;
	if (flag_dedup_cover) {
		cover_data_t* end = cover_data + cover_size;
		cover_unprotect(cov);
		std::sort(cover_data, end);
		cover_size = std::unique(cover_data, end) - cover_data;
		cover_protect(cov);
	}
	// Truncate PCs to uint32 assuming that they fit into 32-bits.
	// True for x86_64 and arm64 without KASLR.
	// debug("COVER SIZE: %u\n", cover_size);
	for (uint32 i = 0; i < cover_size; i++) {
		// debug("WRITING OUTPUT\n");
		write_output(cover_data[i]);
	}
	*cover_count_pos = cover_size;
}
#endif

void handle_completion(thread_t* th, bool writeCoverage)
{
	if (th->res != (intptr_t)-1 && writeCoverage)
		copyout_call_results(th);
	if (!collide && !th->colliding && writeCoverage) {
		write_call_output(th, true);
		write_extra_output();
	}
	th->executing = false;
}

void copyout_call_results(thread_t* th)
{
	if (th->copyout_index != no_copyout) {
		if (th->copyout_index >= kMaxCommands)
			failmsg("result overflows kMaxCommands", "index=%lld", th->copyout_index);
		results[th->copyout_index].executed = true;
		results[th->copyout_index].val = th->res;
	}
	for (bool done = false; !done;) {
		uint64 instr = read_input(&th->copyout_pos);
		switch (instr) {
		case instr_copyout: {
			uint64 index = read_input(&th->copyout_pos);
			if (index >= kMaxCommands)
				failmsg("result overflows kMaxCommands", "index=%lld", index);
			char* addr = (char*)read_input(&th->copyout_pos);
			uint64 size = read_input(&th->copyout_pos);
			uint64 val = 0;
			if (copyout(addr, size, &val)) {
				results[index].executed = true;
				results[index].val = val;
			}
			debug_verbose("copyout 0x%llx from %p\n", val, addr);
			break;
		}
		default:
			done = true;
			break;
		}
	}
}

void write_call_output(thread_t* th, bool finished)
{
	uint32 reserrno = 999;
	const bool blocked = finished && th != last_scheduled;
	uint32 call_flags = call_flag_executed | (blocked ? call_flag_blocked : 0);
	if (finished) {
		reserrno = th->res != -1 ? 0 : th->reserrno;
		call_flags |= call_flag_finished |
			      (th->fault_injected ? call_flag_fault_injected : 0);
	}
	// debug("IS KERNEL 64 BIT: %d\n", is_kernel_64_bit);
#if SYZ_EXECUTOR_USES_SHMEM
	debug("call idx: %d, call num: %d, reserrno: %u\n", th->call_index, th->call_num, reserrno);
	write_output(th->call_index);
	write_output(th->call_num);
	write_output(reserrno);
	write_output(call_flags);
	uint32* signal_count_pos = write_output(0); // filled in later
	uint32* cover_count_pos = write_output(0); // filled in later
	uint32* comps_count_pos = write_output(0); // filled in later

	if (flag_comparisons) {
		// Collect only the comparisons
		uint32 ncomps = th->cov.size;
		kcov_comparison_t* start = (kcov_comparison_t*)(th->cov.data + sizeof(uint64));
		kcov_comparison_t* end = start + ncomps;
		if ((char*)end > th->cov.data_end)
			failmsg("too many comparisons", "ncomps=%u", ncomps);
		cover_unprotect(&th->cov);
		std::sort(start, end);
		ncomps = std::unique(start, end) - start;
		cover_protect(&th->cov);
		uint32 comps_size = 0;
		for (uint32 i = 0; i < ncomps; ++i) {
			if (start[i].ignore())
				continue;
			comps_size++;
			start[i].write();
		}
		// Write out number of comparisons.
		*comps_count_pos = comps_size;
	} else if (flag_coverage) {
		if (is_kernel_64_bit)
			write_coverage_signal<uint64>(&th->cov, signal_count_pos, cover_count_pos);
		else
			write_coverage_signal<uint32>(&th->cov, signal_count_pos, cover_count_pos);
	}
	debug_verbose("out #%u: index=%u num=%u errno=%d finished=%d blocked=%d sig=%u cover=%u comps=%u\n",
		      completed, th->call_index, th->call_num, reserrno, finished, blocked,
		      *signal_count_pos, *cover_count_pos, *comps_count_pos);	  
	completed++;
	write_completed(completed);
#else
	call_reply reply;
	reply.header.magic = kOutMagic;
	reply.header.done = 0;
	reply.header.status = 0;
	reply.call_index = th->call_index;
	reply.call_num = th->call_num;
	reply.reserrno = reserrno;
	reply.flags = call_flags;
	reply.signal_size = 0;
	reply.cover_size = 0;
	reply.comps_size = 0;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe call write failed");
	debug_verbose("out: index=%u num=%u errno=%d finished=%d blocked=%d\n",
		      th->call_index, th->call_num, reserrno, finished, blocked);
#endif
}

void write_extra_output()
{
#if SYZ_EXECUTOR_USES_SHMEM
	if (!flag_coverage || !flag_extra_coverage || flag_comparisons)
		return;
	cover_collect(&extra_cov);
	if (!extra_cov.size)
		return;
	write_output(-1); // call index
	write_output(-1); // call num
	write_output(999); // errno
	write_output(0); // call flags
	uint32* signal_count_pos = write_output(0); // filled in later
	uint32* cover_count_pos = write_output(0); // filled in later
	write_output(0); // comps_count_pos
	if (is_kernel_64_bit)
		write_coverage_signal<uint64>(&extra_cov, signal_count_pos, cover_count_pos);
	else
		write_coverage_signal<uint32>(&extra_cov, signal_count_pos, cover_count_pos);
	cover_reset(&extra_cov);
	debug_verbose("extra: sig=%u cover=%u\n", *signal_count_pos, *cover_count_pos);
	completed++;
	write_completed(completed);
#endif
}

void thread_create(thread_t* th, int id)
{
	th->created = true;
	th->id = id;
	th->executing = false;
	event_init(&th->ready);
	event_init(&th->done);
	event_set(&th->done);
	if (flag_threaded)
		thread_start(worker_thread, th);
}

void* worker_thread(void* arg)
{
	thread_t* th = (thread_t*)arg;
	current_thread = th;
	if (flag_coverage)
		cover_enable(&th->cov, flag_comparisons, false);
	for (;;) {
		event_wait(&th->ready);
		event_reset(&th->ready);
		execute_call(th, true);
		event_set(&th->done);
	}
	return 0;
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
	// if the relative path is formatted as ./filename
	if (rel_path[0] == '.' && rel_path.size() > 1) {
		rel_path = rel_path.substr(2, std::string::npos);
	}

	return mount_point + "/" + rel_path;
}

intptr_t execute_cc_syscall(const call_t* call, intptr_t args[kMaxArgs]) {
    int ret = 0;
	unsigned long max_change = 1024*32;
	unsigned long len, offset;
	unsigned int mode, flags;
	errno = 0;
    switch(call->sys_nr) {
        case SYS_write:
            if (args[1] == 0)
                break;
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
			offset = (unsigned long)args[2];
		 	len = (unsigned long)args[3];
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
            cm_->CmSync();
            break;
		case SYS_read:
			ret = cm_->CmRead((int)args[0], (void*)args[1], (size_t)args[2]);
			break;
        default:
            ret = syscall(call->sys_nr, (intptr_t) args[0], (intptr_t) args[1], (intptr_t) args[2], (intptr_t) args[3], (intptr_t) args[4], (intptr_t) args[5]);
            break;
    }
	if (ret < 0) {
		syscall_success << "FAILED" << endl;
	} else {
		syscall_success << "SUCCEEDED" << endl;
	}
    return ret;
}

void execute_call(thread_t* th, bool collectCoverage)
{
	const call_t* call = &syscalls[th->call_num];
	// memset(th->args, 0, th->num_args*sizeof(intptr_t));
	debug("EXECUTE CALL\n");
	debug("#%d [%llums] -> %s(",
	      th->id, current_time_ms() - start_time_ms, call->name);
	for (int i = 0; i < th->num_args; i++) {
		if (i != 0)
			debug(", ");
		debug("0x%llx", (uint64)th->args[i]);
	}
	debug(")\n");

	int fail_fd = -1;
	th->soft_fail_state = false;
	if (flag_fault && th->call_index == flag_fault_call) {
		if (collide)
			fail("both collide and fault injection are enabled");
		fail_fd = inject_fault(flag_fault_nth);
		th->soft_fail_state = true;
	}

	if (collectCoverage)
		cover_reset(&th->cov);
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

	if (collectCoverage) {
		cover_collect(&th->cov);
		if (th->cov.size >= kCoverSize)
			failmsg("too much cover", "thr=%d, cov=%u", th->id, th->cov.size);
	}
	th->fault_injected = false;

	if (flag_fault && th->call_index == flag_fault_call) {
		th->fault_injected = fault_injected(fail_fd);
	}

	debug("#%d [%llums] <- %s=0x%llx errno=%d ",
	      th->id, current_time_ms() - start_time_ms, call->name, (uint64)th->res, th->reserrno);
	if (flag_coverage)
		debug("cover=%u ", th->cov.size);
	if (flag_fault && th->call_index == flag_fault_call)
		debug("fault=%d ", th->fault_injected);
	debug("\n");
}

#if SYZ_EXECUTOR_USES_SHMEM
static uint32 hash(uint32 a)
{
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return a;
}

const uint32 dedup_table_size = 8 << 10;
uint32 dedup_table[dedup_table_size];

// Poorman's best-effort hashmap-based deduplication.
// The hashmap is global which means that we deduplicate across different calls.
// This is OK because we are interested only in new signals.
static bool dedup(uint32 sig)
{
	for (uint32 i = 0; i < 4; i++) {
		uint32 pos = (sig + i) % dedup_table_size;
		if (dedup_table[pos] == sig)
			return true;
		if (dedup_table[pos] == 0) {
			dedup_table[pos] = sig;
			return false;
		}
	}
	dedup_table[sig % dedup_table_size] = sig;
	return false;
}
#endif

void execute_one(){}

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
		NONFAILING(switch (size) {
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
		});
		break;
	case binary_format_strdec:
		if (size != 20)
			failmsg("bad strdec size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "%020llu", val));
		break;
	case binary_format_strhex:
		if (size != 18)
			failmsg("bad strhex size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "0x%016llx", val));
		break;
	case binary_format_stroct:
		if (size != 23)
			failmsg("bad stroct size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "%023llo", val));
		break;
	default:
		failmsg("unknown binary format", "format=%llu", bf);
	}
}

bool copyout(char* addr, uint64 size, uint64* res)
{
	return NONFAILING(
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
	    });
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
	val += pid_stride * procid;
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
	return *input_pos;
}

#if SYZ_EXECUTOR_USES_SHMEM
uint32* write_output(uint32 v)
{
	if (output_pos < output_data || (char*)output_pos >= (char*)output_data + kMaxOutput)
		failmsg("output overflow", "pos=%p region=[%p:%p]",
			output_pos, output_data, (char*)output_data + kMaxOutput);
	*output_pos = v;
	return output_pos++;
}

uint32* write_output_64(uint64 v)
{
	if (output_pos < output_data || (char*)(output_pos + 1) >= (char*)output_data + kMaxOutput)
		failmsg("output overflow", "pos=%p region=[%p:%p]",
			output_pos, output_data, (char*)output_data + kMaxOutput);
	*(uint64*)output_pos = v;
	output_pos += 2;
	return output_pos;
}

void write_completed(uint32 completed)
{
	__atomic_store_n(output_data, completed, __ATOMIC_RELEASE);
}
#endif

#if SYZ_EXECUTOR_USES_SHMEM
void kcov_comparison_t::write()
{
	if (type > (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK))
		failmsg("invalid kcov comp type", "type=%llx", type);

	// Write order: type arg1 arg2 pc.
	write_output((uint32)type);

	// KCOV converts all arguments of size x first to uintx_t and then to
	// uint64. We want to properly extend signed values, e.g we want
	// int8 c = 0xfe to be represented as 0xfffffffffffffffe.
	// Note that uint8 c = 0xfe will be represented the same way.
	// This is ok because during hints processing we will anyways try
	// the value 0x00000000000000fe.
	switch (type & KCOV_CMP_SIZE_MASK) {
	case KCOV_CMP_SIZE1:
		arg1 = (uint64)(long long)(signed char)arg1;
		arg2 = (uint64)(long long)(signed char)arg2;
		break;
	case KCOV_CMP_SIZE2:
		arg1 = (uint64)(long long)(short)arg1;
		arg2 = (uint64)(long long)(short)arg2;
		break;
	case KCOV_CMP_SIZE4:
		arg1 = (uint64)(long long)(int)arg1;
		arg2 = (uint64)(long long)(int)arg2;
		break;
	}
	bool is_size_8 = (type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8;
	if (!is_size_8) {
		write_output((uint32)arg1);
		write_output((uint32)arg2);
	} else {
		write_output_64(arg1);
		write_output_64(arg2);
	}
}

bool kcov_comparison_t::ignore() const
{
	// Comparisons with 0 are not interesting, fuzzer should be able to guess 0's without help.
	if (arg1 == 0 && (arg2 == 0 || (type & KCOV_CMP_CONST)))
		return true;
	if ((type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8) {
		// This can be a pointer (assuming 64-bit kernel).
		// First of all, we want avert fuzzer from our output region.
		// Without this fuzzer manages to discover and corrupt it.
		uint64 out_start = (uint64)output_data;
		uint64 out_end = out_start + kMaxOutput;
		if (arg1 >= out_start && arg1 <= out_end)
			return true;
		if (arg2 >= out_start && arg2 <= out_end)
			return true;
#if defined(GOOS_linux)
		// Filter out kernel physical memory addresses.
		// These are internal kernel comparisons and should not be interesting.
		// The range covers first 1TB of physical mapping.
		uint64 kmem_start = (uint64)0xffff880000000000ull;
		uint64 kmem_end = (uint64)0xffff890000000000ull;
		bool kptr1 = arg1 >= kmem_start && arg1 <= kmem_end;
		bool kptr2 = arg2 >= kmem_start && arg2 <= kmem_end;
		if (kptr1 && kptr2)
			return true;
		if (kptr1 && arg2 == 0)
			return true;
		if (kptr2 && arg1 == 0)
			return true;
#endif
	}
	return !coverage_filter(pc);
}

bool kcov_comparison_t::operator==(const struct kcov_comparison_t& other) const
{
	// We don't check for PC equality now, because it is not used.
	return type == other.type && arg1 == other.arg1 && arg2 == other.arg2;
}

bool kcov_comparison_t::operator<(const struct kcov_comparison_t& other) const
{
	if (type != other.type)
		return type < other.type;
	if (arg1 != other.arg1)
		return arg1 < other.arg1;
	// We don't check for PC equality now, because it is not used.
	return arg2 < other.arg2;
}
#endif

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

void setup_features(char** enable, int n)
{
	// This does any one-time setup for the requested features on the machine.
	// Note: this can be called multiple times and must be idempotent.
	flag_debug = true;
#if SYZ_HAVE_FEATURES
	setup_sysctl();
#endif
	for (int i = 0; i < n; i++) {
		bool found = false;
#if SYZ_HAVE_FEATURES
		for (unsigned f = 0; f < sizeof(features) / sizeof(features[0]); f++) {
			if (strcmp(enable[i], features[f].name) == 0) {
				features[f].setup();
				found = true;
				break;
			}
		}
#endif
		if (!found)
			failmsg("setup features: unknown feature", "feature=%s", enable[i]);
	}
}

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
