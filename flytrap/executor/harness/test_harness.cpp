#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <getopt.h>
#include <cerrno>
#include <iostream>
#include <stdlib.h>
#include <sys/wait.h>
#include <iostream>
#include <fstream>
#include <assert.h>
#include <sys/ioctl.h>
#include <string>
#include <thread> 
#include <sys/sendfile.h>
#include <chrono>

// #include "tester.h"
#include "Tester.h"
#include "AceTester.h"
// #include "SyzkallerTester.h"

using std::string;
using std::cout;
using std::endl;
using std::ofstream;
using std::cerr;
using std::stoull;
using std::stoi;
using std::chrono::steady_clock;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::microseconds;
using std::chrono::time_point;
using fs_testing::Tester;
using fs_testing::AceTester;
// using fs_testing::SyzkallerTester;

#define OPTSTRING "a:s:b:r:p:d:q:u:m:hvk:tcf:Do:M:n:A:"

// constants to help copy file system images around
#define ZERO1 "dd if=/dev/zero of="
#define ZERO2 " status=noxfer > /dev/null 2>&1"
#define BASE1 "dd if="
#define BASE2 " of="
#define BASE3 " bs=64M status=noxfer > /dev/null 2>&1"
#define REPLAY1 "dd if="
#define REPLAY2 " of="
#define REPLAY3 "/code/replay/nova_replay.img bs=64M status=noxfer > /dev/null 2>&1"

#define IMG1 "sudo dd if=/dev/zero of="
#define IMG2 "/code/replay/nova_replay.img bs=128M count=1 status=noxfer > /dev/null 2>&1"

// default values; assumes we are using 128MB PM devices starting at 4GB. Users can change 
// these values via command line
// TODO: we may be able to get these values dynamically from NOVA or the PM device
unsigned long pm_start = 0x100000000;
unsigned long pm_size =  0x7ffffff;
unsigned long replay_pm_start = 0x108000000; // TODO: make this command line arg or get it dynamically

// NOTE: path_to_base_img is relative to the source directory of the nova-tester repo
string path_to_base_img = "code/replay/base.img";
string pm_device = "/dev/pmem0";
string replay_device_path = "/dev/pmem1";
string mount_point = "/mnt/pmem";
string replay_mount_point = "/mnt/pmem_replay";
string kernel = "../linux-5.1/vmlinux";
string fs = "NOVA";
string testerType = "";
int max_k = 2;

static constexpr char kChangePath[] = "run_changes";

int set_up_imgs(string pm_device, string path_to_base_img, bool verbose);

static const option long_options[] = {
    {"pm-start", required_argument, NULL, 'a'},
    {"pm-size", required_argument, NULL, 's'},
    // {"base-path", required_argument, NULL, 'b'},
    {"device-path", required_argument, NULL, 'd'},
    {"replay-device-path", required_argument, NULL, 'r'},
    {"replay-mount-point", required_argument, NULL, 'p'},
    {"mount-point", required_argument, NULL, 'm'},
    {"verbose", no_argument, NULL, 'v'},
    {"kernel", required_argument, NULL, 'k'},
    {"make-trace", no_argument, NULL, 't'},
    {"tester", required_argument, NULL, 'q'},
    {"reorder", no_argument, NULL, 'c'},
    {"fs-type", required_argument, NULL, 'f'},
    {"check-data", no_argument, NULL, 'D'},
    {"mount-opts", required_argument, NULL, 'o'},
    {"mod-addr", required_argument, NULL, 'M'}, // address of dynamically loaded kernel module for the file system. can be obtained with sudo cat /proc/modules
    {"num-threads", required_argument, NULL, 'n'},
    {"test-file-path", required_argument, NULL, 't'},
    {"max-k", required_argument, NULL, 'A'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0},
};

int main(int argc, char* argv[]) {
    int option_index = 0;
    int ret, fd;
    string command;
    string test_file_path = "";
    bool verbose = false;
    bool reorder = false;
    int change_fd;
    pid_t child;
    pid_t waitres = 0;
    pid_t status = -1;
    bool make_trace = false;
    bool check_data = false;
    string mount_opts = "";
    int num_threads = 1; // higher value + test set up for multithreading will test concurrent operations 
    unsigned long long mod_addr = 0;
    bool coverage = false;
    milliseconds elapsed;

    // updated if any of the tests didn't pass so we can keep track in pmtester.py
    int passed = 0;

    time_point<steady_clock> setup_start = steady_clock::now();

    opterr = 0;
    // parse command line arguments 
    for (int c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index); 
         c != -1; 
         c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index) ) {
        switch (c) {
            case 'a':
                // TODO: let users give this in terms of KMG
                pm_start = strtol(optarg, NULL, 16);
                break;
            case 's':
                // TODO: let users give this in terms of KMG
                pm_size = strtol(optarg, NULL, 16);
                break;
            case 'M':
                mod_addr = stoull(optarg, NULL, 16);
            case 'u':
                printf("COVER\n");
                coverage = true;
                break;
            case 'b':
                path_to_base_img = string(optarg);
                break;
            case 'd':
                pm_device = string(optarg);
                break;
            case 'm':
                mount_point = string(optarg);
                break;
            case 'r':
                replay_device_path = string(optarg);
                break;
            case 'p':
                replay_mount_point = string(optarg);
                break;
            case 'v':
                verbose = true;
                break;
            case 'q':
                testerType = string(optarg);
                break;
            case 'k':
                kernel = string(optarg);
                break;
            case 't':
                make_trace = true;
                break;
            case 'c':
                reorder = true;
                break;
            case 'f':
                fs = string(optarg);
                break;
            case 'D':
                check_data = true;
                break;
            case 'o':
                mount_opts = string(optarg);
                break;
            case 'n':
                num_threads = stoi(optarg);
                break;
            case 'A':
                // TODO: there should be a way to indicate that you want to check EVERYTHING
                max_k = stoi(optarg);
                break;
            case 'h':
                printf("print help\n");
                return 0;
            // default:
            //     return -1;
        }
        opterr = 0;
    }

    // // TODO: make this not case sensitive
    // if (fs != "NOVA" && fs != "pmfs") {
    //     cerr << "Unrecognized file system. Please specify NOVA or pmfs (case sensitive)" << endl;
    // }

    // TODO: check that pm_device and replay_device_path are actually DAX devices that NOVA can be mounted on

    if (testerType == "syz") {
        assert(0 && "syzkaller tester is not supported right now");
    }

    string fs_type;
    if (fs == "NOVA") {
        fs_type = "nova";
    } else {
        fs_type = fs;
    }
    command = "rmmod logger_" + fs_type;
    system(command.c_str());
    command = "rmmod " + fs_type + " -f";
    system(command.c_str());
    // TODO: don't rely on hardcoded absolute paths
    command = "insmod /root/tmpdir/linux-5.1/fs/" + fs_type + "/" + fs_type + ".ko";
    int r = system(command.c_str());
	if (r < 0) {
		cout << "failed to load fs module" << endl;
        return r;
	}
    // r = system("insmod /root/syzkallerBinaries/linux_amd64/loggers/logger-nova.ko");
    // command = "insmod /root/syzkallerBinaries/linux_amd64/loggers/logger-" + fs_type + ".ko";
    command = "insmod /root/tmpdir/syzkallerBinaries/linux_amd64/loggers/logger-" + fs_type + ".ko";
    r = system(command.c_str());
	if (r < 0) {
		cout << "failed to load logger module" << endl;
        return r;
	}

    const unsigned int test_case_idx = optind;
    test_file_path = argv[test_case_idx];
    if (test_file_path.empty()) {
        cerr << "Please give an .so test case to load" << endl;
        return -1;
    }
    // logfile stuff is copied directly from CrashMonkey
    // Get the name of the test being run.
    int begin = test_file_path.rfind('/');
    // Remove everything before the last /.
    string test_name = test_file_path.substr(begin + 1);
    // Remove the extension
    if (test_name.find("\\.so") != std::string::npos) {
      test_name = test_name.substr(0, test_name.length() - 3);
      std::cout << "found!" << '\n';
    }
    // Get the date and time stamp and format.
    time_t now = time(0);
    char time_st[18];
    strftime(time_st, sizeof(time_st), "%Y%m%d_%H%M%S", localtime(&now));
    // TODO: save this somewhere else
    string s = "/root/tmpdir/logs/workloads/" + string(time_st) + "-" + test_name + ".log";
    ofstream logfile(s);

    // if we are testing ext4-dax, need to provide the -o dax mount option
    // TODO: what happens if the user provides the -o dax option (or a version of it)?
    // should probably check to see if they provided it
    if (fs == "ext4") {
        mount_opts += ",dax";
        // right now, we will just use ACE tests to test ext4 dax. syzkaller doesn't have 
        // the proper fsync/sync/fdatasync usage built in
        if (testerType == "syz") {
            cout << "syzkaller tester does not currently support EXT4-DAX" << endl;
            logfile << "syzkaller tester does not currently support EXT4-DAX" << endl;
            logfile.close();
            return -1;
        }
        // similarly, since ext4 dax is not synchronous like the other systems we test,
        // we can't do brute force testing
        if (reorder) {
            cout << "Brute-force testing is not supported for EXT4-DAX" << endl;
            logfile << "Brute-force testing is not supported for EXT4-DAX" << endl;
            logfile.close();
            return -1;
        }
    }

    logfile << "# of CPUs: " << std::thread::hardware_concurrency() << endl;
    logfile << "Mount opts: " << mount_opts << endl;

    // TODO: write any kind of error to the logfile (perror, etc)

    int checkpoint = 0;
    bool last_checkpoint = false;

    /*
     * Phase 1: get a profile of the workload. We do not do any logging here 
     * because this is JUST to get a profile. We also set up the tester object
     * that we will use for the rest of this test here. Profiling is only concerned
     * with system call activity so we don't need to use the base image here.
     */
    

    Tester* tester;
    logfile << "TEST TYPE: " << testerType << endl;
    // if (testerType == "syz") {
    //   logfile << "CALLING SYZKALLER TESTER" << endl;
    //   tester = new SyzkallerTester(pm_device, replay_device_path, mount_point, replay_mount_point,
    //                                pm_start, pm_size, kernel, fs, check_data, mount_opts, mod_addr,
    //                                num_threads, coverage, replay_pm_start);
    // } else {
      tester = new AceTester(pm_device, replay_device_path, mount_point, replay_mount_point,
                             pm_start, pm_size, kernel, fs, check_data, mount_opts, mod_addr,
                             num_threads, coverage, replay_pm_start, max_k);
    // }
    tester->set_test_name(test_name); // TODO: include sequence length?


    ret = tester->test_load_class(test_file_path.c_str());
    if (ret != 0) {
        perror("test_load_class");
        logfile << "Unable to load test class" << endl;
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    tester->test_init_values(mount_point, pm_size, num_threads);

    time_point<steady_clock> setup_end = steady_clock::now();
    elapsed = duration_cast<milliseconds>(setup_end - setup_start);
    logfile << "time to set up: " << elapsed.count() << endl;
    logfile << "----------------------------" << endl;

    time_point<steady_clock> profile_start = steady_clock::now();

    fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        logfile << "Unable to open IOCTL device; is logger module loaded?" << endl;
        tester->cleanup(logfile);
        logfile.close();
        return fd;
    }
    // make sure logging is turned off
    // TODO: this may not be necessary, but probably a good idea to make sure we don't 
    // try to add to the log while it's being freed
    ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        logfile << "Error turning on logging" << endl;
        close(fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }
    // free the log now to ensure any remaining data from the last test is cleaned up
    ret = ioctl(fd, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        logfile << "Error freeing log via IOCTL" << endl;
        close(fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    // make sure we record writes for the main PM devices
    ret = ioctl(fd, LOGGER_SET_PM_START, pm_start);
    if (ret < 0) {
        perror("ioctl");
        logfile << "Error setting PM address" << endl;
        close(fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }


    // now turn logging on for the test
    ret = ioctl(fd, LOGGER_LOG_ON, NULL);
    if (ret < 0) {
        perror("ioctl");
        logfile << "Error turning on logging" << endl;
        close(fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    close(fd); // TODO: do we have to close it here? Maybe not, but do this for now to avoid issues with child process writing checkpoints

    // mount the FS, making sure to create a new one since we haven't copied anything in
    ret = tester->mount_fs(true);
    if (ret != 0) {
        perror("mount_fs");
        logfile << "Unable to mount file system for profiling, error code" << ret << endl;
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    // fork a process to run the entire workload
    child = fork();
    if (child < 0) {
        perror("fork");
        logfile << "Error forking child process, error code" << child << endl;
        tester->cleanup(logfile);
        logfile.close();
        return child;
    }
    // parent process
    else if (child != 0) {
        while (waitres == 0) {
            waitres = waitpid(child, &status, WNOHANG);
        }
        // if the child didn't exit normally
        if (WIFEXITED(status) == 0) {
            printf("Error terminating test_run process, status %d\n", status);
            logfile << "Child process exited with error " << WEXITSTATUS(status) << endl;
            tester->cleanup(logfile);
            logfile.close();
            return 1;
        }
        else {
            // the child should run the process in its entirety so the return value 
            // should always be 0, but check just in case
            if (WEXITSTATUS(status) != 0) {
                // printf("Something weird happened! The child returned %d during profiling", status);
                printf("Child process terminated with status %d\n", status);
                logfile << "Child process exited with error " << status << endl;
                tester->cleanup(logfile);
                logfile.close();
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
            logfile << "Test workload returned " << change_fd << endl;
            perror("open");
            printf("failed to open change fd\n");
            return change_fd;
        }
        ret = tester->test_run(change_fd, checkpoint, logfile);
        close (change_fd);
        return ret;
    }

    // unmount the file system
    ret = tester->unmount_fs();
    if (ret != 0) {
        perror("unmount_fs");
        logfile << "Error unmounting file system, error code " << ret << endl;
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    time_point<steady_clock> mods_start = steady_clock::now();

    // load profile into tester->object BEFORE running tests so we only have to do it once
    change_fd = open(kChangePath, O_RDONLY);
    if (change_fd < 0) {
        perror("open");
        logfile << "Error opening profile file, error code " << change_fd << endl;
        tester->cleanup(logfile);
        logfile.close();
        return change_fd;
    }

    ret = lseek(change_fd, 0, SEEK_SET);
    if (ret < 0) {
        perror("lseek");
        logfile << "Error seeking in profile file, error code " << ret << endl;
        close(change_fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    ret = tester->GetChangeData(change_fd);
    if (ret != 0) {
        logfile << "Error getting workload profile, error code " << ret << endl;
        close(change_fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    time_point<steady_clock> mods_end = steady_clock::now();
    elapsed = duration_cast<milliseconds>(mods_end - mods_start);
    logfile << "time to read disk mods " << elapsed.count() << endl;
    logfile << "----------------------------" << endl;

    // now that we have profiled, we can create oracle files for files that had data writes
    // only do this if the check_data option is set; if it's not, we aren't checking for data 
    // atomicity, so there's no reason to create oracles
    // TODO: remove this
    if (check_data) {
        ret = tester->create_oracle_files();
        if (ret < 0) {
            logfile << "Error creating oracle files" << endl;
            close(change_fd);
            tester->cleanup(logfile);
            logfile.close();
            return ret;
        }
    }

    if (verbose) {
        printf("Running replay and checking for bugs\n");
    }

    // before running replay, check that no kprobes were missed.
    // if they were, fail the test
    // TODO: instead of just failing, we could try running the test again some set number of times,
    // since it's probably a temporary problem causing the kprobes to be missed.

    fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        logfile << "Unable to open IOCTL device; is logger module loaded?" << endl;
        tester->cleanup(logfile);
        logfile.close();
        return fd;
    }

    ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        logfile << "Error turning on logging" << endl;
        close(fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    ret = ioctl(fd, LOGGER_CHECK_MISSED, NULL);
    if (ret < 0) {
        cout << "At least one kprobe was missed during testing; results are unreliable, so test is failed by default\n" << endl;
        logfile << "At least one kprobe was missed during testing; results are unreliable, so test is failed by default\n" << endl;
        tester->cleanup(logfile);
        logfile.close();
        return 2; // indicates that we failed specifically due to kprobe issue so the python wrapper can handle it
    }

    // now that we'll be replaying, set the PM start address to the replay device
    ret = ioctl(fd, LOGGER_SET_PM_START, replay_pm_start);
        if (ret < 0) {
        perror("ioctl");
        logfile << "Error setting PM address" << endl;
        close(fd);
        return ret;
    }

    close(fd);

    logfile << "running tester.replay" << endl;
    // TODO: could we speed things up later by replaying directly onto a PM device?

    time_point<steady_clock> replay_start = steady_clock::now();

    ret = tester->replay(logfile, checkpoint, test_name, make_trace, reorder);
    // for (auto const &x : tester->sys2writes) {
	// logfile << "SYSCALL: " << x.first << " ";
	// for (auto const &i : tester->sys2writes[x.first]) {
	// 	logfile << i << ",";
	// }
	// logfile << "\n";
    // }
    // ret = tester->replay(checkpoint, test_name, make_trace);
    if (ret != 0) {
        perror("replay");
        logfile << "Error replaying writes, error code " << ret << endl;
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }

    time_point<steady_clock> replay_end = steady_clock::now();
    elapsed = duration_cast<milliseconds>(replay_end - replay_start);
    logfile << "time to build full replay " << elapsed.count() << endl;
    logfile << "----------------------------" << endl;

    time_point<steady_clock> free_log_start = steady_clock::now();

    fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        logfile << "Unable to open IOCTL device; is logger module loaded?" << endl;
        tester->cleanup(logfile);
        logfile.close();
        return fd;
    }
    ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        logfile << "Error turning on logging" << endl;
        close(fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }
    ret = ioctl(fd, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        logfile << "Error freeing log via IOCTL" << endl;
        close(fd);
        tester->cleanup(logfile);
        logfile.close();
        return ret;
    }
    close(fd);

    time_point<steady_clock> free_log_end = steady_clock::now();

    elapsed = duration_cast<milliseconds>(free_log_end - free_log_start);
    logfile << "time to free log " << elapsed.count() << endl;
    logfile << "----------------------------" << endl;

    time_point<steady_clock> test_start = steady_clock::now();

    bool retval;
    retval = tester->test_replay(logfile, checkpoint, test_name, make_trace, reorder);
    if (retval == false) {
        cout << "Test failed" << endl;
        passed = 1;
    }
    time_point<steady_clock> test_end = steady_clock::now();
    elapsed = duration_cast<milliseconds>(test_end - test_start);
    logfile << "time to run test " << elapsed.count() << endl;
    logfile << "----------------------------" << endl;

    if (verbose) {
        printf("Cleaning up\n");
    }

    tester->cleanup(logfile);
    tester->test_unload_class();
    logfile.close();
    // TODO: anything else to clean up?

    return passed;
}

int set_up_imgs(string pm_device, string path_to_base_img, bool verbose) {
    char cwd[128];
    char* ret_ptr;
    int ret;
    string command;

    ret_ptr = getcwd(cwd, sizeof(cwd));
    if (ret_ptr == NULL) {
        perror("getcwd");
        return ret;
    }

    if (verbose) {
       printf("Setting up PM device and file system images\n");
    }

    // // in past testing scripts, we've zeroed the PM device and then 
    // // used dd to copy the base image onto it; use the same approach
    // command = ZERO1 + pm_device + ZERO2;
    // ret = system(command.c_str());
    // if (ret < 0) {
    //     perror("system (dd zero)");
    //     return ret;
    // }

    remove("/tmp/nova_replay.img");

    int fd = open("/tmp/nova_replay.img", O_RDWR | O_CREAT);
    if (fd < 0) {
        perror("open");
        return fd;
    }
    
    ret = ftruncate(fd, pm_size);
    if (ret < 0) {
        printf("truncate failed\n");
        perror("truncate");
        return ret;
    }

    close(fd);

    return 0;

}
