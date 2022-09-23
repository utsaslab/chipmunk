#include <string>
#include <stdarg.h>
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <fstream>
#include <string.h>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <map>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <ctime>
#include <cassert>
#include <chrono>
#include <thread>

#include "Tester.h"
#include "SyzTester.h"

namespace fs_testing {

using namespace std;
using std::chrono::steady_clock;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::microseconds;
using std::chrono::time_point;
using fs_testing::utils::DiskMod;

SyzTester::SyzTester(string p, string r, string m, string rm, unsigned long start, unsigned long size, string f, bool d, string o, 
unsigned long long mod, int threads, bool coverage, unsigned long input_data, uint32_t* output_data, 
bool flag_collect_cover, bool flag_dedup_cover, thread_t* th, bool mountCov, unsigned long replay_pm, string instanceId, int maxk)
    {
    device_path = p;
    replay_device_path = r;
    device_mount_point = m;
    replay_mount_point = rm;
    pm_start = start;
    pm_size = size;
    fs = f;
    srand (time(NULL));
    check_data = d;
    // vector<struct write_op*> q;
    // write_queues.push_back(q); // the first queue in the list is the primary queue
    vector<FILE*> v1;
    fptr_map.push_back(v1);
    mount_opts = o;
    mod_addr = mod;
    num_threads = threads;
    captureCoverage = coverage;
    sync_index = 0;
    syscalls.resize(0);
    head = 0;
    tail = 0;
    replay_pm_start = replay_pm;
    this->input_data = input_data;
    this->output_data = output_data;
    this->th = th;
    collect_cover = flag_collect_cover;
    dedup_cover = flag_dedup_cover;
    this->collect_mount_cover = mountCov;
    this->instanceId = instanceId;
    this->setup();
    // string log = "/root/tmpdir/nova-tester/" + instanceId +  "/logs/workloads/syztester";
    // TODO: make sure this works with execprog
    string log = "/roor/tmpdir/logs/workloads/syztester";
    logfile.open(log);
    base_replay_path = "/base_replay.img";
    // TODO: make sure this works with execprog
    diff_path = "/root/tmpdir/logs/diffs/";
    crashStateLogOut = std::ofstream("/root/tmpdir/crashStatesLog", std::ios_base::app);
    oracle_state.disk_path = p;
    oracle_state.mount_point = m;
    oracle_state.replay_mount_point = rm;
    tester_type = "syz";
    max_k = maxk; // TODO: make this a command line argument
}

int SyzTester::resetLogger() {
    int fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device in reset");
        return fd;
    }
    int ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        close(fd);
        return ret;
    }
    ret = ioctl(fd, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        close(fd);
        return ret;
    }
    close(fd);
    return ret;
}

void SyzTester::setup() {
    // string rootDir = "/root/tmpdir/nova-tester/" + this->instanceId + "/";
    string rootDir = "/root/tmpdir/";
    string workloads = rootDir + "logs/workloads";
    string diffs = rootDir + "logs/diffs";
    string baseImg = rootDir + "base.img";
    // see if workloads dir exists
    DIR *workloadDir = opendir(workloads.c_str());
    if (workloadDir) {
        closedir(workloadDir);
    } else {
        string makeWorkload = "mkdir -p " + workloads;
        // debug("make workload: %s\n", makeWorkload.c_str());
        string makeDiffs = "mkdir -p " + diffs;
        // string copyBaseImg = "cp /root/tmpdir/nova-tester/code/replay/base.img /root/tmpdir/nova-tester/" + this->instanceId + "/base_replay.img";

        system(makeWorkload.c_str());
        system(makeDiffs.c_str());
        // system(copyBaseImg.c_str());
    }
}


int SyzTester::cleanup(ofstream& log) {
    int ret, fd;
    microseconds elapsed;
    struct write_op *temp;

    // sleep(1); // give some time for previous work using the logger to finish up

    for (unsigned int i = 0; i < undo_log.size(); i++) {
        free(undo_log[i]->data);
        free(undo_log[i]->metadata);
        free(undo_log[i]);
    }
    while (head != NULL) {
        if (head->next != NULL) {
            temp = head->next;
        } else {
            temp = NULL;
        }
        free(head->metadata);
        if (head->data) {
            free(head->data);
        }
        free(head);
        head = temp;
    }

    free_modified_writes();
    close_fptrs();
    logfile.close();
    // free_queues();
    free_queue(write_queue);

    time_point<steady_clock> free_log_start = steady_clock::now();
    fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        log.close();
        crashStateLogOut.close();
        return fd;
    }
    ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        close(fd);
        log.close();
        crashStateLogOut.close();
        return ret;
    }
    ret = ioctl(fd, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        close(fd);
        log.close();
        crashStateLogOut.close();
        return ret;
    }
    close(fd);
    time_point<steady_clock> free_log_end = steady_clock::now();
    elapsed = duration_cast<microseconds>(free_log_end - free_log_start);
    log << "time to free logs " << elapsed.count() << endl;
    log << "----------------------------" << endl;

    // you need to be able to handle the case where it isn't mounted
    // sleep(1);
    ret = umount(device_mount_point.c_str());
    if (ret != 0) {
        if (errno != EINVAL) {
            perror("unmount");
            log.close();
            crashStateLogOut.close();
            return ret;
        }
    }

    // also try to unmount the crash replay device
    // sleep(1);
    ret = umount(replay_mount_point.c_str());
    if (ret != 0) {
        if (errno != EINVAL) {
            perror("unmount");
            log.close();
            crashStateLogOut.close();
            return ret;
        }
    }

    // truncate("code/replay/base_replay.img", 0);
    truncate(base_replay_path.c_str(), 0);

    test_unload_class();
    log.close();
    crashStateLogOut.close();
    return 0;
}

void SyzTester::setOutputPos(uint32_t* output_pos) {
    this->output_pos = output_pos;
}

}