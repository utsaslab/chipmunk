#include <string>
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
#include <map>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <ctime>
#include <cassert>
#include <chrono>
#include <thread>
#include <sys/sendfile.h>

#include "AceTester.h"
#include "DiskState.h"

#define TEST_CLASS_FACTORY        "test_case_get_instance"
#define TEST_CLASS_DEFACTORY      "test_case_delete_instance"

namespace fs_testing {

using namespace std;
using fs_testing::tests::test_create_t;
using fs_testing::tests::test_destroy_t;
using fs_testing::utils::DiskMod;

AceTester::AceTester(string p, string r, string m, string rm, unsigned long start, unsigned long size, string k, string f, bool d, string o, unsigned long long mod, int threads, bool coverage, unsigned long replay_pm, int maxk) {
    device_path = p;
    replay_device_path = r;
    device_mount_point = m;
    replay_mount_point = rm;
    pm_start = start;
    pm_size = size;
    kernel = k;
    fs = f;
    check_data = d;
    vector<struct write_op*> q;
    vector<FILE*> v1;
    fptr_map.push_back(v1);
    mount_opts = o;
    mod_addr = mod;
    num_threads = threads;
    sync_index = 0;
    head = 0;
    tail = 0;
    replay_pm_start = replay_pm;
    base_replay_path = "/tmp/base_replay.img";
    // TODO: save this somewhere else
    diff_path = "/root/tmpdir/logs/diffs/";
    crashStateLogOut = std::ofstream("/root/tmpdir/crashStatesLog", std::ios_base::app);
    oracle_state.disk_path = p;
    oracle_state.mount_point = m;
    oracle_state.replay_mount_point = rm;
    tester_type = "ace";

    max_k = maxk;
}

int AceTester::cleanup(ofstream& log) {
    int ret, fd;
    struct write_op *temp;
    // TODO: can you clean some of the sleeps out of here?

    for (int i = 0; i < undo_log.size(); i++) {
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
    // free_queues();
    free_queue(write_queue);

    fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        perror("Unable to open IOCTL device");
        return fd;
    }
    ret = ioctl(fd, LOGGER_LOG_OFF, NULL);
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

    // you need to be able to handle the case where it isn't mounted
    // sleep(1);
    ret = umount(device_mount_point.c_str());
    if (ret != 0) {
        if (errno != EINVAL) {
            perror("unmount");
            return ret;
        }
    }

    // also try to unmount the crash replay device
    // sleep(1);
    ret = umount(replay_mount_point.c_str());
    if (ret != 0) {
        if (errno != EINVAL) {
            perror("unmount");
            return ret;
        }
    }

    // remove("code/replay/base_replay.img");
    // truncate("code/replay/base_replay.img", 0);
    truncate(base_replay_path.c_str(), 0);

    test_unload_class();

    return 0;
}

int AceTester::test_init_values(string mount_dir, long filesys_size, int threads) {
  return test_loader.get_instance()->init_values(mount_dir, filesys_size, threads);
}

int AceTester::test_load_class(const char* path) {
  return test_loader.load_class<test_create_t *>(path, TEST_CLASS_FACTORY,
      TEST_CLASS_DEFACTORY);
}

void AceTester::test_unload_class() {
    test_loader.unload_class<test_destroy_t *>();
}

int AceTester::test_run(const int change_fd, const int checkpoint,  std::ofstream &log) {
  return test_loader.get_instance()->Run(change_fd, checkpoint);
}

// int AceTester::GetChangeData(const int fd) {
//   // Need to read a 64-bit value, switch it to big endian to figure out how much
//   // we need to read, read that new data amount, and add it all to a buffer.
//   while (true) {
//     // Get the next DiskMod size.
//     uint64_t buf;
//     const int read_res = read(fd, (void *) &buf, sizeof(uint64_t));
//     if (read_res < 0) {
//       return read_res;
//     } else if (read_res == 0) {
//       // No more data to read.
//       break;
//     }

//     uint64_t next_chunk_size = be64toh(buf);

//     // Read the next DiskMod.
//     shared_ptr<char> data(new char[next_chunk_size], [](char *c) {delete[] c;});
//     memcpy(data.get(), (void *) &buf, sizeof(uint64_t));
//     unsigned long long int read_data = sizeof(uint64_t);
//     while (read_data < next_chunk_size) {
//       const int res = read(fd, data.get() + read_data,
//           next_chunk_size - read_data);
//       if (res <= 0) {
//         // We shouldn't find a size for a DiskMod without the rest of the
//         // DiskMod.
//         return -1;
//       }
//       read_data += res;
//     }

//     DiskMod mod;
//     const int res = DiskMod::Deserialize(data, mod);
//     if (res < 0) {
//       return res;
//     }

//     if (mod.mod_type == DiskMod::kCheckpointMod) {
//       // We found a checkpoint, so switch to a new set of DiskMods.
//       mods_.push_back(vector<DiskMod>());
//     } else {
//       if (mods_.empty()) {
//         // We're just starting, so give us a place to put the mods.
//         mods_.push_back(vector<DiskMod>());
//       }
//       // Just append this DiskMod to the end of the last set of DiskMods.
//       mods_.back().push_back(mod);
//     }
//   }

//   return SUCCESS;
// }

// TODO: remove these, they don't do anything
bool AceTester::test_replay(ofstream& log, int checkpoint, string test_name, bool make_trace, bool reorder) {
    int ret = true;
    // ofstream file;
    // int r;
    // string command;
    // int old_combo_size = combos.size();
    // vector<vector<struct write_op*> > new_combos;
    // map<unsigned long long, string> addr2line_cache;

    // first test the original file system image
    // if (!test_replay_internal(log, checkpoint, "code/replay/nova_replay.img")) {
    if (!test_replay_internal(log, checkpoint, "/tmp/nova_replay.img")) {
        ret = false;
        goto out;
    } 

out:
    // free any the remaining writes
    free_queue(write_queue);

    return ret;
}

bool AceTester::test_replay_internal(ofstream& log, int checkpoint, string replay_img_path) {
    // string command;
    int ret;
    pid_t child;
    int waitres = 0;
    pid_t status = -1;
    bool retval = true;

    // returns false if the test fails or if something goes wrong with 
    // one of the other system calls
    // TODO: distinguish between test failure, and failure of a system call in this code

    // retval = run_check(test_name, replay_device_path, replay_mount_point, replay_img_path, log, checkpoint, true);

    return retval;
}


}