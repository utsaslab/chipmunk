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
#include <sys/syscall.h>

#include "Tester.h"
#include "DiskState.h"

namespace fs_testing {

using namespace std;
using std::chrono::steady_clock;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::time_point;
using fs_testing::utils::DiskMod;

int Tester::mount_fs(bool init) {
    int ret;
    string command;
    string opts = mount_opts;
    // make sure winefs is mounted in strict mode
    // TODO: make this an optional thing for both winefs and other fses with a strict mode
    if (fs.compare("winefs") == 0) {
        opts += ",strict";
        check_data = true;
    }
    if (init) {
        command = "dd if=/dev/zero of=" + device_path + " bs=100M > /dev/null 2>&1";
        system(command.c_str());
        if (fs == "ext4") {
            // TODO: look up and use the correct blocksize
            command = "mkfs.ext4 -b 4096 " + device_path + " > /dev/null 2>&1";
            ret = system(command.c_str());
            if (ret < 0) {
                perror("mkfs.ext4");
                return ret;
            }
            ret = mount(device_path.c_str(), device_mount_point.c_str(), fs.c_str(), 0, mount_opts.c_str());
        } else if (fs == "xfs") {
            command = "mkfs.xfs -m reflink=0 " + device_path + " > /dev/null 2>&1";
            ret = system(command.c_str());
            if (ret < 0) {
                perror("mkfs.xfs");
                return ret;
            }
            ret = mount(device_path.c_str(), device_mount_point.c_str(), fs.c_str(), 0, mount_opts.c_str());
        } else {
            opts = ",init" + opts;
            ret = mount(device_path.c_str(), device_mount_point.c_str(), fs.c_str(), 0, opts.c_str());
        }
    }
    else {
        ret = mount(device_path.c_str(), device_mount_point.c_str(), fs.c_str(), 0, mount_opts.c_str());

    }
    if (ret != 0) {
        perror("mount");
        return ret;
    }
    return 0;
}

int Tester::mount_replay() {
    int ret;
    ret = mount(replay_device_path.c_str(), replay_mount_point.c_str(), fs.c_str(), 0, mount_opts.c_str());
    if (ret != 0) {
        return ret;
    }
    return 0;
}

int Tester::unmount_fs() {
    int ret;
    ret = umount(device_mount_point.c_str());
    if (ret != 0) {
        // sleep for a second to give it a chance to finish up, then try again
        sleep(2);
        ret = umount(device_mount_point.c_str());
        if (ret != 0) {
            perror("umount");
            return ret;
        }
    }    
    return 0;
}


void Tester::set_test_name(string n) {
    test_name = n;
}

void Tester::free_modified_writes() {
    for (unsigned int i = 0; i < modified_writes_list.size(); i++) {
        free(modified_writes_list[i]->metadata);
        free(modified_writes_list[i]);
    }
    modified_writes_list.clear();
}

void Tester::close_fptrs() {
    for (unsigned int i = 0; i < fptr_map.size(); i++) {
        for (unsigned int j = 0; j < fptr_map[0].size(); j++) {
            fclose(fptr_map[i][j]);
        }
    }
    fptr_map.clear();
}

void Tester::free_queue(vector<struct write_op*> &q) {
    for (unsigned int i = 0; i < q.size(); i++) {
        if (q[i]->data != NULL) {
            free(q[i]->data);
        }
        free(q[i]->metadata);
        free(q[i]);
    }
    q.clear();
}

int Tester::replay(ofstream& log, int checkpoint, string test_name, bool make_trace, bool reorder) {
    int fd_replay;
    int fd;
    int checkpoint_count = 0;
    ofstream trace_file;
    int ret;
    string filename;
    string replay_name = replay_device_path;

    remove(base_replay_path.c_str()); // TODO: is this necessary since we truncate it in cleanup?

    string command = "dd if=/dev/pmem1 of=/dev/zero bs=128M > /dev/null 2>&1";
    ret = system(command.c_str());
    if (ret < 0) {
        return -1;
    }
    fd_replay = open(replay_name.c_str(), O_RDWR);
    if (fd_replay < 0) {
        perror("Open replay");
        return fd_replay;
    }

    // mount the oracle file system
    ret = mount_fs(true);
    if (ret < 0) {
        cout << "failed to mount oracle fs " << strerror(errno) << endl;
        return ret;
    }

    // open up the dummy device that gives us logged writes via ioctl
    fd = open("/dev/ioctl_dummy", 0);
    if (fd < 0) {
        close(fd_replay);
        perror("open");
        unmount_fs();
        return -1;
    }
    
    if (make_trace) {
        // set up file to write traces to
        filename = "logs/replay_"+test_name+"_stacktrace";
        // delete the file if it already exists
        ret = access(filename.c_str(), F_OK);
        if (ret == 0) {
            ret = remove(filename.c_str());
            if (ret < 0) {
                perror("remove trace");
                close(fd);
                close(fd_replay);
                unmount_fs();
                return ret;
            }
        }
        trace_file.open(filename);
        if (!trace_file.is_open()) {
            perror("open");
            close(fd);
            close(fd_replay);
            unmount_fs();
            return -1;
        }
    }

    oracle_state.test_name = test_name;

    ret = get_write_log(fd, log, checkpoint, reorder);
    if (ret < 0) {
        close(fd);
        close(fd_replay);
        unmount_fs();
        return ret;
    }

    ret = ioctl(fd, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error freeing log via IOCTL" << endl;
        close(fd);
        close(fd_replay);
        unmount_fs();
        return ret;
    }
    close(fd);


    // make sure the replay base file exists
    int base_fd = open(base_replay_path.c_str(), O_RDWR | O_CREAT, 0777);
    if (base_fd < 0) {
        perror("open 7");
        close(fd_replay);
        unmount_fs();
        return fd;
    }
    ret = ftruncate(base_fd, pm_size);
    if (ret < 0) {
        perror("truncate");
        close(fd_replay);
        close(base_fd);
        unmount_fs();
        return ret;
    }
    close(base_fd);


    string diff_file_path = "/root/tmpdir/logs/diffs/diff-" + test_name;
    ofstream oracle_diff_file(diff_file_path, ofstream::out | std::ios::app);

    sfence_count = 0;
    while (head != NULL) {
        ret = process_log_entry(fd_replay, fd, checkpoint, checkpoint_count, log, test_name, trace_file, make_trace, reorder, oracle_diff_file);
        if (ret != 0) {
            error_in_oracle = true;
            break;
        }
    }

    oracle_diff_file.close();
    if (!error_in_oracle) {
        unlink(diff_file_path.c_str());
    }

    if (make_trace) {
        trace_file.close();
    }
    close(fd_replay);
    close(fd);
    // close all open files so we don't have issues unmounting the file system
    for (map<string, map<int, int> >::iterator it = path_fd_map.begin(); it != path_fd_map.end(); it++) {
        map<int, int> fds = it->second;
        for (map<int, int>::iterator it2 = fds.begin(); it2 != fds.end(); it2++) {
            close(it2->second);
        }
    }

    unmount_fs();

    return 0;
}

int Tester::get_write_log(int fd, ofstream &log, int checkpoint, bool reorder) {
    int ioctl_val = 0;
    struct write_op* new_op;
    struct write_op* last_successful_syscall_mark = nullptr;
    struct write_op* last_successful_syscall_end_mark = nullptr;
    struct write_op* last_syscall_mark = nullptr;
    int checkpoint_count = 0;
     bool combined_data_write;
    struct write_op* first_syscall_mark = NULL;

    log << "getting write log, test type " << tester_type << endl;

    while (ioctl_val == 0) {
        combined_data_write = false;
        // get write op, including the stack trace associated with the function call it recorded
        new_op = (struct write_op*)malloc(sizeof(struct write_op));
        if (new_op == NULL) {
            perror("malloc");
            return -ENOMEM;
        }
        new_op->data = NULL;
        new_op->next = NULL;
        new_op->prev = NULL;

        // allocate space for metadata
        new_op->metadata = (struct op_metadata*)malloc(sizeof(struct op_metadata));
        if (new_op->metadata == NULL) {
            perror("malloc");
            free(new_op);
            return -ENOMEM;
        }

        // get log entry metadata and put it in the pre-allocated struct
        ioctl_val = ioctl(fd, LOGGER_GET_OP, new_op->metadata);
        if (ioctl_val < 0) {
            perror ("error in LOGGER_GET_OP 1");
            return ioctl_val;
        }

        if (new_op->metadata->type == CLWB || new_op->metadata->type == NT) {
            // if this and the previous write log entries are part of the same data write,
            // combine them into one larger write to reduce the number of outstanding writes
            // when performing a larger data write
            // TODO: this will be kind of slow for large data writes that are split up into 
            // pages by the file system
            // however, we only do it once per test, so it's not a HUGE deal
            // TODO: this is VERY slow for ext4 dax - right now we just don't do it since we don't reorder those writes anyway
            if (head != NULL && new_op->metadata->likely_data && tail->metadata->likely_data &&
                new_op->metadata->dst == (tail->metadata->dst + tail->metadata->len)) {
                    // increase tail entry's length
                    // tail->metadata->len += new_op->metadata->len;
                    unsigned long long new_write_len = tail->metadata->len + new_op->metadata->len;
                    // allocate new space for it
                    void* temp_buffer = malloc(new_write_len);
                    if (temp_buffer == NULL) {
                        perror("malloc");
                        free(new_op);
                        return -ENOMEM;
                    }
                    memset(temp_buffer, 0, new_write_len);
                    // copy the tail write's data into the first part
                    memcpy(temp_buffer, tail->data, tail->metadata->len);
                    // copy the new write's data into the rest
                    ioctl_val = ioctl(fd, LOGGER_GET_DATA, (char*)temp_buffer+tail->metadata->len);
                    if (ioctl_val < 0) {
                        perror("LOGGER_GET_DATA");
                        free(temp_buffer);
                        free(new_op->metadata);
                        free(new_op);
                        return ioctl_val;
                    }
                    // now update the tail
                    tail->metadata->len = new_write_len;
                    free(tail->data);
                    tail->data = temp_buffer;
                    // we are no longer using new op so make sure that space is freed
                    free(new_op->metadata);
                    free(new_op);
                    combined_data_write = true;
            } else {
                new_op->data = malloc(new_op->metadata->len);
                if (new_op->data == NULL) {
                    perror("malloc");
                    return -ENOMEM;
                }
                memset(new_op->data, 0, new_op->metadata->len);
                ioctl_val = ioctl(fd, LOGGER_GET_DATA, new_op->data);
                if (ioctl_val < 0) {
                    perror("LOGGER_GET_DATA");
                    free(new_op->data);
                    free(new_op->metadata);
                    return ioctl_val;
                }
            }
        } else if (new_op->metadata->type == MARK_SYS) {
            if (first_syscall_mark == NULL) {
                first_syscall_mark = new_op;
            }
        } else if (new_op->metadata->type == MARK_SYS_END) {
            if (new_op->metadata->sys_ret != -1) {
                last_successful_syscall_mark = last_syscall_mark;
                last_successful_syscall_end_mark = new_op;
            } 
        } else if (new_op->metadata->type == CHECKPOINT) {
            checkpoint_count++;
        }

        if (!combined_data_write) {
            if (head == NULL) {
                head = new_op;
                tail = new_op;
            }
            else {
                tail->next = new_op;
                new_op->prev = tail;
                tail = new_op;
            }
        }

        if (checkpoint_count > 0) 
            return 1;

        // go to the next log entry
        ioctl_val = ioctl(fd, LOGGER_NEXT_OP, NULL);
        if (ioctl_val != 0) {
            // cout << "logger next op returned fail" << endl;
            cout << "Reached end of log" << endl;
            // return ioctl_val;
            break;
        }
        fflush(stdin);
    }

    // NEW: insert a mark op before the first system call mark
    if (tester_type == "syz" && first_syscall_mark != NULL) {
        log << "INSERTING MARK at system call number " << first_syscall_mark->metadata->sys << endl;
        struct write_op* mark = (struct write_op*) malloc(sizeof(struct write_op));
        if (mark == NULL) {
            perror("malloc");
            free(new_op);
            return -ENOMEM;
        }
        mark->metadata = (struct op_metadata*) malloc(sizeof(struct op_metadata));
        if (mark->metadata == NULL) {
            perror("malloc");
            free(new_op);
            return -ENOMEM;
        }
        mark->metadata->type = MARK;
        struct write_op* checkpoint = (struct write_op*) malloc(sizeof(struct write_op));
        if (checkpoint == NULL) {
            perror("malloc");
            free(new_op);
            return -ENOMEM;
        }

        if (first_syscall_mark->prev != NULL) {
            first_syscall_mark->prev->next = mark;
            mark->prev = first_syscall_mark->prev;
        } else {
            head = mark;
        }
        mark->next = first_syscall_mark;
    }

    // TODO: remove this. if the tester type is syz, we should insert more crashes?
    // Insert a checkpoint mark after the last successful syscall end mark
    if (tester_type == "syz" && 
            last_successful_syscall_mark != nullptr && 
            last_successful_syscall_end_mark != nullptr) {
        struct write_op* checkpoint = (struct write_op*) malloc(sizeof(struct write_op));
        if (checkpoint == NULL) {
            perror("malloc");
            free(new_op);
            return -ENOMEM;
        }
        checkpoint->metadata = (struct op_metadata*) malloc(sizeof(struct op_metadata));
        if (checkpoint->metadata == NULL) {
            perror("malloc");
            free(new_op);
            return -ENOMEM;
        }
        checkpoint->metadata->type = CHECKPOINT;
    
        // last_successful_syscall_mark->prev = mark;
        if (last_successful_syscall_end_mark->next != nullptr) {
            last_successful_syscall_end_mark->next->prev = checkpoint;
            checkpoint->next = last_successful_syscall_end_mark->next;
        }
        checkpoint->prev = last_successful_syscall_end_mark;
        last_successful_syscall_end_mark->next = checkpoint;
        if (last_successful_syscall_end_mark == tail) {
            tail = checkpoint;
        }
    }
    return 0;
}

int Tester::process_log_entry(int fd_replay, int fd, int checkpoint, int& checkpoint_count, 
    ofstream& log, string test_name, ofstream& trace_file, bool make_trace, bool reorder, ofstream& oracle_diff_file) {
    int ret;
    bool passed = true;
    struct write_op* new_op;
    string command;

    // dequeue the head of the local write log and process it
    new_op = head;
    if (new_op->next == NULL) {
        head = NULL;
        tail = NULL;
    }
    else {
        head = new_op->next;
    }

    // check the metadata type to determine what to do with the log entry
    switch(new_op->metadata->type) {
        case SFENCE:
            log << "SFENCE, " << new_op->metadata->pid << endl;
            // if there haven't been any writes since the last sfence,
            // we don't have to do anything
            if (unordered_write && reorder) {
                ret = make_and_check_crash_states(fd_replay, fd, checkpoint, log, test_name, trace_file, make_trace, mod_index, reorder);
                if (ret < 0) {
                    return ret;
                }
                for (size_t i = 0; i < write_queue.size(); i++) {
                    log << i << " " << std::hex << write_queue[i]->metadata->dst << ", " << std::dec;
                }
                ret = flush_entries(fd_replay, new_op, trace_file, make_trace, log, write_queue, reorder);
                free_queue(write_queue);
                for (size_t i = 0; i < write_queue.size(); i++) {
                    log << std::hex << write_queue[i]->metadata->dst << ", " << std::dec;
                }
                log << endl;
                free_modified_writes();
                unordered_write = false;
                if (!passed) {
                    return passed;
                }
            } else if (!reorder) {
                // ext4-dax and xfs-dax case: just flush entries
                ret = flush_entries(fd_replay, new_op, trace_file, make_trace, log, write_queue, reorder);
                free_queue(write_queue);
                free_modified_writes();
            }
            break;
        case CLWB:
            log << "CLWB " << std::hex << new_op->metadata->dst << std::dec << ", " << new_op->metadata->len << ", " << new_op->metadata->likely_data << ", " << new_op->metadata->pid << endl;
            if (new_op->metadata->likely_data == 1) {
                epoch_data_writes.push_back(new_op);
            }
            write_queue.push_back(new_op);
            unordered_write = true;
            break;
        case NT:
            log << "NT, " << std::hex << new_op->metadata->dst << ", " << std::dec << new_op->metadata->len << ", " << new_op->metadata->likely_data << ", " << new_op->metadata->pid << endl;
            unordered_write = true;
            write_queue.push_back(new_op);
            break;
        case CHECKPOINT:
            log << "CHECKPOINT" << ", " << new_op->metadata->pid << endl;
            checkpoint_count++;
            if (unordered_write && reorder) {
                ret = make_and_check_crash_states(fd_replay, fd, checkpoint, log, test_name, trace_file, make_trace, mod_index, reorder);
                if (ret < 0) {
                    return ret;
                }
            } else if (!reorder) {
                // in this case, we are testing an FS like ext4 dax or xfs dax with weaker crash consistency guarantees
                // and we don't want to provide full reordering - we only want to crash after sync calls
                ret = check_async_crash(test_name, log);
                if (ret < 0) {
                    return ret;
                }
            }
            return 1;
            break;
        case MARK:
            fs_mounted = true;
            log << "BEGINNING OF TESTED SYSTEM CALL" << ", " << new_op->metadata->pid << endl;
            break;
        case MARK_SYS:
            log << "MARK SYS " << std::dec << new_op->metadata->sys << ", " << new_op->metadata->pid << endl;
            struct syscall_record sr;
            sr.syscall_num = new_op->metadata->sys;
            sr.pid = new_op->metadata->pid;
            sr.finished = false;
            if (syscalls.empty()) {
                // if this is the first system call we've seen,
                // save an initial state for the root directory
                struct paths paths = {device_mount_point, ""};
                ret = oracle_state.add_file_state(paths, false, false, false, false, log, oracle_diff_file);
                if (ret < 0) {
                    log << "Failed getting oracle state" << endl;
                    return ret;
                }
            }
            syscalls.push_back(sr);
            ret = find_disk_mod(sr, log, oracle_diff_file);
            if (ret < 0) {
                // TODO: is this enough to fail?
                passed = false;
                error_in_oracle = true;
                log << "Error finding disk mod" << endl;
                cout << "Error finding disk mod" << endl;
                return ret;
            }
            break;
        case MARK_SYS_END:
            log << "MARK SYS END" << ", " << new_op->metadata->pid << ", " << new_op->metadata->sys_ret << endl;
            sync(); // make sure the crash state is synced before we test it
            // if (call_index == 7) {
            //     string command = "dd if=/dev/pmem1 of=/root/tmpdir/crash.img bs=100M";
            //     system(command.c_str());
            //     command = "dd if=/dev/pmem0 of=/root/tmpdir/oracle.img bs=100M";
            //     system(command.c_str());
            // }
            
            if (reorder) {
                string check_name = test_name + "_mod" + to_string(call_index);
                ret = check_crash_state(fd_replay, check_name, log, checkpoint, reorder, true);
                
                if (ret < 0) {
                    cout << "check crash state < 0 in mark sys end" << endl;
                    return ret;
                }
            }
            break;
    }

    // if there are still log entries, return 0 so the loop
    // in main keeps going
    return 0;
}

// TODO: refactor this and the DiskState functions so we aren't recomputing
// relative paths unnecessarily
int Tester::find_disk_mod(struct syscall_record sr, ofstream& log, ofstream& oracle_diff_file) {
    int ret, fd;
    struct stat file_stat; 
    struct paths paths, temp_paths, new_paths;
    SingleTestInfo test_info;
    bool same_file = false;

    // mod_index starts at -1, so this loop should handle things correctly
    // for the first syscall/disk mod
    // TODO: this could use refactoring
    for (unsigned int i = mod_index+1; i < mods_.size(); i++) {
        DiskMod mod = mods_[i];
        switch (sr.syscall_num) {
            case SYS_mknod:
                assert(0 && "Mknod is not supported");
                return mod_index;
            case SYS_mkdir:
                // need to look for a kCreateMod on a directory
                if (mod.mod_type == DiskMod::kCreateMod && mod.directory_mod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "mkdir " << mod.path << " at " << call_index << endl;
                        syscall_list += "mkdir,";
                        // run mkdir on the oracle 
                        ret = mkdir(mod.path.c_str(), mod.mode);
                        if (ret < 0) {
                            perror("mkdir");
                            log << "find_disk_mod error in mkdir at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                        struct stat dirstat;
                        ret = lstat(mod.path.c_str(), &dirstat);
                        if (ret < 0) {
                            perror("lstat");
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            goto out;
                        }
                        ret = oracle_state.add_file_state(paths, true, false, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            return ret;
                        }
                    }
                    mod_index = i;
                    // return 0;
                    goto done;
                }
                break;
            case SYS_open:
                if (mod.mod_type == DiskMod::kCreateMod && mod.mod_opts == DiskMod::kNoneOpt) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "creat " << mod.path << " at " << call_index << endl;
                        syscall_list += "creat,";
                        fd = open(mod.path.c_str(), mod.flags, mod.mode);
                        if (fd < 0) {
                            perror("creat");
                            log << "find_disk_mod error in creat at " << call_index << endl;
                            ret = fd;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }

                        if (path_fd_map.find(paths.relative_path) == path_fd_map.end()) {
                            map<int, int> new_fd_map;
                            new_fd_map[mod.fd] = fd;
                            path_fd_map[paths.relative_path] = new_fd_map;
                        } else {
                            path_fd_map[paths.relative_path][mod.fd] = fd;
                        }
                        ret = oracle_state.add_file_state(paths, true, false, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                        int ino = oracle_state.contents[paths.relative_path].back()->statbuf.st_ino;
                        // record the inode associated with this file descriptor
                        // so we can properly update linked files later
                        fd_ino_map[fd] = ino;
                    }
                    mod_index = i;
                    // return 0;
                    goto done;
                } else if (mod.mod_type == DiskMod::kDataMetadataMod && mod.mod_opts == DiskMod::kTruncateOpenOpt) {
                    if (mod.return_value >= 0) {
                        call_index++;
                        cout << "open truncate " << mod.path << " at " << call_index << endl;
                        syscall_list += "open trunc,";
                        fd = open(mod.path.c_str(), mod.flags, mod.mode);
                        if (fd < 0) {
                            perror("open trunc");
                            log << "find_disk_mod error in open trunc at " << call_index << endl;
                            ret = fd;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }

                        if (path_fd_map.find(paths.relative_path) == path_fd_map.end()) {
                            map<int, int> new_fd_map;
                            new_fd_map[mod.fd] = fd;
                            path_fd_map[paths.relative_path] = new_fd_map;
                        } else {
                            path_fd_map[paths.relative_path][mod.fd] = fd;
                        }

                        ret = oracle_state.add_file_state(paths, false, false, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                        int ino = oracle_state.contents[paths.relative_path].back()->statbuf.st_ino;
                        // record the inode associated with this file descriptor
                        // so we can properly update linked files later
                        fd_ino_map[fd] = ino;
                    }
                    mod_index = i;
                    // return 0;
                    goto done;
                } else if (mod.mod_type == DiskMod::kOpenMod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "open " << mod.path << " at " << call_index << endl;
                        syscall_list += "open,";
                        fd = open(mod.path.c_str(), mod.flags, mod.mode); // using mode should take care of possible O_TMPFILE cases
                        if (fd < 0) {
                            perror("open");
                            log << "find_disk_mod error in open at " << call_index << endl;
                            ret = fd;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }

                        path_fd_map[paths.relative_path][mod.fd] = fd;
                        int ino = oracle_state.contents[paths.relative_path].back()->statbuf.st_ino;
                        // record the inode associated with this file descriptor
                        // so we can properly update linked files later
                        fd_ino_map[fd] = ino;
                    }
                    mod_index = i;
                    // return 0;
                    goto done;
                }
                break;
            case SYS_write:
                if ((mod.mod_type == DiskMod::kDataMod || mod.mod_type == DiskMod::kDataMetadataMod) && mod.mod_opts == DiskMod::kWriteOpt) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "write " << mod.file_mod_len << " bytes to " << mod.path << " at " << call_index << endl;
                        syscall_list += "write,";
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }

                        fd = path_fd_map[paths.relative_path][mod.fd];
                        // lseek to the recorded location to ensure that we write to the 
                        // correct location in the file
                        ret = lseek(fd, mod.file_mod_location, SEEK_SET);
                        if (ret < 0) {
                            perror("lseek");
                            log << "find_disk_mod error in lseek with write at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = write(fd, mod.file_mod_data.get(), mod.file_mod_len);
                        if (ret < 0) {
                            perror("write");
                            log << "find_disk_mod error in write at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state_from_fd(paths, false, false, fd, fd_ino_map[fd], log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_pwrite64:
                if ((mod.mod_type == DiskMod::kDataMod || mod.mod_type == DiskMod::kDataMetadataMod) && mod.mod_opts == DiskMod::kPwriteOpt) {
                    call_index++;
                    if (mod.return_value >= 0) {
                         cout << "pwrite " << mod.path << " at " << call_index << endl;
                         syscall_list += "pwrite,";
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }

                        fd = path_fd_map[paths.relative_path][mod.fd];
                        ret = pwrite(fd, mod.file_mod_data.get(), mod.file_mod_len, mod.file_mod_location);
                        if (ret < 0) {
                            perror("pwrite 2");
                            log << "find_disk_mod error in pwrite at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state_from_fd(paths, false, false, fd, fd_ino_map[fd], log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    // return 0;
                    goto done;
                }
                break;
            case SYS_mmap:
                assert(0 && "Mmap not supported in brute-force tests");
                break;
            case SYS_msync:
                assert(0 && "Msync not supported in brute-force tests");
                break;
            case SYS_munmap:
                assert(0 && "Munmap not supported in brute-force tests");
                break;
            case SYS_fallocate:
                if ((mod.mod_type == DiskMod::kDataMod || 
                    mod.mod_type == DiskMod::kDataMetadataMod) && 
                    (mod.mod_opts == DiskMod::kFallocateOpt || 
                    mod.mod_opts == DiskMod::kPunchHoleKeepSizeOpt ||
                    mod.mod_opts == DiskMod::kCollapseRangeOpt ||
                    mod.mod_opts == DiskMod::kZeroRangeKeepSizeOpt ||
                    mod.mod_opts == DiskMod::kZeroRangeOpt ||
                    mod.mod_opts == DiskMod::kFallocateKeepSizeOpt)) 
                {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "fallocate " << mod.path << " at " << call_index << endl;
                        syscall_list += "fallocate,";

                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }

                        fd = path_fd_map[paths.relative_path][mod.fd];
                        ret = fallocate(fd, mod.mode, mod.file_mod_location, mod.file_mod_len);
                        if (ret < 0) {
                            perror("fallocate");
                            log << "find_disk_mod error in fallocate at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state_from_fd(paths, false, false, fd, fd_ino_map[fd], log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    // return 0;
                    goto done;
                }
                break;
            case SYS_close:
                if (mod.mod_type == DiskMod::kCloseMod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "close " << mod.path << " at " << call_index << endl;
                        syscall_list += "close,";
                        // look up the fd for the closed file, close it here,
                        // and delete it from the path-fd map
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        fd = path_fd_map[paths.relative_path][mod.fd];
                        close(fd);
                        path_fd_map[paths.relative_path].erase(mod.fd);
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_rename:
                if (mod.mod_type == DiskMod::kRenameMod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "rename " << mod.path << " to " << mod.new_path << " at " << call_index << endl;
                        syscall_list += "rename,";
                        // get canonical path of old file before it is deleted
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            cout << "error on old path " << mod.path << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                       
                        // if new path already exists, we have to do some extra work
                        ret = lstat(mod.new_path.c_str(), &file_stat);
                        set<string> linked_files;
                        if (ret >= 0) {
                            int ino = file_stat.st_ino;
                            if (oracle_state.inum_to_files.find(ino) != oracle_state.inum_to_files.end() && !oracle_state.inum_to_files[ino].empty()) {
                                linked_files = oracle_state.inum_to_files[ino].back();
                            }
                        }

                        same_file = mod.new_path.compare(mod.path) == 0 || linked_files.find(paths.relative_path) != linked_files.end();
                        if (!same_file) {
                            // if the file is a directory, we'll need to update the oracle state for all of its 
                            // contents as well
                            ret = update_children(paths, false, true, log, oracle_diff_file);
                            if (ret < 0) {
                                test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                test_info.PrintResults(log, test_name );
                                goto out;
                            }
                        }

                        ret = rename(mod.path.c_str(), mod.new_path.c_str());
                        if (ret < 0) {
                            perror("rename");
                            log << "find_disk_mod error in rename at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }

                        if (!same_file) {
                            // the old file has been deleted. record this with its canonical path
                            ret = oracle_state.add_file_state(paths, false, true, false, false, log, oracle_diff_file);
                            if (ret < 0) {
                                log << "Failed getting oracle state" << endl;
                                test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                test_info.PrintResults(log, test_name );
                                return ret;
                            }
                            string old_relative_path = paths.relative_path;

                            ret = oracle_state.get_paths(mod.new_path, paths, log);
                            if (ret < 0) {
                                cout << "error on new path " << mod.new_path << endl;
                                test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                test_info.PrintResults(log, test_name );
                                goto out;
                            }

                            // update path fd map for file that was renamed, if necessary
                            if (path_fd_map.find(old_relative_path) != path_fd_map.end()) {
                                for (map<int, int>::iterator it = path_fd_map[old_relative_path].begin(); it != path_fd_map[old_relative_path].end(); it++) {
                                    path_fd_map[paths.relative_path][it->first] = it->second;
                                }
                                path_fd_map.erase(old_relative_path);
                            } 
                            // you also have to update the path fd map for any children that the renamed file might have that are open
                            string old_file = "", new_descendant;
                            for (map<string, map<int, int>>::iterator it = path_fd_map.begin(); it != path_fd_map.end(); it++) {
                                // if a file in the fd map is the descendant of a renamed file, you need to update it 
                                if (it->first.rfind(old_relative_path, 0) == 0 && it->first.compare(old_relative_path) != 0) {
                                    new_descendant = it->first;
                                    old_file = it->first;
                                    new_descendant.erase(0, old_relative_path.size());
                                    new_descendant = paths.relative_path + new_descendant;
                                    break;
                                }
                            }
                            if (old_file.compare("") != 0) {
                                path_fd_map[new_descendant] = path_fd_map[old_file];
                                path_fd_map.erase(old_file);
                            }

                            // cout << "linked files: " << endl;
                            // update state for files linked with the file overwritten by the rename (if there is one)
                            // we have to do this after executing rename, but before updating that file's state to 
                            // make sure we capture everything
                            for (set<string>::iterator it = linked_files.begin(); it != linked_files.end(); it++) {
                                if (*it != paths.relative_path) {
                                    ret = oracle_state.get_paths(device_mount_point + "/" + *it, temp_paths, log);
                                    if (ret < 0) {
                                        cout << "error on linked path " << device_mount_point + "/" + *it << endl;
                                        test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                        test_info.PrintResults(log, test_name );
                                        goto out;
                                    }
                                    ret = oracle_state.add_file_state(temp_paths, false, false, false, false, log, oracle_diff_file);
                                    if (ret < 0) {
                                        log << "Failed getting oracle state" << endl;
                                        test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                        test_info.PrintResults(log, test_name );
                                        goto out;
                                    }
                                }
                            }
                            
                            // TODO: creat should only be true if the file didn't 
                            // exist before (but this isn't going to cause incorrect
                            // behavior) (probably)
                            int old_inode = -1;
                            if (oracle_state.contents.find(paths.relative_path) != oracle_state.contents.end()) {
                                old_inode = oracle_state.contents[paths.relative_path].back()->statbuf.st_ino;
                            }
                            ret = oracle_state.add_file_state(paths, true, false, false, false, log, oracle_diff_file);
                            if (ret < 0) {
                                log << "Failed getting oracle state" << endl;
                                test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                test_info.PrintResults(log, test_name );
                                goto out;
                            }
                            if (old_inode > 0) {
                                oracle_state.remove_file_from_inode(paths.relative_path, old_inode);
                            }

                            ret = update_children(paths, false, false, log, oracle_diff_file);
                            if (ret < 0) {
                                test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                test_info.PrintResults(log, test_name );
                                goto out;
                            }
                        } else {
                            ret = oracle_state.add_file_state(paths, false, false, false, false, log, oracle_diff_file);
                            if (ret < 0) {
                                log << "Failed getting oracle state" << endl;
                                test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                                test_info.PrintResults(log, test_name );
                                return ret;
                            }
                        }
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_unlink:
                if (mod.mod_type == DiskMod::kRemoveMod && !mod.directory_mod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "unlink " << mod.path << " at " << call_index << endl;
                        syscall_list += "unlink,";
                        // get canonical path before the file is deleted
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            cout << "failed getting canonical state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = unlink(mod.path.c_str());
                        if (ret < 0) {
                            perror("unlink");
                            log << "find_disk_mod error in unlink at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state(paths, false, true, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    // return 0;
                    goto done;
                }
                break;
            case SYS_rmdir:
                if (mod.mod_type == DiskMod::kRemoveMod && mod.directory_mod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "rmdir " << mod.path << " at " << call_index << endl;
                        syscall_list += "rmdir,";
                        // get canonical path before directory is deleted
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = rmdir(mod.path.c_str());
                        if (ret < 0) {
                            perror("rmdir");
                            log << "find_disk_mod error in rmdir at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state(paths, false, true, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_link:
                if (mod.mod_type == DiskMod::kLinkMod && mod.mod_opts == DiskMod::kLinkOpt) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "link " << mod.path << ", " << mod.new_path << " at " << call_index << endl;
                        syscall_list += "link,";
                        ret = link(mod.path.c_str(), mod.new_path.c_str());
                        if (ret < 0) {
                            perror("link");
                            log << "find_disk_error in link at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            cout << "error in get paths link 1" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state(paths, false, false, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                        ret = oracle_state.get_paths(mod.new_path, new_paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state(new_paths, true, false, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                        // update file state for any files linked to these two
                        ret = oracle_state.update_links(paths, new_paths, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "failed updating links" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_symlinkat:
                // TODO: add symlink support. it introduces a lot of corner cases that 
                // we don't really have time to work through right now
                assert(false && "symlink not currently supported");
                if (mod.mod_type == DiskMod::kLinkMod && mod.mod_opts == DiskMod::kSymlinkOpt) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "symlink " << mod.path << ", " << mod.new_path << " at " << call_index << endl;
                        syscall_list += "symlink,";
                        // string new_path = device_mount_point + "/" + mod.new_path;
                        // TODO: doing canonical path here might break things
                        ret = symlink(mod.path.c_str(), mod.new_path.c_str());
                        if (ret < 0) {
                            perror("symlink");
                            log << "find_disk_mod error in symlink at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        // this doesn't work properly in the symlink case right now
                        ret = oracle_state.get_paths(mod.new_path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        };
                        // target is unchanged by symlink, so we don't need 
                        // to add new state for it
                        // ret = oracle_state.add_symlink_state(mod.path, device_mount_point + "/" + mod.new_path);
                        ret = oracle_state.add_file_state(paths, false, false, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "failed getting oracle symlink state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_fsync:
                if (mod.mod_type == DiskMod::kFsyncMod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        // TODO: in NOVA, fsync and fdatasync always pass unless the file is mmap'ed
                        // and none of our files are mmap'ed. so we can just ignore it if this fails
                        cout << "fsync " << mod.path << " at " << call_index << endl;
                        syscall_list += "fsync,";

                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret >= 0) {
                            fd = path_fd_map[paths.relative_path][mod.fd];
                            fsync(fd);
                            ret = oracle_state.add_file_state_from_fd(paths, true, false, fd, fd_ino_map[fd], log, oracle_diff_file);
                            if (ret < 0) {
                                log << "Failed getting oracle state in fsync" << endl;
                            }
                        } else {
                            ret = 0;
                        }
                        
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_fdatasync:
                if (mod.mod_type == DiskMod::kFsyncMod) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        // TODO: in NOVA, fsync and fdatasync always pass unless the file is mmap'ed
                        // and none of our files are mmap'ed. so we can just ignore it if this fails
                        cout << "fdatasync " << mod.path << " at " << call_index << endl;
                        syscall_list += "fdatasync,";

                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret >= 0) {
                            fd = path_fd_map[paths.relative_path][mod.fd];
                            fdatasync(fd);
                            ret = oracle_state.add_file_state_from_fd(paths, false, true, fd, fd_ino_map[fd], log, oracle_diff_file);
                        } else {
                            ret = 0;
                        }
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_sync:
                call_index++;
                if (mod.mod_type == DiskMod::kSyncMod) {
                    if (mod.return_value >= 0) {
                        cout << "sync at " << call_index << endl;
                        syscall_list += "sync,";
                        sync();
                        oracle_state.sync();
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_truncate:
                if (mod.mod_type == DiskMod::kDataMetadataMod && mod.mod_opts == DiskMod::kTruncateOpt) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "truncate " << mod.path << " at " << call_index << endl;
                        syscall_list += "truncate,";
                        ret = truncate(mod.path.c_str(), mod.file_mod_len);
                        if (ret < 0) {
                            perror("truncate");
                            log << "find_disk_mod error in truncate at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state(paths, false, false, false, false, log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_ftruncate:
                if (mod.mod_type == DiskMod::kDataMetadataMod && mod.mod_opts == DiskMod::kTruncateOpt) {
                    call_index++;
                    if (mod.return_value >= 0) {
                        cout << "ftruncate " << mod.path << " to size " << mod.file_mod_len << " at " << call_index << endl;
                        syscall_list += "ftruncate,";
                        ret = oracle_state.get_paths(mod.path, paths, log);
                        if (ret < 0) {
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        fd = path_fd_map[paths.relative_path][mod.fd];
                        ret = ftruncate(fd, mod.file_mod_len);
                        if (ret < 0) {
                            perror("ftruncate");
                            log << "find_disk_mod error in ftruncate at " << call_index << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            goto out;
                        }
                        ret = oracle_state.add_file_state_from_fd(paths, false, false, fd, fd_ino_map[fd], log, oracle_diff_file);
                        if (ret < 0) {
                            log << "Failed getting oracle state" << endl;
                            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
                            test_info.PrintResults(log, test_name );
                            return ret;
                        }
                        
                    }
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_lseek:
                if (mod.mod_type == DiskMod::kLseekMod) {
                    call_index++;
                    cout << "lseek at " << call_index << endl;
                    mod_index = i;
                    goto done;
                }
                break;
            case SYS_read:
                if (mod.mod_type == DiskMod::kReadMod) {
                    call_index++;
                    cout << "read at " << call_index << endl;
                    mod_index = i;
                    goto done;
                }
                break;
            default:
                cout << "Unsupported system call " << sr.syscall_num << endl;
                assert(0 && "Unsupported system call");
        }
    }

done:
    return 0;


    // if something fails, make sure all opened files are closed before returning a negative value
out:
    for (map<string, map<int, int>>::iterator it = path_fd_map.begin(); it != path_fd_map.end(); it++) {
        map<int, int> fds = it->second;
        for (map<int, int>::iterator it2 = fds.begin(); it2 != fds.end(); it2++) {
            close(it2->second);
        }
    }
    path_fd_map.clear();
    return ret;
    
}

int Tester::make_and_check_crash_states(
    int fd_replay, 
    int fd, 
    int checkpoint, 
    ofstream& log, 
    string test_name, 
    ofstream& trace_file, 
    bool make_trace, 
    int &mod_index, 
    bool reorder) 
{
    unsigned int i, j;
    int ret;
    // int passed = 0;
    milliseconds elapsed;
    // if there have been unordered writes AND the FS has been 
    // mounted, we can try to throw a crash in here
    // first: make a copy of the replay up to this point BEFORE 
    // flushing these unordered writes
    if (fs_mounted && reorder) {
        sfence_count++;

        // now find all the subsets of unfenced writes to test
        // put the writes in a vector
        vector<vector<struct write_op*> > new_subsets;
        new_subsets = handle_outstanding_writes(log, test_name);

        for (i = 0; i < new_subsets.size(); i++) {
            time_point<steady_clock> run_test_start = steady_clock::now();
            for (j = 0; j < new_subsets[i].size(); j++) {
                log << std::hex << new_subsets[i][j]->metadata->dst << " " << std::dec << new_subsets[i][j]->metadata->len << endl;
            }
            log << endl;

            string test_name2 = test_name + "_sfence" + to_string(sfence_count) + "-" + to_string(i);
            // make a trace for the write in new_subsets[i]
            if (make_trace) {
                string trace_filename = "logs/" + test_name2 + "_stacktrace";
                ifstream stack_src("logs/replay_" + test_name + "_stacktrace", std::ios::binary);
                ofstream stack_dst(trace_filename, std::ios::binary);
                stack_dst << stack_src.rdbuf();
                stack_src.close();
                stack_dst.close();
                ofstream subset_trace(trace_filename, ofstream::out | std::ios::app);
                for (j = 0; j < new_subsets[i].size(); j++) {
                    ret = write_stack_trace(new_subsets[i][j], subset_trace);
                    if (ret < 0) {
                        log << "Failed writing stack trace file" << endl;
                        return -1;
                    }
                }
                subset_trace.close();
            }
            ret = make_replay(test_name2, replay_device_path, new_subsets[i], log);
            time_point<steady_clock> create_state = steady_clock::now();
            elapsed = duration_cast<milliseconds>(create_state - run_test_start);
            log << "time to create crash state: " << elapsed.count() << endl;

            // if (sfence_count == 22 && i == 0) {
            //     string command = "dd if=/dev/pmem0 of=/root/tmpdir/oracle.img bs=100M";
            //     system(command.c_str());
            //     command = "dd if=/dev/pmem1 of=/root/tmpdir/crash.img bs=100M";
            //     system(command.c_str());
            // }

            // TODO: put an option in to save the replay files
            ret = check_crash_state(fd_replay, test_name2, log, checkpoint, reorder, false);
            time_point<steady_clock> check_state = steady_clock::now();
            elapsed = duration_cast<milliseconds>(check_state - create_state);
            log << "time to test crash state: " << elapsed.count() << endl;
            
            // time_point<steady_clock> run_test_end = steady_clock::now();  
            elapsed = duration_cast<milliseconds>(check_state - run_test_start);
            log << "time to create and test crash state: " << elapsed.count() << endl;
            log << "----------------------------" << endl;
        
            if (ret < 0) {
                return ret;
            }
        }
    }

    return 0;
}

int Tester::check_crash_state(int fd_replay, string test_name, ofstream& log, int checkpoint, bool reorder, bool syscall_finished) {
    bool passed;
    int ret = 0;
    // make sure the log is empty, turn on logging and undo mode
    this->crashStateLogOut << endl;
    int fd_ioctl = open("/dev/ioctl_dummy", 0);
    if (fd_ioctl < 0) {
        perror("Unable to open IOCTL device");
        log << "Unable to open IOCTL device; is logger module loaded?" << endl;
        return fd_ioctl;
    }
    ret = ioctl(fd_ioctl, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning off logging" << endl;
        close(fd_ioctl);
        return ret;
    }
    ret = ioctl(fd_ioctl, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error freeing log via IOCTL" << endl;
        close(fd_ioctl);
        return ret;
    }
    // turn on logging with undo mode for the replay device
    ret = ioctl(fd_ioctl, LOGGER_UNDO_ON, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning on undo mode" << endl;
        close(fd_ioctl);
        return fd_ioctl;
    }
    ret = ioctl(fd_ioctl, LOGGER_LOG_ON, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning on logging" << endl;
        close(fd_ioctl);
        return fd_ioctl;
    }
    // clear dmesg logs so we can look at them for errors
    string command = "dmesg -C";
    system(command.c_str());
    passed = run_check(test_name, log, checkpoint, syscall_finished);
    // turn off logging and undo mode
    // we'll free the log later
    ret = ioctl(fd_ioctl, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning off logging" << endl;
        close(fd_ioctl);
        return ret;
    }
    ret = ioctl(fd_ioctl, LOGGER_UNDO_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning off undo mode" << endl;
        close(fd_ioctl);
        return fd_ioctl;
    }

    close(fd_ioctl);

    ret = play_undo_log(fd_replay, log);
    if (ret < 0) {
        return ret;
    }

    if (!passed) {
        cout << test_name << " failed" << endl;
        // TODO: to NOT stop testing as soon as a test fails, 
        // don't return a negative here
        return -1;
        // return 0;
    }

    return 0;
}

/*
 * This function is only called when we hit a checkpoint in non synchronous
 * file system like ext4 dax or xfs dax. Checkpoints are only placed after fsyncs
 * so the current state of the replay device is the final crash state that we will
 * check.
 * TODO: since we don't have to roll back and replay to obtain different crash states,
 * we can probably disable the management of the base replay device when this type 
 * of file system is being tested; would improve performance a bit
 */
int Tester::check_async_crash(string test_name, ofstream& log) {
    int ret, fd_ioctl;
    milliseconds elapsed;
    string path, command;
    DiskMod mod;
    bool passed = true;
    SingleTestInfo test_info;
    test_info.test_num = 0; // TODO: this is wrong. do we have to set this?

    time_point<steady_clock> check_state = steady_clock::now();

    ofstream diff_file;
    string diff_name = diff_path + "diff-" + test_name;
    diff_file.open(diff_name, std::fstream::out | std::fstream::app);

    cout << "running test " << test_name << endl;

    // make sure the log is empty, turn off logging.
    // we don't need undo logging here.
    // TODO: make a separate function for turning off and clearing the log

    fd_ioctl = open("/dev/ioctl_dummy", 0);
    if (fd_ioctl < 0) {
        perror("Unable to open IOCTL device");
        log << "Unable to open IOCTL device; is logger module loaded?" << endl;
        ret = fd_ioctl;
        passed = false;
        goto async_out;
    }
    ret = ioctl(fd_ioctl, LOGGER_LOG_OFF, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error turning off logging" << endl;
        close(fd_ioctl);
        passed = false;
        goto async_out;
    }
    ret = ioctl(fd_ioctl, LOGGER_FREE_LOG, NULL);
    if (ret < 0) {
        perror("ioctl");
        log << "Error freeing log via IOCTL" << endl;
        close(fd_ioctl);
        passed = false;
        goto async_out;
    }
    close(fd_ioctl);

    // // clear dmesg logs so we can look at them for errors without scanning the 
    // // entire thing from boot and past tests
    // command = "dmesg -C";
    // system(command.c_str());

    ret = mount_replay();
    if (ret != 0) {
        // if it fails to mount here, that's an error!
        perror("mount");
        diff_file << "File system is unmountable" << endl;
        test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
        test_info.PrintResults(log, test_name );
        diff_file.close();
        return false;
    }

    // now iterate over the mods and perform checks
    // checks on sync file systems use an index variable to keep track of 
    // where we are in the workload, but since we only crash at the end here,
    // we'll iterate over the whole thing
    for (unsigned int i = 0; i < mods_.size(); i++) {
        mod = mods_[i];
        path = mod.path;
        if (mod.mod_type == DiskMod::kFsyncMod) {
            // compare files at the fsynced path between the crashed state 
            // and the oracle
            ret = oracle_state.check_generic(path, diff_file, log, true);
            if (!ret) {
                passed = false;
                goto async_out;
            }
        } else if (mod.mod_type == DiskMod::kSyncMod) {
            // compare the entire disk
            ret = oracle_state.check_disk_contents(replay_mount_point, replay_device_path, diff_file, log);
            if (!ret) {
                passed = false;
                goto async_out;
            }
        } else if (mod.mod_type == DiskMod::kDataMod || 
            mod.mod_type == DiskMod::kSyncFileRangeMod) {
            ret = oracle_state.check_file_contents_range(path, mod.file_mod_location, mod.file_mod_len, diff_file, log);
            if (!ret) {
                passed = false;
                goto async_out;
            }
        }
    }

    ret = make_files(replay_mount_point, diff_file);
    if (!ret) {
        passed = false;
        goto async_out;
    }

    ret = delete_files(replay_mount_point, diff_file);
    if (!ret) {
        passed = false;
        goto async_out;
    }

    ret = umount(replay_mount_point.c_str());
    if (ret != 0) {
        // if it fails, sleep for a second to give it time to finish up, then try again
        sleep(2);
        ret = umount(replay_mount_point.c_str());
        if (ret != 0) {
            perror("unmount");
            diff_file.close();
            return false;
        }
    }

    elapsed = duration_cast<milliseconds>(steady_clock::now() - check_state);
    log << "time to test crash state: " << elapsed.count() << endl;

async_out:
    diff_file.close();

    if (passed) {
        cout << "passed, removing diff file" << endl;
        ret = remove(diff_name.c_str());
        if (ret < 0) {
            return ret;
        }
        return 0;
    } else {
        test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
        test_info.PrintResults(log, test_name );
        return -1;
    }
}

// TODO: this is not used and most likely does not work correctly. remove it entirely? or fix it?
int Tester::write_stack_trace(struct write_op* op, ofstream& trace_file) {
    int ret;
    for (unsigned int i = 0; i < op->metadata->nr_entries; i++) {
        char buffer[128];
        string result;
        // if we've seen this address before, we don't need to call addr2line to resolve it to a function and line number
        unsigned long address = op->metadata->trace_entries[i] - mod_addr;
        // if (addr2line_cache.find(address) != addr2line_cache.end()) {
        //     result = addr2line_cache[address];
        // }
        // else {
            char addr_string[32];
            ret = sprintf(addr_string, "%lx", address);
            if (ret < 0) {
                return ret;
            }

            string command = "eu-addr2line -f -e " + kernel + " " + string(addr_string);
            FILE *pipe = popen(command.c_str(), "r");
            if (!pipe) {
                return -1;
            }
            if (i == 0) {
                char temp[32];
                // printf("%llx\n", op->metadata->dst);
                ret = sprintf(temp, "%llx", op->metadata->dst);
                if (ret < 0 ) {
                    return ret;
                }
                result = string(temp) + " " ;
            }
            while (!feof(pipe)) {
                if (fgets(buffer, 128, pipe) != NULL) {
                    result += buffer;
                }
            }
            pclose(pipe);
            // add this string to our cache so we don't have to look it up again later if we see it again
            // TODO: should this cache be in pmtester and passed in somehow so that we can use it between calls to the harness?
            // addr2line_cache[address] = result;
        // }
        trace_file << result;
    }
    trace_file << endl;

    return 0;
}

vector<vector<struct write_op*> > Tester::handle_outstanding_writes(ofstream& log, string test_name) {
    bool has_data_write = false;
    vector<vector<struct write_op*> > new_subsets;
    new_subsets.clear();
    vector<struct write_op*> op_vec = write_queue;

    for (unsigned int i = 0; i < op_vec.size(); i++) {
        if (op_vec[i]->metadata->likely_data == 1) {
            has_data_write = true;
            break;
        }
    }

    vector<struct write_op*> current;

    unsigned int subset_size;
    if (max_k < 0 || op_vec.size() < max_k) {
        subset_size = op_vec.size();
    } else {
        subset_size = max_k;
    }

    for (unsigned int k = 1; k <= subset_size; k++) {
        choose(0, k, op_vec, current, new_subsets);
    }

    // if the epoch has any data writes, go through and add some subsets where we modify the data writes according to some heuristics to try to expose more bugs
    if (has_data_write && check_data) {
        modify_data_writes(new_subsets, op_vec);
    }
    
    return new_subsets;
}

void Tester::choose(int n, int k, vector<struct write_op*> op_vec, vector<struct write_op*> current, vector<vector<struct write_op*> > &new_subsets) {
    if (k == 0) {
        new_subsets.push_back(current);
    }
    else {
        for (unsigned int i = n; i <= op_vec.size() - k; i++) {
            vector<struct write_op*> new_vec(current);
            new_vec.push_back(op_vec[i]);
            choose(i+1, k-1, op_vec, new_vec, new_subsets);
        }
    }
}

int Tester::make_replay(string test_name, string replica_path, vector<struct write_op*> writes, ofstream& log) {
    int ret, offset;
    string command;
    int fd;

    fd = open(replica_path.c_str(), O_RDWR);
    if (fd < 0) {
        perror("open replica path");
        return fd;
    }

    for (unsigned int i = 0; i < writes.size(); i++) {
        struct write_op* current = writes[i];
        if (fs_mounted) {
            // first create a write entry storing what is about to be overwritten
            // TODO: make sure to free these!
            struct write_op* undo_entry = (struct write_op*)malloc(sizeof(struct write_op));
            if (undo_entry == NULL) {
                close(fd);
                return -ENOMEM;
            }
            undo_entry->metadata = (struct op_metadata*)malloc(sizeof(struct op_metadata));
            if (undo_entry->metadata == NULL) {
                close(fd);
                return -ENOMEM;
            }
            undo_entry->metadata->dst = current->metadata->dst + (replay_pm_start - pm_start);
            undo_entry->metadata->len = current->metadata->len;
            undo_entry->data = malloc(undo_entry->metadata->len);
            if (undo_entry->data == NULL) {
                close(fd);
                return -ENOMEM;
            }
            // read the current contents from the file
            offset = current->metadata->dst - pm_start;
            ret = pread(fd, undo_entry->data, undo_entry->metadata->len, offset);
            // add the entry to the undo list
            undo_log.push_back(undo_entry);
        }

        offset = current->metadata->dst - pm_start;
        ret = pwrite(fd, current->data, current->metadata->len, offset);
        if (ret < 0) {
            perror("pwrite 6");
            close(fd);
            return ret;
        }
    }
    fsync(fd);
    close(fd);
    
    return 0;
}


bool Tester::run_check(string test_name, ofstream& log, int checkpoint, bool syscall_finished) {
    int ret;
    bool retval;
    unsigned int nthreads = std::thread::hardware_concurrency();
    SingleTestInfo test_info;
    test_info.test_num = checkpoint; // TODO: this is wrong

    ofstream diff_file;
    string diff_name = diff_path + "diff-" + test_name;
    diff_file.open(diff_name, std::fstream::out | std::fstream::app);

    diff_file << "# of CPUs: " << nthreads << endl;
    diff_file << "Mount opts: " << mount_opts << endl;

    ret = mount_replay();
    if (ret != 0) {
        // if it fails to mount here, that's an error!
        perror("mount");
        diff_file << "File system is unmountable" << endl;
        test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
        test_info.PrintResults(log, test_name );
        diff_file.close();
        return false;
    }
    // check the contents of the file system based on the profiling
    retval = check_fs_contents2(checkpoint, diff_file, log, syscall_finished);
    if (!retval) {
        test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
        test_info.PrintResults(log, test_name );
    }
    else {
        // check the dmesg output for silent errors
        string command = "dmesg";
        FILE *fp;
        char buffer[4096];
        string dmesg_output;

        fp = popen(command.c_str(), "r");
        if (fp == NULL) {
            log << "Unable to read dmesg " << endl;
            diff_file << "Unable to read dmesg" << endl;
            return false;
        }
        while (!feof(fp)) {
            if (fgets(buffer, 4096, fp) != NULL) {
                dmesg_output += string(buffer);
            }
        }

        pclose(fp);
        
        // TODO: specify error messages to search for somewhere else
        // TODO: look for nova error messages once we have the truncate bug fixed
        // if (dmesg_output.find("nova error") != string::npos || dmesg_output.find("pmfs error") != string::npos) {
        if (dmesg_output.find("pmfs error") != string::npos || dmesg_output.find("winefs error") != string::npos) {
            diff_file << "dmesg logs may contain an error: " << endl;
            diff_file << dmesg_output << endl;
            retval = false;
        }

        if (!retval) {
            test_info.data_test.SetError(fs_testing::tests::DataTestResult::kAutoCheckFailed);
            test_info.PrintResults(log, test_name );
        }

    }
    test_info.PrintResults(log, test_name );
    ret = umount(replay_mount_point.c_str());
    if (ret != 0) {
        // if it fails, sleep for a second to give it time to finish up, then try again
        sleep(2);
        ret = umount(replay_mount_point.c_str());
        if (ret != 0) {
            perror("unmount");
            diff_file.close();
            return false;
        }
    }

    diff_file.close();

    // if the test passed, remove the diff file
    if (retval) {
        ret = remove(diff_name.c_str());
        if (ret < 0) {
            return false;
        }
    }
    return retval;
}

int Tester::flush_entries(int fd_replay, struct write_op* sfence_op, ofstream& trace_file, bool make_trace, ofstream &log, vector<struct write_op*> &q, bool reorder) {
    int offset, ret;
    struct write_op* current;
    // FILE* base_fptr;
    int fd_base;
    
    // TODO: should do this somewhere else so you don't have to open
    // over and over again
    fd_base = open(base_replay_path.c_str(), O_RDWR);
    if (fd_base < 0) {
        perror("open base 2");
        return -1;
    }
    for (unsigned int i = 0; i < q.size(); i++) {
        current = q[i];
        if (current->metadata->type == SFENCE) {
            if (make_trace && fs_mounted) {
                ret = write_stack_trace(current, trace_file);
                if (ret < 0) {
                    return ret;
                    // free stuff??
                }
                trace_file << "SFENCE" << endl << endl;
            }
        }
        else {
            // write the entry's data to the replay file, and then dequeue it
            if (make_trace && fs_mounted) {
                ret = write_stack_trace(current, trace_file);
                if (ret < 0) {
                    close(fd_base);
                    return ret;
                    // free stuff??
                }
            }

            offset = current->metadata->dst - pm_start;
            ret = pwrite(fd_replay, current->data, current->metadata->len, offset);
            if (ret < 0) {
                perror("pwrite 3");
                return ret;
            }
            ret = pwrite(fd_base, current->data, current->metadata->len, offset);
            if (ret < 0) {
                perror("pwrite 4");
                return ret;
            }
        }
    }
    // fclose(base_fptr);
    close(fd_base);
    return 0;
}

int Tester::play_undo_log(int fd_replay, ofstream& log) {  
    // we first need to obtain all of the writes made during fs checks and add them to the undo log
    int ret;
    unsigned long offset;
    struct write_op *new_op, *current;
    int ioctl_val = 0;
    // FILE* base_fptr;
    int fd_base;

    cout << "PLAY UNDO LOG" << endl;

    int fd_ioctl = open("/dev/ioctl_dummy", 0);
    if (fd_ioctl < 0) {
        perror("Unable to open IOCTL device");
        log << "Unable to open IOCTL device; is logger module loaded?" << endl;
        return fd_ioctl;
    }

    fd_base = open(base_replay_path.c_str(), O_RDWR);
    if (fd_base < 0) {
        perror("open 8");
        close(fd_ioctl);
        return fd_base;
    }

    while (ioctl_val == 0) {
        new_op = (struct write_op*)malloc(sizeof(struct write_op));
        if (new_op == NULL) {
            perror("malloc");
            close(fd_ioctl);
            close(fd_base);
            return -ENOMEM;
        }
        new_op->data = NULL;
        new_op->next = NULL;
        new_op->prev = NULL;

        new_op->metadata = (struct op_metadata*)malloc(sizeof(struct op_metadata));
        if (new_op->metadata == NULL) {
            perror("malloc");
            free(new_op);
            close(fd_ioctl);
            close(fd_base);
            return -ENOMEM;
        }
        ioctl_val = ioctl(fd_ioctl, LOGGER_GET_OP, new_op->metadata);
        if (ioctl_val < 0) {
            perror ("error in LOGGER_GET_OP 2");
            close(fd_ioctl);
            close(fd_base);
            return ioctl_val;
        }

        // we don't log SFENCES in the undo log, so everything will have data
        new_op->data = malloc(new_op->metadata->len);
        if (new_op->data == NULL) {
            perror("malloc");
            close(fd_ioctl);
            close(fd_base);
            return -ENOMEM;
        }
        memset(new_op->data, 0, new_op->metadata->len);
        offset = new_op->metadata->dst - replay_pm_start;
        

        ret = pread(fd_base, new_op->data, new_op->metadata->len, offset);


        // add the entry to the undo log
        undo_log.push_back(new_op);

        // go to the next log entry
        ioctl_val = ioctl(fd_ioctl, LOGGER_NEXT_OP, NULL);
    }

    // now, apply the log in reverse order
    for (int i = undo_log.size()-1; i >= 0; i--) {
        current = undo_log[i];
        offset = current->metadata->dst - replay_pm_start;
        ret = pwrite(fd_replay, current->data, current->metadata->len, offset);
        if (ret < 0) {
            perror("pwrite 7");
            close(fd_ioctl);
            close(fd_base);
            return ret;
        }
    }
    undo_log.clear();
    fsync(fd_replay);
    close(fd_base);
    close(fd_ioctl);

    return 0;
}

// this function is called on the epoch level within the syscall being brute force tested
int Tester::modify_data_writes(vector<vector<struct write_op*> > &new_subsets, vector<struct write_op*> op_vec) {
    unsigned int i, j, k, l;
    struct write_op *current;
    vector<vector<struct write_op*> > modified_subsets;

    map<void*, vector<vector<struct write_op*> > > ptr_map;

    for (i = 0; i < op_vec.size(); i++) {
        current = op_vec[i];
        if (current->metadata->likely_data == 1) {
            // set up the ptr map 
            vector<vector<struct write_op*> > v1;
            ptr_map[current->data] = v1;

            // first: remove a cacheline from the middle of the write. 
            // this will require us to add 2 writes (one for the first half of 
            // the data and one for the second half)
            if (current->metadata->len >= 3*CACHELINE_SIZE) {
                unsigned long long first_half = (current->metadata->len / 2);
                first_half = first_half - (first_half % CACHELINE_SIZE);
                unsigned long long second_half = current->metadata->len - (first_half + CACHELINE_SIZE);

                struct write_op* first = (struct write_op*)malloc(sizeof(struct write_op));
                struct write_op* second = (struct write_op*)malloc(sizeof(struct write_op));
                if (first == NULL || second == NULL) {
                    return -1;
                }
                memcpy(first, current, sizeof(struct write_op));
                memcpy(second, current, sizeof(struct write_op));

                first->metadata = (struct op_metadata*)malloc(sizeof(struct op_metadata));
                second->metadata = (struct op_metadata*)malloc(sizeof(struct op_metadata));
                if (first->metadata == NULL || second->metadata == NULL) {
                    return -1;
                }

                // copy in metadata from current write
                memcpy(first->metadata, current->metadata, sizeof(struct op_metadata));
                memcpy(second->metadata, current->metadata, sizeof(struct op_metadata));

                first->metadata->len = first_half;
                second->metadata->len = second_half;
                // second part's dst address and data pointers also 
                // have to be updated
                second->data = (void*)((unsigned long long)current->data + first_half + CACHELINE_SIZE);
                second->metadata->dst = current->metadata->dst + first_half + CACHELINE_SIZE;

                modified_writes_list.push_back(first);
                modified_writes_list.push_back(second);
                // add these writes to ptr_map so we can easily access them later
                vector<struct write_op*> v2 = {first, second};
                ptr_map[current->data].push_back(v2);
            }
            // now just remove first and last cache line
            if (current->metadata->len >= 2*CACHELINE_SIZE) {
                // set up
                struct write_op* first = (struct write_op*)malloc(sizeof(struct write_op));
                struct write_op* second = (struct write_op*)malloc(sizeof(struct write_op));
                if (first == NULL || second == NULL) {
                    return -1;
                }
                memcpy(first, current, sizeof(struct write_op));
                memcpy(second, current, sizeof(struct write_op));

                first->metadata = (struct op_metadata*)malloc(sizeof(struct op_metadata));
                second->metadata = (struct op_metadata*)malloc(sizeof(struct op_metadata));
                if (first->metadata == NULL || second->metadata == NULL) {
                    return -1;
                }

                // copy in metadata from current write
                memcpy(first->metadata, current->metadata, sizeof(struct op_metadata));
                memcpy(second->metadata, current->metadata, sizeof(struct op_metadata));

                // first: make a write that is missing the first cache line
                first->data = (void*)((unsigned long long)current->data + CACHELINE_SIZE);
                first->metadata->dst = current->metadata->dst + CACHELINE_SIZE;
                first->metadata->len = current->metadata->len - CACHELINE_SIZE;
                modified_writes_list.push_back(first);

                // second: make a write that is missing the last cache line
                second->metadata->len = current->metadata->len - CACHELINE_SIZE;
                modified_writes_list.push_back(second);

                vector<struct write_op*> v2 = {first};
                vector<struct write_op*> v3 = {second};
                ptr_map[current->data].push_back(v2);
                ptr_map[current->data].push_back(v3);
            }
        }
    }


    // now look at the subsets and create new subsets with data writes replaced
    // with modified ones.
    for (i = 0; i < new_subsets.size(); i++) {
        for (j = 0; j < new_subsets[i].size(); j++) {
            current = new_subsets[i][j];
            if (current->metadata->likely_data == 1) {
                // for each modified data write, make a copy of the subset,
                // replace the data write with the modified version in ptr_map
                for (k = 0; k < ptr_map[current->data].size(); k++) {
                    vector<struct write_op*> copy(new_subsets[i]);
                    copy[j] = ptr_map[current->data][k][0];
                    // if there's more, insert it
                    // iterate backwards through the ptr_map vector so we can
                    // always insert into the same place in the array
                    for (l = ptr_map[current->data][k].size()-1; l > 0; l--) {

                        copy.insert(copy.begin()+j+1, ptr_map[current->data][k][l]);
                    }
                    modified_subsets.push_back(copy);
                }
            }
        }
    }
    new_subsets.insert(new_subsets.end(), modified_subsets.begin(), modified_subsets.end());
    
    return 0;
}


bool Tester::check_fs_contents2(int checkpoint, ofstream& diff_file, ofstream& log, bool syscall_finished) {
    bool ret;
    bool passed = true;
    DiskMod mod = mods_[mod_index];
    string path(mod.path);

    diff_file << syscall_list << endl;

    // if we are looking at the mod corresponding to the current operation
    if (mod.return_value >= 0) {
        if (mod.mod_type == DiskMod::kReadMod) {
            // do nothing
        }
        // TODO: we should do a bit more for closes
        else if (mod.mod_type == DiskMod::kOpenMod || mod.mod_type == DiskMod::kLseekMod || mod.mod_type == DiskMod::kCloseMod) {
            bool do_check = true;
            // if the file can be opened/lseeked successfully, just check that it can 
            // be successfully opened (and read?) in the crash state
            if (mod.mod_type == DiskMod::kCloseMod) {
                // there is a tricky case where we will not be able to 
                // find a file at close if it is unlinked, then its parent 
                // is renamed, then it is closed
                // TODO: handle this more cleanly
                // for now, just check whether the file being closed is 
                // in the oracle state and if it's not, assume we hit 
                // that case and skip it
                string path = fix_filepath(mod.path);
                string relpath = path.substr(device_mount_point.size() + 1, string::npos);
                if (oracle_state.contents.find(relpath) == oracle_state.contents.end() || oracle_state.contents[relpath].empty()) {
                    do_check = false;
                }
            }
            if (do_check) {
                ret = oracle_state.check_exists(path, diff_file, log, syscall_finished);
                if (!ret) {
                    passed = false;
                    goto end;
                }
            }
        }
        // covers creat and mkdir
        else if (mod.mod_type == DiskMod::kCreateMod) {
            ret = oracle_state.check_creat_and_mkdir(path, diff_file, log, syscall_finished);
            if (!ret) {
                passed = false;
                goto end;
            }
        } else if ((mod.mod_type == DiskMod::kDataMod || mod.mod_type == DiskMod::kDataMetadataMod) && (mod.mod_opts == DiskMod::kWriteOpt || mod.mod_opts == DiskMod::kPwriteOpt)) {
            ret = oracle_state.check_write(path, diff_file, log, syscall_finished, check_data);
            if (!ret) {
                passed = false;
                goto end;
            }
        }
        else if (mod.mod_type == DiskMod::kRenameMod) {
            ret = oracle_state.check_rename(path, mod.new_path, diff_file, log, syscall_finished);
            if (!ret) {
                passed = false;
                goto end;
            }
        }
        // TODO: the fsync and sync checks. these will be less interesting so you should write all the other checks first
        else if (mod.mod_type == DiskMod::kFsyncMod) {
            // TODO: have to be careful here; looks like NOVA doesn't return an error
            // if you try to fsync a file that doesn't exist.
        }
        else if (mod.mod_type == DiskMod::kSyncMod) {
        }
        else if (mod.mod_type == DiskMod::kRemoveMod) {
            ret = oracle_state.check_remove(path, diff_file, log, syscall_finished);
            if (!ret) {
                passed = false;
                goto end;
            }
        } else if (mod.mod_type == DiskMod::kLinkMod) {
            if (mod.mod_opts != DiskMod::kSymlinkOpt) {
                ret = oracle_state.check_link(path, mod.new_path, diff_file, log, syscall_finished);
                if (!ret) {
                    passed = false;
                    goto end;
                }
            }
        }
        // generic check to make sure things were atomic. this should be enough for most 
        // system calls
        else {
            ret = oracle_state.check_generic(path, diff_file, log, syscall_finished);
            if (!ret) {
                passed = false;
                goto end;
            }
        }
        ret = oracle_state.check_files(mod, path_fd_map, fd_ino_map, diff_file, log);
        if (!ret) {
            passed = false;
            goto end;
        }
        
    }

    ret = make_files(replay_mount_point, diff_file);
    if (!ret) {
        passed = false;
        goto end;
    }

    ret = delete_files(replay_mount_point, diff_file);
    if (!ret) {
        passed = false;
        goto end;
    }

end:
    return passed;
}

// `path` should be an absolute path into the crashed fs
bool Tester::make_files(string path, ofstream& diff_file) {
    bool ret;
    int res;
    struct stat statbuf;

    res = lstat(path.c_str(), &statbuf);
    if (res < 0) {
        diff_file << "lstat on " << path << " failed in make_files, error " << strerror(errno) << endl;
        return false;
    }


    if (S_ISDIR(statbuf.st_mode)) {
        string filepath = path + "/" + "_dummy";
        int fd = open(filepath.c_str(), O_CREAT|O_RDWR, 0777);
        if (fd < 0) {
            diff_file << "Couldn't create file " << filepath << endl;
            return false;
        }
        close(fd);

        DIR* directory = opendir(path.c_str());
        if (directory == NULL) {
            cout << "Could not open directory " << path << endl;
            diff_file << "Could not open directory " << path << endl;
            return false;
        }

        struct dirent* dir_entry;
        while ((dir_entry = readdir(directory))) {
            if ((strcmp(dir_entry->d_name, ".") == 0) ||
                (strcmp(dir_entry->d_name, "..") == 0)) {
                continue;
            }

            string subpath = path + "/" + string(dir_entry->d_name);
            ret = make_files(subpath, diff_file);
            if (!ret) {
                closedir(directory);
                return false;
            }
        }
        closedir(directory);
    }

    return true;
}

// `path` should be an absolute path into the crashed fs
bool Tester::delete_files(string path, ofstream& diff_file) {
    struct stat statbuf;
    int res; 
    bool ret;

    res = lstat(path.c_str(), &statbuf);
    if (res < 0) {
        diff_file << "lstat on " << path << " failed in delete_files" << endl;
        return false;
    }

    if (S_ISDIR(statbuf.st_mode)) {
        // the path leads to a directory, recursively delete contents 
        // before deleting the directory itself
        DIR* directory = opendir(path.c_str());
        if (directory == NULL) {
            cout << "Could not open directory " << path << endl;
            diff_file << "Could not open directory " << path << endl;
            return false;
        }

        struct dirent* dir_entry;
        while ((dir_entry = readdir(directory))) {
            if ((strcmp(dir_entry->d_name, ".") == 0) ||
                (strcmp(dir_entry->d_name, "..") == 0)) {
                continue;
            }

            string subpath = path + "/" + string(dir_entry->d_name);
            ret = delete_files(subpath, diff_file);
            if (!ret) {
                closedir(directory);
                return false;
            }
        }
        closedir(directory);
        if (path != replay_mount_point) {
            res = rmdir(path.c_str());
            if (res < 0) {
                diff_file << "Could not delete directory " << path << " " << strerror(errno) << endl;
                return false;
            }
        }

    } else {
        // it's a regular file, delete it directly
        res = unlink(path.c_str());
        if (res < 0) {
            diff_file << "Could not delete file " << path << " " << strerror(errno) << endl;
            return false;
        }
    }

    return true;
}

int Tester::GetChangeData(const int fd) {
  // Need to read a 64-bit value, switch it to big endian to figure out how much
  // we need to read, read that new data amount, and add it all to a buffer.
  while (true) {
    // Get the next DiskMod size.
    uint64_t buf;
    const int read_res = read(fd, (void *) &buf, sizeof(uint64_t));
    if (read_res < 0) {
      return read_res;
    } else if (read_res == 0) {
      // No more data to read.
      break;
    }
    uint64_t next_chunk_size = be64toh(buf);

    // Read the next DiskMod.
    shared_ptr<char> data(new char[next_chunk_size], [](char *c) {delete[] c;});
    memcpy(data.get(), (void *) &buf, sizeof(uint64_t));
    unsigned long long int read_data = sizeof(uint64_t);
    while (read_data < next_chunk_size) {
      const int res = read(fd, data.get() + read_data,
          next_chunk_size - read_data);
      if (res <= 0) {
        // We shouldn't find a size for a DiskMod without the rest of the
        // DiskMod.
        return -1;
      }
      read_data += res;
    }

    DiskMod mod;
    const int res = DiskMod::Deserialize(data, mod);
    if (res < 0) {
      return res;
    }

    mods_.push_back(mod);
  }
  return SUCCESS;
}

// paths is the absolute path of the base file
int Tester::update_children(struct paths paths, bool creat, bool del, ofstream& log, ofstream& oracle_diff_file) {
    struct stat filestat;
    int ret;
    ret = lstat(paths.canonical_path.c_str(), &filestat);
    if (ret < 0) {
        log << "cannot lstat " << paths.canonical_path << endl;
        return ret;
    }
    if (S_ISDIR(filestat.st_mode)) {
        DIR* directory = opendir(paths.canonical_path.c_str());
        if (directory == NULL) {
            log << "could not open directory " << paths.canonical_path << endl;
            return ret;
        }
        struct dirent *dentry;
        while ((dentry = readdir(directory))) {
            if ((strcmp(dentry->d_name, ".") == 0) ||
                (strcmp(dentry->d_name, "..") == 0)) {
                continue;
            }
            struct paths subpaths;
            subpaths.canonical_path = paths.canonical_path + "/" + string(dentry->d_name);
            subpaths.relative_path = paths.relative_path + "/" + string(dentry->d_name);
            ret = oracle_state.add_file_state(subpaths, creat, del, false, false, log, oracle_diff_file);
            if (ret < 0) {
                closedir(directory);
                log << "child file " << subpaths.canonical_path << " could not be accessed" << endl;
                return ret;
            }
            ret = lstat(subpaths.canonical_path.c_str(), &filestat);
            if (ret < 0) {
                closedir(directory);
                log << "cannot lstat " << subpaths.canonical_path << endl;
                return ret;
            }
            if (S_ISDIR(filestat.st_mode)) {
                ret = update_children(subpaths, creat, del, log, oracle_diff_file);
                if (ret < 0) {
                    closedir(directory);
                    return ret;
                }
            }
        }
        closedir(directory);
    }
    return 0;
}

}
