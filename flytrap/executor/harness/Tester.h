#ifndef BASE_TESTER_H
#define BASE_TESTER_H

#include <string>
#include <vector>
#include <fstream>
#include <map>

#include "../utils/ClassLoader.h"
#include "../tests/BaseTestCase.h"
#include "../results/TestSuiteResult.h"
#include "../ioctl.h"
#include "DiskState.h"

#define CACHELINE_SIZE 64

namespace fs_testing {

struct syscall_record {
    unsigned int syscall_num;
    unsigned int pid;
    bool finished;
};
    
// this is going to be a base class for tester classes that will be used by the ace and 
// syz executors.
class Tester {

public: 
    Tester() {}

    virtual ~Tester() {}

    virtual int cleanup(std::ofstream& log) = 0;

    virtual int test_load_class(const char *path) {return -1;}

    virtual void test_unload_class() {};

    int mount_fs(bool init);

    int mount_replay();

    int unmount_fs(void);

    virtual void setup() {}
    virtual int resetLogger() {return -1;}
    virtual void setOutputPos(uint32_t* output_pos) {}

    virtual int test_init_values(std::string mountDir, long filesysSize, int threads) {return -1;}
    virtual int test_run(const int change_fd, const int checkpoint, std::ofstream &log) {return -1;};
    int GetChangeData(const int fd);

    void set_test_name(std::string n);

    void free_modified_writes();

    void close_fptrs(); // TODO: do we still use this?

    void free_queue(std::vector<struct write_op *> &q);

    int replay(std::ofstream &log, int checkpoint, std::string test_name, bool make_trace, bool reorder, std::string log_name);

    // TODO: do we still need these? fuzzer shouldn't, so make them virtual?
    virtual bool test_replay(std::ofstream &log, int checkpoint, std::string test_name, bool make_trace, bool reorder) {return false;};
    virtual bool test_replay_internal(std::ofstream &log, int checkpoint, std::string replay_img_path) {return false;};

    int get_write_log(int fd, std::ofstream &log, int checkpoint, bool reorder);

    int process_log_entry(int fd_replay, int fd, int checkpoint, int &checkpoint_count, std::ofstream &log,
                              std::string test_name, std::ofstream &trace_file, bool make_trace, bool reorder,
                              std::ofstream& oracle_diff_file, std::string log_name);

    std::vector <std::vector<struct write_op *>>
        handle_outstanding_writes(std::ofstream &log, std::string test_name);

    int write_stack_trace(struct write_op *op, std::ofstream &trace_file);

    void choose(int n, int k, std::vector<struct write_op *> op_vec, std::vector<struct write_op *> current,
                    std::vector <std::vector<struct write_op *>> &combos);


    int make_replay(std::string test_name, std::string replica_path,
                        std::vector<struct write_op *> writes, std::ofstream &log);

    bool run_check(std::string test_name, std::ofstream& log, int checkpoint, bool syscall_finished);


    int flush_entries(int fd_replay, struct write_op *sfence_op, std::ofstream &trace_file, bool make_trace,
                          std::ofstream &log, std::vector<struct write_op *> &q, bool reorder);

    int modify_data_writes(std::vector <std::vector<struct write_op *>> &new_subsets,
                               std::vector<struct write_op *> op_vec);
    
    int play_undo_log(int fd_replay, std::ofstream& log);

    bool check_fs_contents2(int checkpoint, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished);
    int make_and_check_crash_states(int fd_replay, int fd, int checkpoint, std::ofstream& log, std::string test_name, std::ofstream& trace_file, bool make_trace, int &mod_index, bool reorder);
    int check_crash_state(int fd_replay, std::string test_name, std::ofstream& log, int checkpoint, bool reorder, bool syscall_finished);
    int find_disk_mod(struct syscall_record sr, std::ofstream& log, std::ofstream& oracle_diff_file);
    int check_async_crash(int fd_replay, std::string test_name, std::ofstream& log, std::string log_name);

    std::vector<struct write_op*> write_queue;
    std::vector<struct write_op *> epoch_data_writes;
    std::vector<struct write_op *> modified_writes_list;
    std::vector<std::vector<FILE*> > fptr_map;

    bool collect_cover;

protected:

    std::string device_path;
    std::string replay_device_path;
    std::string device_mount_point;
    std::string replay_mount_point;

    unsigned long pm_start;
    unsigned long pm_size;
    unsigned long replay_pm_start;

    std::string kernel;
    std::string tester_type;
    unsigned long long mod_addr;

    std::string fs;
    
    bool check_data;

    std::string mount_opts;

    int num_threads;

    fs_testing::utils::ClassLoader<fs_testing::tests::BaseTestCase> test_loader;

    // std::vector <std::vector<fs_testing::utils::DiskMod>> mods_;
    std::vector<fs_testing::utils::DiskMod> mods_;

    std::string test_name;

    std::vector<struct write_op*> undo_log;

    struct write_op* head;
    struct write_op* tail;

    std::vector<struct syscall_record> syscalls;
    int sync_index;

    // keeps track of whether there's an unordered clwb write in the linked list
    bool unordered_write = false;
    bool fs_mounted = false;
    int sfence_count;
    int num_data_write_images;

    std::string base_replay_path;
    std::string diff_path;

    // mod index tells us where in the workload we are, including marks and checkpoints
    int mod_index = -1;
    // call_index tells us which system call (successful or unsuccessful) last ran
    // and does not include extra mods like mod_index does
    int call_index = -1;

    std::map<std::string, std::map<int, int> > path_fd_map;
    std::map<int, int> fd_ino_map;

    // std::vector<std::pair<int, int> > sys_ret_list;

    DiskState oracle_state;

    std::string syscall_list;

    std::ofstream crashStateLogOut;
    bool error_in_oracle = false;

    int max_k;

    bool make_files(std::string path, std::ofstream& diff_file);
    bool delete_files(std::string path, std::ofstream& diff_file);
    int update_children(struct paths paths, bool creat, bool del, std::ofstream& log, std::ofstream& oracle_diff_file);
};

}

#endif