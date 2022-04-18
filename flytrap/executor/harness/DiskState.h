#ifndef DISK_STATE_H
#define DISK_STATE_H

#include <string>
#include <map>
#include <vector>
#include <set>
#include "helpers.h"
#include "../utils/DiskMod.h"

#include "FileState.h"

namespace fs_testing{

class DiskState {
public:
    DiskState();
    DiskState(std::string device_path, std::string mnt_point, std::string r_mnt);
    ~DiskState();

    std::string disk_path;
    std::string mount_point;
    std::string replay_mount_point;
    std::string test_name;

    std::map<std::string, std::vector<FileState*> > contents;
    std::set<std::string> files;

    // versioned map indicating which files have the same inode. whenever we modify these 
    // lists, we add a new version into the vectors
    std::map<int, std::vector<std::set<std::string> > > inum_to_files;


    int add_file_state(struct paths paths, bool creat, bool del, bool fsync, bool fdatasync, std::ofstream& log, std::ofstream& diff_file);
    int add_file_state_from_fd(struct paths paths, bool fsync, bool fdatasync, int fd, int ino, std::ofstream& log, std::ofstream& diff_file);
    std::set<std::string> remove_file_from_inode(string relative_path, int ino);
    int update_links(struct paths old_paths, struct paths new_paths, std::ofstream& log, std::ofstream& diff_file);
    void sync();
    int get_relative_path(std::string file_path, std::string& relative_path);
    int get_paths(std::string path, struct paths& out_paths, std::ofstream& log);

    // int delete_closed_file(struct paths paths, std::map<std::string, std::map<int, int> > path_fd_map);

    int add_symlink_state(std::string target, std::string linkpath);

    bool check_parent(std::string relpath, std::ofstream& diff_file, std::ofstream& log, bool op_completed);

    bool check_exists(std::string path, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished);
    bool check_creat_and_mkdir(std::string path, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished);
    bool check_generic(std::string path, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished);
    bool check_rename(std::string old_path, std::string new_path, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished);
    bool check_write(std::string path, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished, bool atomic);
    bool check_remove(std::string path, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished);
    bool check_link(std::string target, std::string linkpath, std::ofstream& diff_file, std::ofstream& log, bool syscall_finished);

    // bool check_files(utils::DiskMod mod, std::ofstream& diff_file, std::ofstream& log);
    bool check_files(utils::DiskMod mod, std::map<std::string, std::map<int, int> > path_fd_map, std::map<int, int> fd_ino_map, std::ofstream& diff_file, std::ofstream& log);
    bool check_file(std::string path, std::set<std::string> skip_files, std::set<std::string> linked_files, std::ofstream& diff_file, std::ofstream& log);


    bool check_disk_contents(std::string crash_mount_path, std::string crash_dev_path, std::ofstream& diff_file, std::ofstream& log);
    int get_crash_disk_contents(std::string path, std::ofstream& diff_file, std::ofstream& log);
};

}


#endif /* DISK_STATE_H */