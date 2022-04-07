#ifndef FILE_STATE_H
#define FILE_STATE_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <set>

namespace fs_testing {

class FileState {
public:
    FileState(const FileState &old); // copy constructor
    // FileState(std::string p, bool deleted, bool fsync, bool fdatasync);
    FileState();
    ~FileState();

    int init_file_state(std::string p, bool deleted, bool fsync, bool fdatasync, std::ofstream& diff_file);
    int init_symlink_target_state(std::string p);
    int init_crash_file_state(std::string p, std::ofstream& diff_file);

    std::string path; // absolute path so we can look up the file
    bool present;
    bool fsynced; // has this version of the file been fsynced
    bool fdatasynced; // has this version of the file been fdatasynced
    bool symlink;
    bool symlink_cycle; // true if a symlink cycle prevents this file from being accessed 
    struct stat statbuf;

    unsigned int seq_num; // TODO: is this necessary? orders changes?

    // these should probably be in a union because we'll only ever use one at a time
    std::string content_hash; // md5sum hash of the file contents
    std::set<std::string> contents;
    std::string link_target;


    FileState operator=(const FileState& f);
    friend std::ofstream& operator<< (std::ofstream& os, const FileState& f);

    bool compare(FileState* compare_state, std::ofstream& diff_file);

    
private:
    // these should only be used in the constructor
    int set_stat(void);
    int set_content_hash(std::ofstream& diff_file);
    int set_up_state(std::string p, std::ofstream& diff_file);

    // std::string statbuf_tostring();
};
}

#endif /* FILE_STATE_H */