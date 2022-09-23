#include "DiskState.h"
#include "FileState.h"

#include <string>
#include <assert.h>
#include <iostream>
#include <fcntl.h>
#include <set>
#include <unistd.h>
#include <algorithm>
#include <stdio.h>
#include <string.h>

using namespace std;

// probably much bigger than what we need, but good to be safe with the fuzzer...
#define MAX_PATH_LEN 4096 

namespace fs_testing {

DiskState::DiskState() {
    disk_path = "";
    mount_point = "";
}

DiskState::DiskState(string device_path, string mnt_point, string r_mnt) {
    disk_path = device_path;
    mount_point = mnt_point;
    replay_mount_point = r_mnt;
}

DiskState::~DiskState() {
    for (set<string>::iterator it = files.begin(); it != files.end(); it++) {
        string path = *it;
        for (unsigned int i = 0; i < contents[path].size(); i++) {
            delete(contents[path][i]);
        }
    }
}

// obtains the canonical version of the given path as well as the relative version
// with the mount point omitted
int DiskState::get_paths(string path, struct paths& out_paths, ofstream& log) {
    int ret;
    string canonical_path, relative_path;
    canonical_path = fix_filepath(path);
    ret = get_relative_path(canonical_path, relative_path);
    if (ret < 0) {
        log << "Bad test program - path points outside of PM file system" << endl;
        log << path << " - canonical is " << canonical_path << endl;
        return ret;
    }

    out_paths.canonical_path = canonical_path;
    out_paths.relative_path = relative_path;
    return 0;
}


// assume that file_path has already been resolved to a canonical path using realpath
// fills in the relative path by reference
int DiskState::get_relative_path(string file_path, string& relative_path) {
    if (file_path.length() < mount_point.length() || file_path.substr(0, mount_point.length()) != mount_point) {
        return -2;
    }
    if (file_path == mount_point) {
        relative_path = "";
    } else {
        relative_path = file_path.substr(mount_point.length()+1, string::npos); 
    }
    return 0;
}

int DiskState::add_file_state_from_fd(struct paths paths, bool fsync, bool fdatasync, int fd, int ino, ofstream& log, ofstream& diff_file) {
    int ret;
    assert(paths.canonical_path.substr(0, mount_point.length()) == mount_point);
    // if we're operating on a file that doesn't exist any more (which is possible),
    // we need to make sure we retain the fact that the file has been deleted
    bool del;
    if (contents.find(paths.relative_path) != contents.end()) {
        del = !contents[paths.relative_path].back()->present;
    } else {
        del = false;
    }

    FileState* new_file_state = new FileState();
    ret = new_file_state->init_file_state(paths.canonical_path, del, fsync, fdatasync, diff_file);
    // diff_file.close();
    if (ret < 0) {
        return ret;
    }
    // we want to update the state of all files linked to this inode
    set<string> linked_files = inum_to_files[ino].back();
    for (set<string>::iterator it = linked_files.begin(); it != linked_files.end(); it++) {
        if (*it != paths.relative_path) {
            struct paths ino_paths;
            ret = get_paths(mount_point + "/" + *it, ino_paths, log);
            if (ret < 0) {
                log << "failed getting paths for " << *it << endl;
                return ret;
            }
            ret = add_file_state(ino_paths, false, false, false, false, log, diff_file);
            if (ret < 0) {
                log << "failed updating state for " << ino_paths.relative_path << endl;
                return ret;
            }
        }
    }

    // save this version of the file
    if (contents.find(paths.relative_path) == contents.end()) {
        vector<FileState*> new_vec = {new_file_state};
        contents[paths.relative_path] = new_vec;
    } else {
        contents[paths.relative_path].push_back(new_file_state);
    }
    files.insert(paths.relative_path);

    return 0;
}

int DiskState::add_file_state(struct paths paths, bool creat, bool del, bool fsync, bool fdatasync, ofstream& log, ofstream& diff_file) {
    int ret, ino;
    assert(paths.canonical_path.substr(0, mount_point.length()) == mount_point);
    if (creat || del) {
        // if we are creating or deleting a file, also update its parent
        string parent_relative_path, parent_path;
        size_t found = paths.relative_path.find_last_of("/");
        if (found == string::npos) {
            parent_relative_path = "";
            parent_path = mount_point;
        } else {
            parent_relative_path = paths.relative_path.substr(0, found);
            parent_path = mount_point + "/" + parent_relative_path;
        }

        // in certain cases with symlink loops, the parent may not exist after the symlink is deleted.
        // in this case, we should walk up the path until we find an ancestor that does exist.
        while (access(parent_path.c_str(), F_OK) != 0 && parent_path != mount_point) {
            found = parent_relative_path.find_last_of("/");
            if (found == string::npos) {
                parent_relative_path = "";
                parent_path = mount_point;
            } else {
                parent_relative_path = parent_relative_path.substr(0, found);
                parent_path = mount_point + "/" + parent_relative_path;
            }
        }

        // if the parent exists, add state for it. if not, we're probably deleting a whole 
        // directory tree and have already handled the parent
        if (contents.find(parent_relative_path) != contents.end()) {
            if (contents[parent_relative_path].back()->present) {
                FileState* parent_state = new FileState();
                ret = parent_state->init_file_state(parent_path, false, false, false, diff_file);
                if (ret < 0) {
                    return ret;
                }
                if (contents.find(parent_relative_path) == contents.end()) {
                    vector<FileState*> new_vec = {parent_state};
                    contents[parent_relative_path] = new_vec;
                } else {
                    contents[parent_relative_path].push_back(parent_state);
                }
            }
        }
    }

    // the file state uses the absolute path to the file so it can 
    // actually find the file
    // kind of janky creation, but makes sure we can handle errors cleanly
    
    FileState* new_file_state = new FileState();
    ret = new_file_state->init_file_state(paths.canonical_path, del, fsync, fdatasync, diff_file);
    // diff_file.close();
    if (ret < 0) {
        return ret;
    }
    if (!del) {
        ino = new_file_state->statbuf.st_ino;
        if (inum_to_files.find(ino) == inum_to_files.end()) {
            set<string> new_set = {paths.relative_path};
            vector<set<string> > new_vec = {new_set};
            inum_to_files[ino] = new_vec;
        } else {
            set<string> new_set(inum_to_files[ino].back());
            new_set.insert(paths.relative_path);
            inum_to_files[ino].push_back(new_set);
        }
    }
    else { // del
        // get the inode number from the last real version of the file
        FileState* last_state = contents[paths.relative_path].back();
        ino = last_state->statbuf.st_ino;

        // if there are other files with this inode, update their oracle states so that 
        // they have the correct link count
        if (inum_to_files.find(ino) != inum_to_files.end()) {
            set<string> new_set = remove_file_from_inode(paths.relative_path, ino);
            if (!new_set.empty()) {
                for (set<string>::iterator it = new_set.begin(); it != new_set.end(); it++) {
                    struct paths ino_paths;
                    ret = get_paths(mount_point + "/" + *it, ino_paths, log);
                    if (ret < 0) {
                        log << "failed getting paths for " << *it << endl;
                        return ret;
                    }
                    ret = add_file_state(ino_paths, false, false, false, false, log, diff_file);
                    if (ret < 0) {
                        log << "failed updating state for " << ino_paths.relative_path << endl;
                        return ret;
                    }
                }
            }
        }
    }

    // save this version of the file
    if (contents.find(paths.relative_path) == contents.end()) {
        vector<FileState*> new_vec = {new_file_state};
        contents[paths.relative_path] = new_vec;
    } else {
        contents[paths.relative_path].push_back(new_file_state);
    }
    files.insert(paths.relative_path);

    return 0;
}

set<string> DiskState::remove_file_from_inode(string relative_path, int ino) {
    set<string> new_set(inum_to_files[ino].back());
    new_set.erase(relative_path);
    inum_to_files[ino].push_back(new_set);
    return new_set;
}

int DiskState::update_links(struct paths old_paths, struct paths new_paths, ofstream& log, ofstream& diff_file) {
    struct paths ino_paths;
    int ret;
    int ino = contents[old_paths.relative_path].back()->statbuf.st_ino;
    set<string> linked_files = inum_to_files[ino].back();

    for (set<string>::iterator it = linked_files.begin(); it != linked_files.end(); it++) {
        if (*it != old_paths.relative_path && *it != new_paths.relative_path) {
            ret = get_paths(mount_point + "/" + *it, ino_paths, log);
            if (ret < 0) {
                log << "failed getting paths for " << *it << endl;
                return ret;
            }
            ret = add_file_state(ino_paths, false, false, false, false, log, diff_file);
            if (ret < 0) {
                log << "failed updating state for " << ino_paths.relative_path << endl;
                return ret;
            }
        }
    }

    return 0;
}

void DiskState::sync() {
    for (set<string>::iterator it = files.begin(); it != files.end(); it++) {
        string relpath = *it;
        FileState* sync_state(contents[relpath].back());
        sync_state->fsynced = true;
        contents[relpath].push_back(sync_state);
    }
}

// op_completed is different from syscall_finished; syscall_finished just indicates that the system call has actually 
// run to completion, whereas op_completed indicates whether, from the main file's perspective, whether the operation
// seems to have completed or not
bool DiskState::check_parent(std::string relpath, ofstream& diff_file, ofstream& log, bool op_completed) {
    int ret;
    FileState *oracle_parent, *crash_parent;
    size_t found = relpath.find_last_of("/");
    // if found is string::npos, then there aren't any so the mount point is just the thing i guess
    string parent_relpath, crash_parent_path, oracle_parent_path;
    if (found == string::npos) {
        parent_relpath = "";
        crash_parent_path = replay_mount_point;
        oracle_parent_path = mount_point;
    } else {
        parent_relpath = relpath.substr(0, found);
        crash_parent_path = replay_mount_point + "/" + parent_relpath;
        oracle_parent_path = mount_point + "/" + parent_relpath;
    }

    if (op_completed) {
        oracle_parent = contents[parent_relpath].back();
    } else {
        size_t size = contents[parent_relpath].size();
        oracle_parent = contents[parent_relpath][size-2];
    }

    crash_parent = new FileState();
    ret = crash_parent->init_crash_file_state(crash_parent_path, diff_file);
    if (ret < 0) {
        // TODO: do we need to check eloop here? probably not?
        diff_file << "Failed reading " << crash_parent_path << endl;
        delete crash_parent;
        return false;
    }

    // TODO: it's possible that this is too strong of a check?
    bool states_match = oracle_parent->compare(crash_parent, diff_file);
    if (!states_match) {
        diff_file << "Parent directories " << crash_parent_path << " and " << oracle_parent_path << " do not match" << endl;
        delete crash_parent;
        return false;
    }
    delete crash_parent;
    return true;
}

bool DiskState::check_creat_and_mkdir(std::string path, ofstream& diff_file, ofstream& log, bool syscall_finished) {
    int ret;
    FileState crash_file_state, *oracle_file_state;
    bool present_in_crash_state = false;
    bool states_match = true;

    struct paths oracle_paths;
    ret = get_paths(path, oracle_paths, log);
    if (ret < 0) {
        return false;
    }
    
    // construct path to the file in the crash state
    // string relpath = path.substr(mount_point.size() + 1, string::npos);
    // string crash_path = replay_mount_point + "/" + relpath;
    string crash_path = replay_mount_point + "/" + oracle_paths.relative_path;
    oracle_file_state = contents[oracle_paths.relative_path].back();
    // attempt to construct a file state for this file
    ret = crash_file_state.init_crash_file_state(crash_path, diff_file);
    // if (ret == -ELOOP) {
    //     // check that attempting to access the oracle also results in ELOOP
    //     ret = access(oracle_file_state->path.c_str(), F_OK);
    //     // if so, we can't do any other checks
    //     if (ret < 0 && errno == ELOOP) {
    //         return true;
    //     }
    //     // if not, something is wrong
    //     else {
    //         diff_file << "accessing " << crash_path << " returns ELOOP but " << oracle_file_state->path << " does not" << endl;
    //         return false;
    //     }
    // }
    present_in_crash_state = ret >= 0 && crash_file_state.present;
    if (present_in_crash_state) {
        // if the file is present in the crash state, it should match the most recent version 
        // in the oracle.
        
        states_match = oracle_file_state->compare(&crash_file_state, diff_file);
    }

    // if something is wrong, print out more detailed information about failure
    if (syscall_finished) {
        if (!present_in_crash_state) {
            diff_file << "mkdir/creat operation completed, but " << crash_path << " not present" << endl;
            return false;
        }
    } 

    // if syscall isn't completed, then in order to pass, either:
    // - file is not present
    // - file is present and states match
    if (!(!present_in_crash_state || states_match)) {
        diff_file << "file is present but states do not match" << endl;
        return false;
    }
    // finally do a sanity check on the parent directory to make sure it looks right
    bool parent_ok = check_parent(oracle_paths.relative_path, diff_file, log, syscall_finished || present_in_crash_state);
    return parent_ok;
}

// TODO: check both parent directories
bool DiskState::check_rename(string old_path, string new_path, ofstream& diff_file, ofstream& log, bool syscall_finished) {
    bool crash_old_present = false, crash_new_present = false, states_match;
    int ret;
    FileState crash_state_new, crash_state_old, *oracle_state_new, *oracle_state_old;

    old_path = fix_filepath(old_path);
    new_path = fix_filepath(new_path);

    if (old_path == new_path) {
        return true;
    }

    string relpath_new = new_path.substr(mount_point.size() + 1, string::npos);
    string relpath_old = old_path.substr(mount_point.size() + 1, string::npos);
    string crash_new_path = replay_mount_point + "/" + relpath_new;
    string crash_old_path = replay_mount_point + "/" + relpath_old;

    size_t size = contents[relpath_old].size();
    oracle_state_new = contents[relpath_new].back();

    oracle_state_old = contents[relpath_old][size-2];
    ret = crash_state_new.init_crash_file_state(crash_new_path, diff_file);

    crash_new_present = ret >= 0 && crash_state_new.present;
    // although the old file will be deleted at some point during the operation, we'll set 
    // the deleted param to false here because if the file DOES exist, we want to get its
    // metadata.
    ret = crash_state_old.init_crash_file_state(crash_old_path, diff_file);
    crash_old_present = ret >= 0 && crash_state_old.present;

    // it's fine if just the old file is present. as a sanity check, make sure it matches the oracle
    // except what if the new file already existed?
    if (crash_old_present && !crash_new_present) {
        // if (oracle_state_new->present) {
        //     diff_file << crash_new_path << " existed prior to rename, but it is not present" << endl;
        //     return false;
        // }
        if (contents[relpath_new].size() > 2) {
            if (contents[relpath_new][contents[relpath_new].size()-2]->present) {
                diff_file << crash_new_path << " existed prior to rename, but it is not present" << endl;
                return false;
            }
        }
        states_match = oracle_state_old->compare(&crash_state_old, diff_file);
        if (!states_match) {
            diff_file << "Content mismatch of old file in rename operation on " << crash_old_path << endl;
            return false;
        }
    }

    if (crash_old_present && crash_new_present) {
        // this is legal if old and new files have the same inode 
        // (i.e. one is hard linked to the other) because apparently
        // that's how it works
        if (crash_state_new.statbuf.st_ino == crash_state_old.statbuf.st_ino) {
            return true;
        }
        // otherwise crash new and oracle new must be DISTINCT
        // (i.e., the rename has happened on the oracle, but 
        // it has not completed on the crash state yet)
        // if they're the same, something is wrong
        states_match = oracle_state_new->compare(&crash_state_new, diff_file);
        if (states_match) {
            diff_file << "Rename atomicity violation: " << crash_old_path << " and " << crash_new_path << " exist simultaneously" << endl;
            return false;
        }
    }
    // }

    // if only the new file is present in the crash state, we should make sure 
    // that it is NOT outdated - it MUST match the newest version of the new file in 
    // the oracle
    if (!crash_old_present && crash_new_present) {
        states_match = oracle_state_new->compare(&crash_state_new, diff_file);
        if (!states_match) {
            diff_file << "Rename atomicity violation: " << crash_old_path << " is gone but " << crash_new_path << " is not correct" << endl;
            return false;
        }
    }

    if (!crash_old_present && !crash_new_present) {
        diff_file << "Rename atomicity violation: neither " << crash_old_path << " nor " << crash_new_path << " is present in crash state" << endl;
        return false;
    }
    return true;
}

bool DiskState::check_exists(string path, ofstream& diff_file, ofstream& log, bool syscall_finished) {
    int ret;
    FileState crash_file_state, *oracle_file_state;
    path = fix_filepath(path);
    // TODO: more direct checks on if the file can be read? creating the file state should cover that i think

    // construct path to the file in the crash state
    string relpath = path.substr(mount_point.size() + 1, string::npos);
    string crash_path = replay_mount_point + "/" + relpath;
    oracle_file_state = contents[relpath].back();

    // attempt to construct a file state for this file
    ret = crash_file_state.init_crash_file_state(crash_path, diff_file);
    if (ret < 0 || !crash_file_state.present) {
        // if the file doesn't actually exist in the oracle, then it's legal
        // for the file to not exist in the crash state either
        if (!oracle_file_state->present) {
            return true;
        }
        diff_file << path << " does not exist in crash state" << endl;
        return false;
    }
    // check that the oracle state matches the crash state
    bool states_match = oracle_file_state->compare(&crash_file_state, diff_file);
    if (!states_match) {
        diff_file << crash_path << " does not match oracle " << path << endl;
        return false;
    }

    return true;
}

bool DiskState::check_generic(string path, ofstream& diff_file, ofstream& log, bool syscall_finished) {
    int ret;
    FileState crash_file_state, *oracle_file_state_new, *oracle_file_state_old;
    path = fix_filepath(path);
    // construct path to the file in the crash state
    string relpath;
    if (path.compare(mount_point) == 0) {
        relpath = "";
    } else {
        relpath = path.substr(mount_point.size() + 1, string::npos);
    }
    string crash_path = replay_mount_point + "/" + relpath;

    int num_oracle_states = contents[relpath].size();

    if (num_oracle_states < 2) {
        log << "Something is wrong, not enough oracle states for " << path << endl;
        return false;
    }
    // what do we want to check? file exists, file size either matches old or new state
    // there are two valid oracle states to check against, the current one or the prior one
    oracle_file_state_new = contents[relpath][num_oracle_states-1];
    oracle_file_state_old = contents[relpath][num_oracle_states-2];

    // attempt to construct a file state for this file
    ret = crash_file_state.init_crash_file_state(crash_path, diff_file);
    if (ret < 0 || !crash_file_state.present) {
        // if the file has been deleted in the oracle, it's fine if it's 
        // not present in the crash state
        if (!oracle_file_state_new->present) {
            return true;
        }
        diff_file << path << " does not exist in crash state" << endl;
        return false;
    }

    // the crash state should exactly match either the old or new oracle state
    bool states_match_old = oracle_file_state_old->compare(&crash_file_state, diff_file);
    bool states_match_new = oracle_file_state_new->compare(&crash_file_state, diff_file);
    // if the syscall is finished, then we must match the new state
    if (syscall_finished && !states_match_new) {
        diff_file << "Operation completed, but " << crash_path << " does not match oracle" << endl;
        return false;
    }

    // should match either new or old state
    if (!states_match_new && !states_match_old) {
        diff_file << crash_path << " does not match a valid crash state" << endl;
        return false;
    }

    return true;
}

bool DiskState::check_write(string path, ofstream& diff_file, ofstream& log, bool syscall_finished, bool atomic) { 
    int ret;
    FileState crash_file_state, *oracle_file_state_new, *oracle_file_state_old;
    // if we expect writes to be atomic, we can do a normal atomicity check
    if (atomic || syscall_finished) {
        return check_generic(path, diff_file, log, syscall_finished);
    }
    // else, we can only do weaker checks. make sure that the file exists and 
    // fields that shouldn't change, like inode and numlinks, are correct
    path = fix_filepath(path);

    // construct path to the file in the crash state
    string relpath = path.substr(mount_point.size() + 1, string::npos);
    string crash_path = replay_mount_point + "/" + relpath;
    // attempt to construct a file state for this file
    ret = crash_file_state.init_crash_file_state(crash_path, diff_file);
    if (ret < 0 || !crash_file_state.present) {
        diff_file << path << " does not exist in crash state" << endl;
        return false;
    }

    int num_oracle_states = contents[relpath].size();
    if (num_oracle_states < 2) {
        log << "Something is wrong, not enough oracle states for " << path << endl;
        return false;
    }
    oracle_file_state_new = contents[relpath][num_oracle_states-1];
    oracle_file_state_old = contents[relpath][num_oracle_states-2];

    // check the stat fields that we can (ino, link count, etc.)
    bool retval = crash_file_state.statbuf.st_ino == oracle_file_state_new->statbuf.st_ino &&
            crash_file_state.statbuf.st_ino == oracle_file_state_old->statbuf.st_ino &&
            crash_file_state.statbuf.st_nlink == oracle_file_state_new->statbuf.st_nlink &&
            crash_file_state.statbuf.st_nlink == oracle_file_state_old->statbuf.st_nlink &&
            crash_file_state.statbuf.st_mode == oracle_file_state_new->statbuf.st_mode &&
            crash_file_state.statbuf.st_mode == oracle_file_state_old->statbuf.st_mode &&
            crash_file_state.statbuf.st_uid == oracle_file_state_new->statbuf.st_uid &&
            crash_file_state.statbuf.st_uid == oracle_file_state_old->statbuf.st_uid &&
            crash_file_state.statbuf.st_gid == oracle_file_state_new->statbuf.st_gid &&
            crash_file_state.statbuf.st_gid == oracle_file_state_old->statbuf.st_gid;
    return retval;
}

bool DiskState::check_remove(string path, ofstream& diff_file, ofstream& log, bool syscall_finished) {
    int ret;
    FileState crash_file_state, *oracle_file_state;
    path = fix_filepath(path);

    // construct path to the file in the crash state
    string relpath = path.substr(mount_point.size() + 1, string::npos);
    string crash_path = replay_mount_point + "/" + relpath;

    ret = crash_file_state.init_crash_file_state(crash_path, diff_file);
    bool crash_present = ret >= 0 && crash_file_state.present;

    if (syscall_finished && crash_present) {
        diff_file << crash_path << " is present but has been deleted" << endl;
        return false;
    }

    if (crash_present) {
        int num_oracle_states = contents[relpath].size();
        oracle_file_state = contents[relpath][num_oracle_states-2];

        bool states_match = oracle_file_state->compare(&crash_file_state, diff_file);
        if (!states_match) {
            diff_file << crash_path << " does not match oracle " << path << endl;
            return false;
        }
    } 

    // make sure the parents are right
    bool parent_ok = check_parent(relpath, diff_file, log, syscall_finished || !crash_present);

    return parent_ok;
}

bool DiskState::check_link(string target, string linkpath, ofstream& diff_file, ofstream& log, bool syscall_finished) {
    bool link_present, states_match, op_completed;
    int ret;
    FileState crash_state_target, crash_state_link, *oracle_state_target, *oracle_state_link;

    target = fix_filepath(target);
    linkpath = fix_filepath(linkpath);

    string relative_target = target.substr(mount_point.size() + 1, string::npos);
    string relative_linkpath = linkpath.substr(mount_point.size() + 1, string::npos);
    string crash_target = replay_mount_point + "/" + relative_target;
    string crash_linkpath = replay_mount_point + "/" + relative_linkpath;

    // hard link creation fails if there is already a file at the linkpath,
    // so we can assume that if the linkpath file exists, the link has completed
    ret = crash_state_link.init_crash_file_state(crash_linkpath, diff_file);
    link_present = ret >= 0 && crash_state_link.present;

    if (syscall_finished && !link_present) {
        diff_file << "link operation completed but linkpath " << crash_linkpath << " is not present" << endl;
        return false;
    }

    if (link_present) {
        ret = crash_state_target.init_crash_file_state(crash_target, diff_file);
        if (ret < 0) {
            diff_file << "link target " << crash_target << " does not exist" << endl;
            return false;
        }
        // if the link is present, the operation should be completed - compare 
        // against the newest version of the oracle
        oracle_state_target = contents[relative_target].back();
        oracle_state_link = contents[relative_linkpath].back();

        states_match = oracle_state_target->compare(&crash_state_target, diff_file);
        if (!states_match) {
            diff_file << target << " and " << crash_target << " do not match" << endl;
            return false;
        }
        states_match = oracle_state_link->compare(&crash_state_link, diff_file);
        if (!states_match) {
            diff_file << linkpath << " and " << crash_linkpath << " do not match" << endl;
            return false;
        }
        op_completed = true;
    } else {
        // the linkpath file is not present, so the operation has not completed. we should not see any effects from it
        // the target should exist though
        ret = crash_state_target.init_crash_file_state(crash_target, diff_file);
        if (ret < 0) {
            diff_file << "link target " << crash_target << " does not exist" << endl;
            return false;
        }

        int target_oracle_states = contents[relative_target].size();
        oracle_state_target = contents[relative_target][target_oracle_states-2];

        
        states_match = oracle_state_target->compare(&crash_state_target, diff_file);
        if (!states_match) {
            diff_file << target << " and " << crash_target << " do not match" << endl;
            diff_file << "failed in check_link" << endl;
            return false;
        }
        op_completed = false;
    }
    // check parent state
    bool parent_ok = check_parent(relative_linkpath, diff_file, log, op_completed);
    if (!parent_ok) {
        return false;
    }

    return true;
}

bool DiskState::check_files(utils::DiskMod mod, map<string, map<int, int> > path_fd_map, map<int,int> fd_ino_map, ofstream& diff_file, ofstream& log) {
    // this function should check all of the files that are NOT touched by
    // the system call we crashed during. there are other checks for those calls
    int ret;
    size_t found;
    struct paths mod_path;
    set<string> skip_files, linked_files1, new_linked_files;
    int old_file_inode = -1;
    // assume that no files will be named NONE so that we can differentiate between 
    // lack of a file to skip and the root directory
    string crash_mod_path = "NONE", crash_parent = "NONE", crash_mod_new_path = "NONE", crash_new_parent = "NONE";
    string oracle_mod_new_path;
    // first figure out some paths to AVOID checking (specifically the paths 
    // modified by this mod, including potentially parents)
    if (mod.path != "") {
        ret = get_paths(mod.path, mod_path, log);
        if (ret < 0) {
            log << "Error getting path for " << mod.path << " in check_files" << endl;
            return false;
        }
        crash_mod_path = replay_mount_point + "/" + mod_path.relative_path;
        if (mod.return_value >= 0) {
            if (mod.mod_type == utils::DiskMod::kCreateMod || mod.mod_type == utils::DiskMod::kRemoveMod || mod.mod_type == utils::DiskMod::kRenameMod) {
                found = mod_path.relative_path.find_last_of("/");
                if (found == string::npos) {
                    crash_parent = replay_mount_point + "/";
                } else {
                    crash_parent = replay_mount_point + "/" + mod_path.relative_path.substr(0, found);
                }
            }

            if (mod.mod_type == utils::DiskMod::kRenameMod || mod.mod_type == utils::DiskMod::kLinkMod) {
                ret = get_paths(mod.new_path, mod_path, log);
                if (ret < 0) {
                    log << "Error getting path for " << mod.new_path << " in check_files" << endl;
                    return false;
                }
                crash_mod_new_path = replay_mount_point + "/" + mod_path.relative_path;
                string oracle_mod_new_path = replay_mount_point + "/" + mod_path.relative_path;

                found = mod_path.relative_path.find_last_of("/");
                if (found == string::npos) {
                    crash_new_parent = replay_mount_point + "/";
                } else {
                    crash_new_parent = replay_mount_point + "/" + mod_path.relative_path.substr(0, found);
                }
            }
        }

        // if the mod is a remove: check if the file being removed still exists 
        // in the crash state
        skip_files.insert(crash_mod_path);
        skip_files.insert(crash_parent);
        skip_files.insert(crash_mod_new_path);
        skip_files.insert(crash_new_parent);


        if (path_fd_map.find(mod_path.relative_path) != path_fd_map.end() &&
            path_fd_map[mod_path.relative_path].find(mod.fd) != path_fd_map[mod_path.relative_path].end()){
            // if the file has any open file descriptors, those are what we should use 
            // to determine linkage
            int fd = path_fd_map[mod_path.relative_path][mod.fd];
            int ino = fd_ino_map[fd];
            old_file_inode = ino;
            linked_files1 = inum_to_files[ino].back();
        } else {
            ret = access(crash_mod_path.c_str(), F_OK);
            if (ret == 0) {
                // if the file exists, we should check the second most recent version of 
                // any files that are linked to crash_mod_path
                // get the file's ino
                struct stat statbuf;
                ret = lstat(crash_mod_path.c_str(), &statbuf);
                if (ret < 0) {
                    log << "error stat-ing " << crash_mod_path << endl;
                    perror("lstat");
                    return false;
                }
                int size = inum_to_files[statbuf.st_ino].size();
                old_file_inode = statbuf.st_ino;
                if (mod.mod_type == utils::DiskMod::kRemoveMod || mod.mod_type == utils::DiskMod::kRenameMod) {
                    if (size < 2) {
                        log << "not enough records in inum_to_files" << endl;
                        return false;
                    }
                    linked_files1 = inum_to_files[statbuf.st_ino][size-2];
                } else if (size >= 1) {
                    linked_files1 = inum_to_files[statbuf.st_ino].back();
                }
            }  else {
                // find the file's old inode in the oracle, and use that to 
                // determine the linked files
                // TODO: this might not always work if the file was unlinked and linked 
                // files were subsequently changed via file descriptor....
                int num_states = contents[mod_path.relative_path].size();
                if (num_states > 1) {
                    for (int i = num_states-1; i >= 0; i--) {
                        FileState* path_oracle = contents[mod_path.relative_path][i];
                        if (path_oracle->present) {
                            int ino = path_oracle->statbuf.st_ino;
                            int size = inum_to_files[ino].size();
                            if (size >= 2) {
                                linked_files1 = inum_to_files[ino][size-2]; 
                            }
                            old_file_inode = ino;
                            break;
                        }
                    }
                }
            }
        }

        // if the operation is a rename and the new file already existed, we need to account 
        // for the old file and the new file's links
        if (mod.mod_type == utils::DiskMod::kRenameMod && crash_mod_path.compare(crash_mod_new_path) != 0) {
            // the new path exists (but it may be an old version of the file, not the renamed file)
            // so get that file's links and add them to the link set
            struct stat statbuf;
            ret = lstat(crash_mod_new_path.c_str(), &statbuf);
            if (ret >= 0) {
                int size = inum_to_files[statbuf.st_ino].size();
                if (size < 2) {
                    // log << "not enough records in inum_to_files " << size << endl;
                    // return false;
                    new_linked_files = inum_to_files[statbuf.st_ino].back();
                } else {
                    ret = get_paths(mod.new_path, mod_path, log);
                    if (ret < 0) {
                        log << "Error getting path for " << mod.new_path << " in check_files" << endl;
                        return false;
                    }
                    // in this case, if the rename caused a file overwrite, we have to consider the OLD 
                    // file's links
                    set<string> temp;
                    for (int i = contents[mod_path.relative_path].size() - 1; i >= 0; i--) {
                        FileState* cur = contents[mod_path.relative_path][i];
                        if (cur->present && cur->statbuf.st_ino != old_file_inode) {
                            size = inum_to_files[cur->statbuf.st_ino].size();
                            if (size < 2) {
                                temp = inum_to_files[cur->statbuf.st_ino].back();
                            } else {
                                temp =  inum_to_files[cur->statbuf.st_ino][size-2];
                            }
                            break;
                        }
                    }
                    size = inum_to_files[statbuf.st_ino].size();
                    new_linked_files = inum_to_files[statbuf.st_ino][size-2];
                    for (set<string>::iterator it = temp.begin(); it != temp.end(); it++) {
                        new_linked_files.insert(*it);
                    }
                }
            }
            // if the new file does not exist, we just have to account for the old file's links,
            // which we have already done
        }
    }

    set<string> linked_files;
    // janky set union
    for (set<string>::iterator it = linked_files1.begin(); it != linked_files1.end(); it++) {
        linked_files.insert(*it);
    }
    for (set<string>::iterator it = new_linked_files.begin(); it != new_linked_files.end(); it++) {
        linked_files.insert(*it);
    }

    // ok now go through the whole file tree and make sure everything looks right 
    // for all files that are NOT in the skip list
    return check_file("", skip_files, linked_files, diff_file, log);
    
}

// the paths passed in here should be relative to the mount point
bool DiskState::check_file(string path, set<string> skip_files, set<string> linked_files, ofstream& diff_file, ofstream& log) {
    bool ret;
    FileState crash_state, *oracle_state;
    if (path[0] == '/') {
        path = path.substr(1, string::npos);
    }

    if (linked_files.find(path) != linked_files.end()) {
        // skip files that are linked to the current file
        return true;
    } else {
        oracle_state = contents[path].back();
    }

    if (skip_files.find(replay_mount_point + "/" + path) == skip_files.end()) {
        // create a crash state for this file
        // we don't really care about the return value here; if there is an issue 
        // it should get caught when we do the compare
        crash_state.init_crash_file_state(replay_mount_point + "/" + path, diff_file);
        ret = oracle_state->compare(&crash_state, diff_file);
        if (!ret) {
            diff_file << "compare in check file on " << crash_state.path << " failed" << endl;
            return false;
        }

        // this should always be true, but just in case
        if (oracle_state->present) {
            string full_path = mount_point + "/" + path;

            // if this file is a directory, traverse all of its entries
            // if we find an error, return false immediately
            if (S_ISDIR(oracle_state->statbuf.st_mode)) {
                DIR* directory = opendir(full_path.c_str());
                if (directory == NULL) {
                    cout << "could not open directory " << full_path << endl;
                    diff_file << "could not open directory " << full_path << endl;
                    return false;
                }

                struct dirent* dir_entry;
                while ((dir_entry = readdir(directory))) {
                    if ((strcmp(dir_entry->d_name, ".") == 0) ||
                        (strcmp(dir_entry->d_name, "..") == 0)) {
                        continue;
                    }

                    string subpath = path + "/" + string(dir_entry->d_name);
                    ret = check_file(subpath, skip_files, linked_files, diff_file, log);
                    if (!ret) {
                        closedir(directory);
                        return false;
                    }
                }
                closedir(directory);
            }
        } 
    }
    return true;
}

bool DiskState::check_disk_contents(string crash_mount_path, string crash_dev_path, ofstream& diff_file, ofstream& log) {
    int ret;
    bool match;
    // walk through the crash state and grab the state of each file that is present
    DiskState crash_state(crash_dev_path, crash_mount_path, "");
    struct paths root_path = {crash_mount_path, ""};

    // add state for the root 
    ret = crash_state.add_file_state(root_path, false, false, false, false, log, diff_file);
    if (ret < 0) {
        return false;
    }
    
    // then for the rest of the crash state contents
    ret = crash_state.get_crash_disk_contents(crash_mount_path, diff_file, log);
    if (ret < 0) {
        return false;
    }

    // compare the crash state against the oracle state (self)
    // iterate over the oracle state, since it should contain a superset of the files in 
    // the crash state as it contains records for ALL files that have existed at any point
    map<string, vector<FileState*>>::iterator it;
    for (it = contents.begin(); it != contents.end(); it++) {
        // remember: string keys in the map are relative paths
        string relative_path = it->first;
        FileState* oracle_file_state = it->second.back();
        FileState* crash_file_state;

        if (oracle_file_state->present) {
            if (crash_state.contents.count(relative_path) == 0) {
                diff_file << mount_point + "/" + relative_path << " is present in the oracle but not in the crash state" << endl;
                return false;
            } 
            crash_file_state = crash_state.contents[relative_path].back();
            match = oracle_file_state->compare(crash_file_state, diff_file);
            if (!match) {
                return false;
            }
        }
    }

    // sanity check to make sure the crash state doesn't contain any files 
    // that the oracle doesn't have
    for (it = crash_state.contents.begin(); it != crash_state.contents.end(); it++) {
        string relative_path = it->first;
        if (contents.count(relative_path) == 0 || !contents[relative_path].back()->present) {
            diff_file << mount_point + "/" + relative_path << " is present in the crash state but not in the oracle" << endl;
            return false;
        }
    }

    return true;
}

// should only be called on crash state
int DiskState::get_crash_disk_contents(string path, ofstream& diff_file, ofstream& log) {
    DIR *directory;
    struct dirent *dir_entry;
    struct stat statbuf;
    int ret;

    directory = opendir(path.c_str());
    if (directory == NULL) {
        return 0;
    }
    dir_entry = readdir(directory);
    if (dir_entry == NULL) {
        closedir(directory);
        return 0;
    }
    do {
        // this is pretty much taken verbatim from crashmonkey with adjustments
        // for our file state management
        string parent_path(path);
        string filename(dir_entry->d_name);
        string current_path = parent_path + "/" + filename;
        string relative_path = current_path;
        relative_path.erase(0, mount_point.length()+1);

        ret = lstat(current_path.c_str(), &statbuf);
        if (ret < 0) {
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            
            if ((strcmp(dir_entry->d_name, ".") == 0) || (strcmp(dir_entry->d_name, "..") == 0) ||
                (strcmp(dir_entry->d_name, "lost+found") == 0)) {
                continue;
            }
            struct paths paths = {current_path, relative_path};
            ret = add_file_state(paths, false, false, false, false, log, diff_file);
            if (ret < 0) {
                log << "failed getting oracle state" << endl;
                return ret;
            }
            ret = get_crash_disk_contents(current_path, diff_file, log);
            if (ret < 0) {
                return ret;
            }
        } else {
            struct paths paths = {current_path, relative_path};
            ret = add_file_state(paths, false, false, false, false, log, diff_file);
            if (ret < 0) {
                log << "failed getting oracle state" << endl;
                return ret;
            }
        }
    } while ((dir_entry = readdir(directory)));
    

    closedir(directory);
    return 0;
}

// TODO: could miss some bugs in the sync file data range case - but do we ever actually do that?
bool DiskState::check_file_contents_range(string path, int offset, int length, ofstream& diff_file, ofstream& log) {
    int ret;
    struct stat statbuf;
    FileState crash_state, *oracle_file_state_new, *oracle_file_state_old;
    string relpath;
    path = fix_filepath(path);
    // construct path to the file in the crash state
    if (path.compare(mount_point) == 0) {
        relpath = "";
    } else {
        relpath = path.substr(mount_point.size() + 1, string::npos);
    }
    string crash_path = replay_mount_point + "/" + relpath;

    // check that the file is still present in the oracle
    // it may have been deleted prior to the fsync/sync/datasync
    // int 
    // oracle_state = contents[relpath].back();
    // if (!oracle_state->present) {
    //     // make sure that the file is not present in the crash state either
    //     ret = lstat(crash_path.c_str(), &statbuf);
    //     if (ret == 0) {
    //         diff_file << crash_path << "exists in the crash state, but " << path << " does not exist in the oracle" << endl;
    //         return false;
    //     }
    //     return true;
    // }

    int num_oracle_states = contents[relpath].size();
    if (num_oracle_states < 2) {
        log << "Something is wrong, not enough oracle states for " << path << endl;
        return false;
    }
    oracle_file_state_new = contents[relpath][num_oracle_states-1];
    oracle_file_state_old = contents[relpath][num_oracle_states-2];


    ret = crash_state.init_crash_file_state(crash_path, diff_file);
    if (ret < 0) {
        log << "failed getting crash state" << endl;
        return false;
    }

    bool match_old = oracle_file_state_old->compare_at_offset(&crash_state, offset, length, diff_file);
    bool match_new = oracle_file_state_new->compare_at_offset(&crash_state, offset, length, diff_file);
    cout << "match old: " << match_old << endl;
    cout << "match new: " << match_new << endl;

    if (!match_old && !match_new) {
        return false;
    }

    return true;
}


} // namespace fs_testing