#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <cassert>
#include <fcntl.h>
#include <dirent.h>
#include <string>
#include <fstream>
#include <string.h>
#include <set>
#include <sys/wait.h>
// #include <sstream>

#include "FileState.h"
#include "helpers.h"

using namespace std;
using namespace fs_testing;

FileState::FileState() {}

FileState::FileState(const FileState &old) {
    path = old.path;
    statbuf = old.statbuf;
    present = old.present;
    fsynced = old.fsynced;
    fdatasynced = old.fdatasynced;
    contents = old.contents;
    content_hash = old.content_hash;
    seq_num = old.seq_num + 1;
}

FileState::~FileState() {}

FileState FileState::operator=(const FileState& f) {
    path = f.path;
    statbuf = f.statbuf;
    present = f.present;
    fsynced = f.fsynced;
    fdatasynced = f.fdatasynced;
    contents = f.contents;
    content_hash = f.content_hash;
    seq_num = f.seq_num;
    return *this;
}

std::ofstream& operator<< (std::ofstream& os, struct stat& f) {
  os << "---File Stat Atrributes---" << endl;
  os << "Inode     : " << f.st_ino << endl;
  os << "TotalSize : " << f.st_size << endl;
  os << "BlockSize : " << f.st_blksize << endl;
  os << "#Blocks   : " << f.st_blocks << endl;
  os << "#HardLinks: " << f.st_nlink << endl;
  os << "Mode      : " << f.st_mode << endl;
  os << "User ID   : " << f.st_uid << endl;
  os << "Group ID  : " << f.st_gid << endl;
  os << "Device ID : " << f.st_rdev << endl;
  os << "RootDev ID: " << f.st_dev << endl;
  return os;
}


int FileState::set_stat() {
    int ret;
    errno = 0;
    ret = lstat(path.c_str(), &statbuf);
    return ret;
}

int FileState::set_content_hash(ofstream& diff_file) {
    // first check that we can read from the file
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        diff_file << "Cannot open " << path << ": " << strerror(errno) << endl;
        return fd;
    }
    // attempt to read the file
    char buf[32];
    int ret = pread(fd, buf, 32, 0);
    if (ret < 0) {
        diff_file << "Cannot read " << path << ": " << strerror(errno) << endl;
        close(fd);
        return false;
    }
    close(fd);


    // read the file. assumes we have already called lstat and can get 
    // the total size from there
    string contents_str;
    FILE *fp;
    char md5[100];

    string command = "md5sum " + path;
    fp = popen(command.c_str(), "r");
    fscanf(fp, "%s", md5);
    ret = pclose(fp);
    if (ret != 0) {
        diff_file << "md5sum on " << path << " failed; file is not readable" << endl;
        return -1;
    }
    content_hash = string(md5);
    return ret;
}

int FileState::init_crash_file_state(string p, ofstream& diff_file) {
    int ret;
    path = p;
    fsynced = false;
    fdatasynced = false;
    symlink = false;
    symlink_cycle = false;
    present = true;
    memset(&statbuf, 0, sizeof(struct stat));

    ret = access(p.c_str(), F_OK);
    if (ret < 0) {
        present = false;
        if (errno == ELOOP) {
            return -ELOOP;
        } else {
            return 0;
        }
    }

    if (present) {
        return set_up_state(p, diff_file);
    }

    return 0;
}

int FileState::init_file_state(string p, bool deleted, bool fsync, bool fdatasync, ofstream& diff_file) {
    path = fix_filepath(p);
    present = !deleted;
    fsynced = fsync;
    fdatasynced = fdatasync;
    symlink = false;
    symlink_cycle = false;
    memset(&statbuf, 0, sizeof(struct stat));
    if (present) {
        return set_up_state(path, diff_file);
    }
    return 0;
}

int FileState::set_up_state(string p, ofstream& diff_file) {
    int ret;
    errno = 0;
    ret = set_stat();
    if (ret < 0) {
        if (errno == ELOOP) {
            symlink_cycle = true;
        }
        else {
            if (errno != ENOENT) {
                diff_file << "Unable to stat file " << p << ": " << strerror(errno) << endl;
            }
            return ret;
        }
    }
    // save the contents of the file in some way
    // TODO: are these the best pieces of information to save?
    if (symlink_cycle) {
        return 0;
    }
    else if (S_ISDIR(statbuf.st_mode)) {
        content_hash = "";
        DIR *dir;
        struct dirent *ent;
        dir = opendir(path.c_str());
        if (dir != NULL) {
            while ((ent = readdir(dir)) != NULL) {
                contents.insert(ent->d_name);
            }
        } else {
            perror("opendir");
            return -1;
        }
        closedir(dir);
    } else if (S_ISLNK(statbuf.st_mode)) {
        // assume that the provided path is absolute and obtain its mount point
        assert(path[0] == '/');
        string mount_point = "";
        size_t cur_index = 0;
        size_t count = 0;
        // we want to stop on the third /
        while (cur_index < path.size()) {
            if (path[cur_index] == '/') {
                count++;
            }
            if (count == 3) {
                break;
            }
            cur_index++;
        }
        mount_point = path.substr(0, cur_index+1);

        char pathbuf[4096];
        memset(pathbuf, 0, 4096);
        symlink = true;
        ret = readlink(p.c_str(), pathbuf, 4096);
        if (ret < 0) {
            if (errno == ELOOP) {
                link_target = "";
                symlink_cycle = true;
                return 0;
            }
            perror("readlink");
            return ret;
        }
        // this may be broken; that's fine, we don't really care
        // we'll save a simplified version of the filepath (i.e. without ..'s)
        // so that we can manage it more easily 
        // link_target = fix_filepath(fix_symlink_target(string(pathbuf), mount_point));
        link_target = fix_filepath(fix_symlink_target(string(pathbuf), mount_point));
        // link_target = fix_filepath(string(pathbuf));
    } else {
        // read the file and get a hash of its content
        ret = set_content_hash(diff_file);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

bool FileState::compare(FileState* compare_state, ofstream& diff_file) {
    if (present != compare_state->present) {
        if (present) {
            diff_file << path << " is present but " << compare_state->path << " is not" << endl;
        } else {
            diff_file << compare_state->path << " is present but " << path << " is not" << endl;
        }
        return false;
    }
    else if (!present) {
        return true;
    }

    if (!contents.empty() || !compare_state->contents.empty()) {
        if (contents.size() != compare_state->contents.size()) {
            diff_file << "oracle has more directory entries than the crash" << endl;
            diff_file << path << " has " << contents.size() << " directory entries and " << compare_state->path << " has " << compare_state->contents.size() << endl;
            diff_file << path << ": " << endl;
            for (auto entry : contents) {
            // for (set<string>::iterator it = contents.begin(); it != contents.end(); it++) {}
                diff_file << "\t" << entry << endl;
            }
            diff_file << compare_state->path << ": " << endl;
            for (auto entry : compare_state->contents) {
                diff_file << "\t" << entry << endl;
            }

            return false;
        }
        if (contents != compare_state->contents) {
            diff_file << "crash has more directory entries than the oracle" << endl;
            diff_file << path << " and " << compare_state->path << " do not have the same directory entries" << endl;
            diff_file << path << ": " << endl;
            for (auto entry : contents) {
                diff_file << "\t" << entry << endl;
            }
            diff_file << compare_state->path << ": " << endl;
            for (auto entry : compare_state->contents) {
                diff_file << "\t" << entry << endl;
            }
            return false;
        }
    }
    
    bool match = (statbuf.st_ino == compare_state->statbuf.st_ino) &&
            (statbuf.st_mode == compare_state->statbuf.st_mode) &&
            (statbuf.st_nlink == compare_state->statbuf.st_nlink) &&
            (statbuf.st_uid == compare_state->statbuf.st_uid) &&
            (statbuf.st_gid == compare_state->statbuf.st_gid) &&
            (statbuf.st_size == compare_state->statbuf.st_size) &&
            (statbuf.st_blksize == compare_state->statbuf.st_blksize);// &&
            // (statbuf.st_blocks == compare_state->statbuf.st_blocks);
            // TODO: we should check block # unless there has been a fallocate....
            // it looks like FALLOC_FL_KEEP_SIZE blocks are dropped at umount,
            // which makes things a lot harder for us. so don't check block size for now
    if (!match) {
        diff_file << "Stat mismatch" << endl;
        diff_file << path << ": " << endl;
        diff_file << statbuf << endl;
        diff_file << compare_state->path << ": " << endl;
        diff_file << compare_state->statbuf << endl;
        return false;
    }
    // TODO: if this fails, give more info about the difference
    if (content_hash.compare(compare_state->content_hash) != 0) {
        diff_file << "Content hash mismatch between " << path << " and " << compare_state->path << endl;
        diff_file << "oracle hash for " << compare_state->path << ": " << compare_state->content_hash << endl;
        diff_file << "crash hash for " << path << ":" << content_hash << endl;
        return false;
    }
    return true;
}

// based on crashmonkey's compare_file_contents
bool FileState::compare_at_offset(FileState* compare_state, int offset, int len, ofstream& diff_file) {
    string oracle_path = path;
    string crash_path = compare_state->path;
    char oracle_buf[len + 1];
    char crash_buf[len + 1];
    int ret;

    ifstream oracle_f(oracle_path, std::ios::binary);
    ifstream crash_f(crash_path, std::ios::binary);

    if (!oracle_f) {
        diff_file << "Error opening input file stream " << oracle_path << endl;;
        return false;
    } 
    if (!crash_f) {
        diff_file << "Error opening input file stream " << crash_path << endl;
        return false;
    }

    oracle_f.seekg(offset, ifstream::beg);
    crash_f.seekg(offset, ifstream::beg);

    oracle_f.read(oracle_buf, len);
    crash_f.read(crash_buf, len);

    oracle_f.close();
    crash_f.close();

    oracle_buf[len] = '\0';
    crash_buf[len] = '\0';

    ret = strcmp(oracle_buf, crash_buf);
    if (ret == 0) {
        return true;
    }

    diff_file << "Content mismatch in " << path << endl;
    diff_file << "Offset " << offset << ", length " << len << endl;
    diff_file << oracle_path << " has " << oracle_buf << endl;
    diff_file << crash_path << " has " << crash_buf << endl;
    return false;
}
