#ifndef DISK_CONTENTS_H
#define DISK_CONTENTS_H

#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace fs_testing {

struct file_content_diff {
  std::string path;
  int length;
  char* buffer_f1;
  char* buffer_f2;
};

class fileAttributes {
public:
  struct dirent dir_attr;
  struct stat stat_attr;
  std::string md5sum;

  fileAttributes();
  ~fileAttributes();

  void set_dir_attr(struct dirent* a);
  void set_stat_attr(std::string path, bool islstat);
  int set_attr(std::string path, std::ofstream& diff);
  void set_md5sum(std::string filepath);
  bool compare_dir_attr(struct dirent a);
  bool compare_stat_attr(struct stat a);
  bool compare_md5sum(std::string a);
  bool is_regular_file();
};

class DiskContents {
public:
  // Constructor and Destructor
  DiskContents(std::string path, std::string type);
  ~DiskContents();
  
  int mount_disk(std::string opts);
  std::string get_mount_point();
  void set_mount_point(std::string path);
//   int unmount_and_delete_mount_point();
  int unmount_disk();
  bool compare_disk_contents(DiskContents &compare_disk, std::ofstream &diff_file, std::string opts);
  bool compare_entries_at_path(DiskContents &compare_disk, std::string &path,
    std::ofstream &diff_file, bool print_err);
  // bool compare_file_contents(DiskContents &compare_disk, std::string path,
  //   int offset, int length, std::ofstream &diff_file);
  bool compare_file_contents(std::string oracle_file, std::string path, int offset, int length, std::ofstream &diff_file);
  bool compare_file_contents2(DiskContents &compare_disk, std::string path,
    int offset, int length, std::ofstream &diff_file, std::string opts);
  bool deleteFiles(std::string path, std::ofstream &diff_file);
  bool makeFiles(std::string base_path, std::ofstream &diff_file);
  bool sanity_checks(std::ofstream &diff_file);

  bool check_creat_and_mkdir(DiskContents &oracle, std::string path, std::ofstream &diff_file, bool syscall_finished);
  bool check_truncate(DiskContents &oracle, std::string path, fileAttributes fa, std::ofstream &diff_file, bool syscall_finished);

  struct file_content_diff content_diff;

private:
  bool device_mounted;
  std::string disk_path;
  std::string mount_point;
  std::string fs_type;
  std::map<std::string, fileAttributes> contents;
  void compare_contents(DiskContents &compare_disk, std::ofstream &diff_file);
  void get_contents(const char* path);
};

} // namespace fs_testing

#endif // DISK_CONTENTS_H
