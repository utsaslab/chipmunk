#include "DiskContents.h"
#include <cassert>

using std::endl;
using std::cout;
using std::string;
using std::ofstream;

namespace fs_testing {

fileAttributes::fileAttributes() {
  md5sum = "";
  // Initialize dir_attr entries
  dir_attr.d_ino = -1;
  dir_attr.d_off = -1;
  dir_attr.d_reclen = -1;
  dir_attr.d_type = -1;
  dir_attr.d_name[0] = '\0';
  // Initialize stat_attr entried
  stat_attr.st_ino == -1;
  stat_attr.st_mode = -1;
  stat_attr.st_nlink = -1;
  stat_attr.st_uid = -1;
  stat_attr.st_gid = -1;
  stat_attr.st_size = -1;
  stat_attr.st_blksize = -1;
  stat_attr.st_blocks = -1;
}

fileAttributes::~fileAttributes() {
}

void fileAttributes::set_dir_attr(struct dirent* a) {
  dir_attr.d_ino = a->d_ino;
  dir_attr.d_off = a->d_off;
  dir_attr.d_reclen = a->d_reclen;
  dir_attr.d_type = a->d_type;
  strncpy(dir_attr.d_name, a->d_name, sizeof(a->d_name));
  dir_attr.d_name[sizeof(a->d_name) - 1] = '\0';
}

void fileAttributes::set_stat_attr(string path, bool islstat) {
  if (islstat) {
    lstat(path.c_str(), &stat_attr);
  } else {
    lstat(path.c_str(), &stat_attr);
  }
  return;
}

int fileAttributes::set_attr(string path, ofstream& log) {
  struct stat statbuf;
  struct dirent* dir_entry;
  DIR* directory;
  int ret;

  ret = lstat(path.c_str(), &statbuf);
  if (ret < 0) {
    perror("lstat");
    return ret;
  }
  string parent_path = path.substr(0, path.find_last_of("/"));

  directory = opendir(parent_path.c_str());
  if (directory == NULL) {
    perror("opendir");
    log << "Error opening directory " << path << endl;
    return -1;
  }
  
  dir_entry = readdir(directory);
  if (dir_entry == NULL) {
    perror("readdir");
    log << "Error reading directory " << path << endl;
    closedir(directory);
    return -1;
  }

  set_dir_attr(dir_entry);
  set_stat_attr(path, true);

  closedir(directory);
  return 0;

}

void fileAttributes::set_md5sum(string file_path) {
  FILE *fp;
  string command = "md5sum " + file_path;
  char md5[100];
  fp = popen(command.c_str(), "r");
  fscanf(fp, "%s", md5);
  fclose(fp);
  md5sum = string(md5);
}

bool fileAttributes::compare_dir_attr(struct dirent a) {

  return ((dir_attr.d_ino == a.d_ino) &&
    (dir_attr.d_off == a.d_off) &&
    (dir_attr.d_reclen == a.d_reclen) &&
    (dir_attr.d_type == a.d_type) &&
    (strcmp(dir_attr.d_name, a.d_name) == 0));
}

bool fileAttributes::compare_stat_attr(struct stat a) {

  return ((stat_attr.st_ino == a.st_ino) &&
    (stat_attr.st_mode == a.st_mode) &&
    (stat_attr.st_nlink == a.st_nlink) &&
    (stat_attr.st_uid == a.st_uid) &&
    (stat_attr.st_gid == a.st_gid) &&
    // (stat_attr.st_rdev == a.st_rdev) &&
    // (stat_attr.st_dev == a.st_dev) &&
    (stat_attr.st_size == a.st_size) &&
    (stat_attr.st_blksize == a.st_blksize)); //&&
    // TODO: ADD THIS BACK IN!!!!
    // (stat_attr.st_blocks == a.st_blocks));
}

bool fileAttributes::compare_md5sum(string a) {
  return md5sum.compare(a);
}

bool fileAttributes::is_regular_file() {
  return S_ISREG(stat_attr.st_mode);
}

ofstream& operator<< (ofstream& os, fileAttributes& a) {
  // print dir_attr
  os << "---Directory Atrributes---" << endl;
  os << "Name   : " << (a.dir_attr).d_name << endl;
  os << "Inode  : " << (a.dir_attr).d_ino << endl;
  os << "Offset : " << (a.dir_attr).d_off << endl;
  os << "Length : " << (a.dir_attr).d_reclen << endl;
  os << "Type   : " << (a.dir_attr).d_type << endl;
  // print stat_attr
  os << "---File Stat Atrributes---" << endl;
  os << "Inode     : " << (a.stat_attr).st_ino << endl;
  os << "TotalSize : " << (a.stat_attr).st_size << endl;
  os << "BlockSize : " << (a.stat_attr).st_blksize << endl;
  os << "#Blocks   : " << (a.stat_attr).st_blocks << endl;
  os << "#HardLinks: " << (a.stat_attr).st_nlink << endl;
  os << "Mode      : " << (a.stat_attr).st_mode << endl;
  os << "User ID   : " << (a.stat_attr).st_uid << endl;
  os << "Group ID  : " << (a.stat_attr).st_gid << endl;
  os << "Device ID : " << (a.stat_attr).st_rdev << endl;
  os << "RootDev ID: " << (a.stat_attr).st_dev << endl;

  return os;
}

DiskContents::DiskContents(string path, string type) {
  disk_path = path;
  fs_type = type;
  device_mounted = false;
}

DiskContents::~DiskContents() {
}

int DiskContents::mount_disk(string opts) {
    // assume that the mount point already exists
    int ret;
    // ret = mount(disk_path.c_str(), mount_point.c_str(), "NOVA", MS_RDONLY, NULL);
    cout << "mounting at " << mount_point << endl;
    if (opts == "") {
      ret = mount(disk_path.c_str(), mount_point.c_str(), fs_type.c_str(), MS_RDONLY, NULL);
    }
    else {
      ret = mount(disk_path.c_str(), mount_point.c_str(), fs_type.c_str(), MS_RDONLY, opts.c_str());
    }
    if (ret < 0) {
        return ret;
    }

    device_mounted = true;
    return 0;
}

int DiskContents::unmount_disk() {
    // we don't want to delete the mount point
    int ret;
    
    ret = umount(mount_point.c_str());
    if (ret < 0) {
      // sleep and try again
      sleep(2);
      ret = umount(mount_point.c_str());
      if (ret < 0) {
        return ret;
      }
    }

    device_mounted = false;
    return 0;
}

void DiskContents::set_mount_point(string path) {
  mount_point = path;
}

void DiskContents::get_contents(const char* path) {
  DIR *directory;
  struct dirent *dir_entry;
  // open both the directories
  if (!(directory = opendir(path))) {
    return;
  }
  // get the contents in both the directories
  if (!(dir_entry = readdir(directory))) {
    closedir(directory);
    return;
  }
  do {
    string parent_path(path);
    string filename(dir_entry->d_name);
    string current_path = parent_path + "/" + filename;
    string relative_path = current_path;
    relative_path.erase(0, mount_point.length());
    struct stat statbuf;
    fileAttributes fa;
    if (lstat(current_path.c_str(), &statbuf) == -1) {
      continue;
    }
    if (dir_entry->d_type == DT_DIR) {
      if ((strcmp(dir_entry->d_name, ".") == 0) || (strcmp(dir_entry->d_name, "..") == 0)) {
        continue;
      }
      fa.set_dir_attr(dir_entry);
      fa.set_stat_attr(current_path, false);
      contents[relative_path] = fa;
      // If the entry is a directory and not . or .. make a recursive call
      get_contents(current_path.c_str());
    } else if (dir_entry->d_type == DT_LNK) {
      // compare lstat outputs
      struct stat lstatbuf;
      if (lstat(current_path.c_str(), &lstatbuf) == -1) {
        continue;
      }
      fa.set_stat_attr(current_path, true);
      contents[relative_path] = fa;
    } else if (dir_entry->d_type == DT_REG) {
      fa.set_md5sum(current_path);
      fa.set_stat_attr(current_path, false);
      contents[relative_path] = fa;
    } else {
      fa.set_stat_attr(current_path, false);
      contents[relative_path] = fa;
    }
  } while (dir_entry = readdir(directory));
  closedir(directory);
}

string DiskContents::get_mount_point() {
  return mount_point;
}

bool DiskContents::check_creat_and_mkdir(DiskContents &oracle, string path, ofstream& diff_file, bool syscall_finished) {
  int res;
  bool match;

  // There is an issue in NOVA where directories are listed as having 0 blocks until you 
  // write to them or unmount the system. Fsyncing doesn't do anything. Current workaround 
  // is to remove the check on number of blocks, but that really isn't what we should do.

  if (disk_path.compare(oracle.disk_path) == 0) {
    return true;
  }

  string oracle_path = oracle.mount_point + path;
  string crash_path = mount_point + path;

  // check if the file exists in the crash path
  res = access(crash_path.c_str(), F_OK);
  if (res == 0 || syscall_finished) {
    match = compare_entries_at_path(oracle, path, diff_file, true);
    return match;
  }
  // else, if the file doesn't exist, do nothing; there isn't anything to 
  // to check here. this is a valid crash state.
  return true;
}

bool DiskContents::check_truncate(DiskContents &oracle, string path, fileAttributes fa, ofstream& diff_file, bool syscall_finished) {
  int ret, fd, bytes_read;
  bool match_old, match_current;
  fileAttributes crash_attrs;
  int buflen = 4096;
  char* filebuf[buflen];

  if (disk_path.compare(oracle.disk_path) == 0) {
    return true;
  }

  string oracle_path = oracle.mount_point + path;
  string crash_path = mount_point + path;

  // the file should exist in the crash path if we have called truncate on it
  ret = access(crash_path.c_str(), F_OK);
  if (ret != 0) {
    diff_file << "Truncated file does not exist in crash state" << endl;
    return false;
  }

  match_current = compare_entries_at_path(oracle, path, diff_file, false);

  // TODO: we write to diff_file if set_attr fails here, but we write to the main // log if it fails in some other places. that seems bad.
  ret = crash_attrs.set_attr(crash_path, diff_file);
  if (ret < 0) {
    return false;
  }

  match_old = crash_attrs.compare_stat_attr(fa.stat_attr);

  // the file size should match either the old size or the new one
  // it COULD match both if we truncate to the current size, so this has 
  // to be inclusive OR
  if (!(match_old || match_current)) {
    fileAttributes oracle_fa;
    oracle_fa.set_attr(oracle_path.c_str(), diff_file);
    diff_file << "DIFF: Content Mismatch" << endl;
    diff_file << "Truncated file does not match a valid crash state" << endl;
    diff_file << "Crash contents at " << crash_path << ": " << endl;
    diff_file << crash_attrs << endl;
    diff_file << "Old oracle contents: " << endl;
    diff_file << fa << endl;
    diff_file << "New oracle contents: " << endl;
    diff_file << oracle_fa << endl;
    return false;
  }
  // if the syscall has finished, then the file size has to match 
  // the oracle's file size
  if (syscall_finished && !match_current) {
    return false;
  }

  // so if the size of the file is greater than the old size, open it and 
  // start reading from the point at which we extended it, and make sure that 
  // it has zeroes
  if (crash_attrs.stat_attr.st_size > fa.stat_attr.st_size) {
    fd = open(crash_path.c_str(), O_RDONLY);
    if (fd < 0) {
      perror("open");
      diff_file << "Unable to open " << crash_path << endl;
    }
    bytes_read = buflen;
    while (bytes_read == buflen) {
      // cout << "loop" << endl;
      bytes_read = pread(fd, filebuf, buflen, fa.stat_attr.st_size);
      cout << bytes_read << endl;
      if (filebuf[0] == 0) {
        cout << "hello!!" << endl;
      } else {
        cout << "not zero" << endl;
      }
      cout << "hello?" << endl; // BUILD AND RUN
      // cout << typeid(filebuf[0]).name() << endl;
      // for (int i = 0; i < bytes_read; i++) {
      //   if 
      // }
    }

    close(fd);
  }

  return true;
} 


bool DiskContents::compare_disk_contents(DiskContents &compare_disk, ofstream &diff_file, string opts) {
  bool retValue = true;

  if (disk_path.compare(compare_disk.disk_path) == 0) {
    return retValue;
  }

//   string base_path = "/mnt/snapshot";
  string base_path = mount_point;
  get_contents(base_path.c_str());

  // if (compare_disk.mount_disk(opts) != 0) {
  //   perror("mount");
  //   cout << "Mounting " << compare_disk.disk_path << " failed" << endl;
  //   return false;
  // }

  compare_disk.get_contents(compare_disk.get_mount_point().c_str());

  // Compare the size of contents
  if (contents.size() != compare_disk.contents.size()) {
    diff_file << "DIFF: Mismatch" << endl;
    diff_file << "Unequal #entries in " << disk_path << ", " << compare_disk.disk_path;
    diff_file << endl << endl;
    diff_file << disk_path << " contains:" << endl;
    for (auto &i : contents) {
      diff_file << i.first << endl;
    }
    diff_file << endl;

    diff_file << compare_disk.disk_path << " contains:" << endl;
    for (auto &i : compare_disk.contents) {
      diff_file << i.first << endl;
    }
    diff_file << endl;
    retValue = false;
  }

  // entry-wise comparision
  for (auto &i : contents) {
    fileAttributes i_fa = i.second;
    if (compare_disk.contents.find((i.first)) == compare_disk.contents.end()) {
      diff_file << "DIFF: Missing " << i.first << endl;
      diff_file << "Found in " << disk_path << " only" << endl;
      diff_file << i_fa << endl << endl;
      retValue = false;
      continue;
    }
    fileAttributes j_fa = compare_disk.contents[(i.first)];
    if (!(i_fa.compare_dir_attr(j_fa.dir_attr)) ||
          !(i_fa.compare_stat_attr(j_fa.stat_attr))) {
        diff_file << "DIFF: Content Mismatch " << i.first << endl << endl;
        diff_file << disk_path << ":" << endl;
        diff_file << i_fa << endl << endl;
        diff_file << compare_disk.disk_path << ":" << endl;
        diff_file << j_fa << endl << endl;
        retValue = false;
        continue;
    }
    // compare user data if the entry corresponds to a regular files
    if (i_fa.is_regular_file()) {
      // check md5sum of the file contents
      if (i_fa.compare_md5sum(j_fa.md5sum) != 0) {
        diff_file << "DIFF : Data Mismatch of " << (i.first) << endl;
        diff_file << disk_path << " has md5sum " << i_fa.md5sum << endl;
        diff_file << compare_disk.disk_path << " has md5sum " << j_fa.md5sum;
        diff_file << endl << endl;
        retValue = false;
      }
    }
  }
//   compare_disk.unmount_and_delete_mount_point();
  // compare_disk.unmount_disk();
  return retValue;
}

// TODO(P.S.) Cleanup the code and pull out redundant code into separate functions
bool DiskContents::compare_entries_at_path(DiskContents &oracle,
  string &path, ofstream &diff_file, bool print_err) {
  bool retValue = true;

  if (disk_path.compare(oracle.disk_path) == 0) {
    return retValue;
  }

  string base_path = mount_point + path;

  string oracle_mount_point(oracle.get_mount_point());
  string oracle_path = oracle_mount_point + path;

  fileAttributes base_fa, oracle_fa;
  bool failed_stat = false;
  struct stat base_statbuf, oracle_statbuf;
  if (lstat(base_path.c_str(), &base_statbuf) == -1) {
    diff_file << "Failed stating the file " << base_path << " in crashed FS" << endl;
    failed_stat = true;
  }
  if (lstat(oracle_path.c_str(), &oracle_statbuf) == -1) {
    diff_file << "Failed stating the file " << oracle_path << " in oracle FS" << endl;
    failed_stat = true;
  }


  if (failed_stat) {
    return false;
  }

  base_fa.set_stat_attr(base_path, false);
  oracle_fa.set_stat_attr(oracle_path, false);
  if (!(base_fa.compare_stat_attr(oracle_fa.stat_attr))) {
    diff_file << "DIFF: Content Mismatch " << path << endl << endl;
    diff_file << base_path << ":" << endl;
    diff_file << base_fa << endl << endl;
    diff_file << oracle_path << ":" << endl;
    diff_file << oracle_fa << endl << endl;
    return false;
  }

  if (base_fa.is_regular_file()) {
    base_fa.set_md5sum(base_path);
    oracle_fa.set_md5sum(oracle_path);
    if (base_fa.compare_md5sum(oracle_fa.md5sum) != 0) {
      diff_file << "DIFF : Data Mismatch of " << path << endl;
      diff_file << base_path << " has md5sum " << base_fa.md5sum << endl;
      diff_file << oracle_path << " has md5sum " << oracle_fa.md5sum;
      diff_file << endl << endl;
      return false;
    }
  }
  return retValue;
}

// compare file contents against a given oracle file, not the contents 
// in an oracle file system image
bool DiskContents::compare_file_contents(string oracle_file, string path, int offset, int length, ofstream &diff_file) {
	string base_path = mount_point + path;
  memset(&content_diff, 0, sizeof(struct file_content_diff));

	// we aren't using a compare disk at all here, just the oracle file
	// cout << "compare file contents base path: " << base_path << endl;

	// try to stat the base file in the crash state
	fileAttributes base_fa;
	// bool failed_stat = false;
	struct stat base_statbuf, compare_statbuf;
	if (lstat(base_path.c_str(), &base_statbuf) == -1) {
		diff_file << "Failed stating the file " << base_path << endl;
		// failed_stat = true;
		return false;
	}

  if (lstat(oracle_file.c_str(), &compare_statbuf) == -1) {
    diff_file << "Failed stating the file " << oracle_file << endl;
    return false;
  }

	std::ifstream f1(base_path, std::ios::binary);
  std::ifstream f2(oracle_file, std::ios::binary);

	if (!f1 || !f2) {
		cout << "Error opening input file streams " << base_path  << " and ";
		cout << oracle_file << endl;
		return false;
	}

	f1.seekg(offset, std::ifstream::beg);
	f2.seekg(offset, std::ifstream::beg);

	char * buffer_f1 = new char[length + 1];
	char * buffer_f2 = new char[length + 1];

	f1.read(buffer_f1, length);
	f2.read(buffer_f2, length);

	f1.close();
	f2.close();

  // if we were able to read from both f1 and f2, compare their contents
  if (f1 && f2) {
    buffer_f1[length] = '\0';
    buffer_f2[length] = '\0';

    if (strcmp(buffer_f1, buffer_f2) == 0) {
      return true;
    }
  }
  // if we couldn't read from both, that's fine; both files are empty
  else if (!f1 && !f2) {
    return true;
  }
  // otherwise, if we read from one and not the other, there's a mismatch

  // save the diff; we'll print it out later only if the comparison against 
  // both oracles fails
  content_diff.path = path;
  content_diff.length = length;
  content_diff.buffer_f1 = buffer_f1;
  content_diff.buffer_f2 = buffer_f2;
	return false;
}

bool DiskContents::compare_file_contents2(DiskContents &compare_disk, string path,
    int offset, int length, ofstream &diff_file, string opts) {
  bool retValue = true;
  if (disk_path.compare(compare_disk.disk_path) == 0) {
    return retValue;
  }

  // string base_path = "/mnt/snapshot" + path;
  string base_path = mount_point + path;
  // if (compare_disk.mount_disk(opts) != 0) {
  //   perror("mount");
  //   cout << "Mounting " << compare_disk.disk_path << " failed" << endl;
  //   return false;
  // }
  string compare_disk_mount_point(compare_disk.get_mount_point());
  string compare_path = compare_disk_mount_point + path;

  fileAttributes base_fa, compare_fa;
  bool failed_stat = false;
  struct stat base_statbuf, compare_statbuf;
  if (stat(base_path.c_str(), &base_statbuf) == -1) {
    diff_file << "Failed stating the file " << base_path << endl;
    failed_stat = true;
  }
  if (stat(compare_path.c_str(), &compare_statbuf) == -1) {
    diff_file << "Failed stating the file " << compare_path << endl;
    failed_stat = true;
  }

  if (failed_stat) {
    // compare_disk.unmount_and_delete_mount_point();
    // compare_disk.unmount_disk();
    return false;
  }

  std::ifstream f1(base_path, std::ios::binary);
  std::ifstream f2(compare_path, std::ios::binary);

  if (!f1 || !f2) {
    cout << "Error opening input file streams " << base_path  << " and ";
    cout << compare_path << endl;
    // compare_disk.unmount_and_delete_mount_point();
    // compare_disk.unmount_disk();
    return false;
  }

  f1.seekg(offset, std::ifstream::beg);
  f2.seekg(offset, std::ifstream::beg);

  char * buffer_f1 = new char[length + 1];
  char * buffer_f2 = new char[length + 1];

  f1.read(buffer_f1, length);
  f2.read(buffer_f2, length);
  f1.close();
  f2.close();

  if (f1 && f2) {
    buffer_f1[length] = '\0';
    buffer_f2[length] = '\0';

    if (strcmp(buffer_f1, buffer_f2) == 0) {
      // compare_disk.unmount_disk();
      return true;
    }
  }
  // if we couldn't read from both, that's fine; both files are empty,
  // or maybe the offset is beyond the end of the files
  else if (!f1 && !f2) {
    // compare_disk.unmount_disk();
    return true;
  }

  // buffer_f1[length] = '\0';
  // buffer_f2[length] = '\0';

  // if (strcmp(buffer_f1, buffer_f2) == 0) {
  //   // compare_disk.unmount_and_delete_mount_point();
  //   compare_disk.unmount_disk();
  //   return true;
  // }

  for (int i = 0; i < length; i++) {
    if (buffer_f1[i] != buffer_f2[i]) {
      cout << "Mismatch starting at " << i << endl;
      break;
    }
  }

  diff_file << __func__ << " failed" << endl;
  diff_file << "Content Mismatch of file " << path << " from ";
  diff_file << offset << " of length " << length << endl;
  diff_file << base_path << " has " << buffer_f1 << endl;
  diff_file << compare_path << " has " << buffer_f2 << endl;
  // compare_disk.unmount_and_delete_mount_point();
  // compare_disk.unmount_disk();
  // sleep(5);
  return false;
}

bool isEmptyDirOrFile(string path) {
  DIR *directory = opendir(path.c_str());
  if (directory == NULL) {
    return true;
  }

  struct dirent *dir_entry;
  int num_dir_entries = 0;
  while (dir_entry = readdir(directory)) {
    if (++num_dir_entries > 2) {
      break;
    }
  }
  closedir(directory);
  if (num_dir_entries <= 2) {
    return true;
  }
  return false;
}

bool isFile(string path) {
  struct stat sb;
  if (lstat(path.c_str(), &sb) < 0) {
    cout << __func__ << ": Failed stating " << path << endl;
    return false;
  }
  if (S_ISDIR(sb.st_mode)) {
    return false;
  }
  return true;
}

bool DiskContents::deleteFiles(string path, ofstream &diff_file) {
  int ret;
  struct stat buf;
  if (path.empty()) {
    return true;
  }

  ret = lstat(path.c_str(), &buf);
  if (ret < 0) {
    diff_file << "Failed stat-ing " << path << " " << strerror(errno) << endl;
    return false;
  }

  if (isEmptyDirOrFile(path) == true) {
    if (path.compare(mount_point) == 0) { 
      return true;
    }
    if (isFile(path) == true) {
      // return (unlink(path.c_str()) == 0);
      ret = unlink(path.c_str());
      if (ret != 0) {
        diff_file << "Could not delete file " << path << " " << strerror(errno) << endl;
      }
      return (ret == 0);
    } else {
      // return (rmdir(path.c_str()) == 0);
      ret = rmdir(path.c_str());
      if (ret < 0) {
        diff_file << "Could not delete empty directory " << path << " " << strerror(errno) << endl;
      }
      return (ret == 0);
    }
  }

  DIR *directory = opendir(path.c_str());
  if (directory == NULL) {
    cout << "Couldn't open the directory " << path << endl;
    diff_file << "Couldn't open the directory " << path << endl;
    return false;
  }

  struct dirent *dir_entry;
  while (dir_entry = readdir(directory)) {
    if ((strcmp(dir_entry->d_name, ".") == 0) ||
        (strcmp(dir_entry->d_name, "..") == 0)) {
      continue;
    }
    string subpath = path + "/" + string(dir_entry->d_name);
    bool subpathIsFile = isFile(subpath);
    // janky fix for symlink loop problem - don't recursively delete 
    // on symlinks. not perfect, but strengthened checks should 
    // fix this issue in the future.
    if (!S_ISLNK(buf.st_mode)) {
      bool res = deleteFiles(subpath, diff_file);
      if (!res) {
        closedir(directory);
        diff_file << "Couldn't remove directory " << subpath << " " << strerror(errno) << endl;
        cout << "Couldn't remove directory " << subpath << " " << strerror(errno) << endl;
        return res;
      }
    }

    // we may have already deleted the file, so check to make sure it's still there
    // before atttempting to finally delete it
    // also, we could get to this point with a non-empty directory, which will throw 
    // an error if we try to delete it
    struct stat statbuf;
    ret = stat(subpath.c_str(), &statbuf);
    if (!subpathIsFile && ret == 0 && isEmptyDirOrFile(subpath)) {
      if (rmdir(subpath.c_str()) < 0) {
        diff_file << "Couldn't remove directory " << subpath << " "  << strerror(errno) << endl;
        cout << "Couldn't remove directory " << subpath << " " << strerror(errno) << endl;
        return false;
      }
    }
  }
  closedir(directory);
  return true;
}

bool DiskContents::makeFiles(string base_path, ofstream &diff_file) {
  get_contents(base_path.c_str());
  for (auto &i : contents) {
    if (S_ISDIR((i.second).stat_attr.st_mode)) {
      string filepath = base_path + i.first + "/" + "_dummy";
      int fd = open(filepath.c_str(), O_CREAT|O_RDWR, 0777);
      if (fd < 0) {
        diff_file <<  "Couldn't create file " << filepath << endl;
        cout <<  "Couldn't create file " << filepath << endl;
        return false;
      }
      close(fd);
    }
  }
  return true;
}

bool DiskContents::sanity_checks(ofstream &diff_file) {
//   cout << __func__ << endl;
//   string base_path = "/mnt/snapshot";
  string base_path = mount_point; // want to do sanity checks on the directory where the replayed image is mounted
  // string base_path = "/mnt/pmem";
  if (!makeFiles(base_path, diff_file)) {
    cout << "Failed: Couldn't create files in all directories" << endl;
    diff_file << "Failed: Couldn't create files in all directories" << endl;
    return false;
  }

  if (!deleteFiles(base_path, diff_file)) {
    cout << "Failed: Couldn't delete all the existing directories" << endl;
    diff_file << "Failed: Couldn't delete all the existing directories" << endl;
    return false;
  }

//   cout << "Passed sanity checks" << endl;
  return true;
}


} // namespace fs_testing