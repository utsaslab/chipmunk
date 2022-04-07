#include "../api/wrapper.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <utility>


#include <iostream>

#include "../api/actions.h"
#include "../../ioctl.h"

namespace fs_testing {
namespace user_tools {
namespace api {

using std::pair;
using std::shared_ptr;
using std::string;
using std::tuple;
using std::unordered_map;
using std::vector;

using fs_testing::utils::DiskMod;
using std::cout;
using std::endl;

// Super ugly defines to do compile-time string concatonation X times...
#define REP0(x)
#define REP1(x)     x
#define REP2(x)     REP1(x) x
#define REP3(x)     REP2(x) x
#define REP4(x)     REP3(x) x
#define REP5(x)     REP4(x) x
#define REP6(x)     REP5(x) x
#define REP7(x)     REP6(x) x
#define REP8(x)     REP7(x) x
#define REP9(x)     REP8(x) x
#define REP10(x)    REP9(x) x

#define REP(hundreds, tens, ones, x) \
  REP##hundreds(REP10(REP10(x))) \
  REP##tens(REP10(x)) \
  REP##ones(x)

namespace {

// We want exactly 4k of data for this.
static const unsigned int kTestDataSize = 4096;
// 4K of data plus one terminating byte.
static constexpr char kTestDataBlock[kTestDataSize + 1] =
  REP(1, 2, 8, "abcdefghijklmnopqrstuvwxyz123456");

}  // namespace

// namespace fs_testing {
// namespace user_tools {
// namespace api {




int startMark(int sys) {
	int fd = open("/dev/ioctl_dummy", 0);
	ioctl(fd, LOGGER_MARK_SYS, sys);
	return fd;
	//close(fd);
}

void endMark(int fd, int ret) {
	ioctl(fd, LOGGER_MARK_SYS_END, (unsigned long) ret);
	close(fd);
}

int DefaultFsFns::FnMknod(const std::string &pathname, mode_t mode, dev_t dev) {
	int fd = startMark(SYS_mknod);
  	int ret = mknod(pathname.c_str(), mode, dev);
	endMark(fd, ret);
	return ret;
}

// int DefaultFsFns::FnFchmod(int fd, mode_t mode) {
//   int fd_ = startMark(SYS_fchmod);
//   int ret = fchmod(fd, mode);
//   endMark(fd_, ret);
//   return ret;
// }

void DefaultFsFns::setCoverage(bool coverage, int ctr) {
  this->getCoverage = coverage;
  if (!coverage)
    return;
  cover_out = std::ofstream("cover-" + std::to_string(ctr), std::ios_base::app);
  cover_fd = open(WRAPPER_KCOV_PATH, O_RDWR);
  if (cover_fd == -1)
    perror("open"), exit(1);
  if (ioctl(cover_fd, WRAPPER_KCOV_INIT_TRACE, WRAPPER_COVER_SIZE))
    perror("ioctl"), exit(1);
  this->cover = (covert*)mmap(NULL, WRAPPER_COVER_SIZE*WRAPPER_KCOV_ENTRY_SIZE,
                           PROT_READ | PROT_WRITE, MAP_SHARED, cover_fd, 0);
  if ((void *) this->cover == MAP_FAILED)
    perror("mmap"), exit(1);
  if (ioctl(cover_fd, WRAPPER_KCOV_ENABLE, WRAPPER_KCOV_TRACE_PC))
    perror("ioctl"), exit(1);
  __atomic_store_n(&this->cover[0], 0, __ATOMIC_RELAXED);
}

void DefaultFsFns::resetCoverage() {
  if (!getCoverage)
    return;
  *((uint64_t*)this->cover) = 0;
}

void DefaultFsFns::writeCoverage() {
  if (!getCoverage)
    return;
  uint32_t size = *((uint32_t *) this->cover);
  for (uint32_t i = 1; i < size; i++) {
    cover_out << (uint32_t) this->cover[i] << endl;
  }
}

int DefaultFsFns::FnMkdir(const std::string &pathname, mode_t mode) {
	int fd = startMark(SYS_mkdir);
  // resetCoverage();
	int ret = mkdir(pathname.c_str(), mode);
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnOpen(const std::string &pathname, int flags) {
  // fprintf(stderr, "open path: %s\n", pathname.c_str());
	int fd = startMark(SYS_open);
  // resetCoverage();
	int ret = open(pathname.c_str(), flags);
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnOpen2(const std::string &pathname, int flags, mode_t mode) {
    // fprintf(stderr, "open path: %s\n", pathname.c_str());
	int fd = startMark(SYS_open);
  // resetCoverage();
  int ret = open(pathname.c_str(), flags, mode);
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

off_t DefaultFsFns::FnLseek(int fd, off_t offset, int whence) {
	int fd_ = startMark(SYS_lseek);
  // resetCoverage();
	int ret = lseek(fd, offset, whence);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

ssize_t DefaultFsFns::FnWrite(int fd, const void *buf, size_t count) {
	int fd_ = startMark(SYS_write);
  // resetCoverage();
  int ret = write(fd, buf, count);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

ssize_t DefaultFsFns::FnPwrite(int fd, const void *buf, size_t count,
    off_t offset) {
	int fd_ = startMark(SYS_pwrite64);
  // resetCoverage();
  int ret = pwrite(fd, buf, count, offset);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

void * DefaultFsFns::FnMmap(void *addr, size_t length, int prot, int flags,
    int fd, off_t offset) {
	int fd_ = startMark(SYS_mmap);
  // resetCoverage();
	void *ret = mmap(addr, length, prot, flags, fd, offset);
  writeCoverage();
	endMark(fd_, (ret == NULL) ? -1 : 0);
	return ret;
}

int DefaultFsFns::FnMsync(void *addr, size_t length, int flags) {
	int fd = startMark(SYS_msync);
  // resetCoverage();
	int ret = msync(addr, length, flags);
	writeCoverage();
  endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnMunmap(void *addr, size_t length) {
	int fd = startMark(SYS_munmap);
  // resetCoverage();
	int ret = munmap(addr, length);
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnFallocate(int fd, int mode, off_t offset, off_t len) {
	int fd_ = startMark(SYS_fallocate);
  // resetCoverage();
	int ret = fallocate(fd, mode, offset, len);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

int DefaultFsFns::FnClose(int fd) {
	int fd_ = startMark(SYS_close);
  // resetCoverage();
	int ret = close(fd);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

int DefaultFsFns::FnRename(const string &old_path, const string &new_path) {
	int fd = startMark(SYS_rename);
	int ret = rename(old_path.c_str(), new_path.c_str());
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnUnlink(const std::string &pathname) {
	int fd = startMark(SYS_unlink);
  // resetCoverage();
	int ret = unlink(pathname.c_str());
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnRemove(const std::string &pathname) {
	int fd = startMark(SYS_unlink);
  // resetCoverage();
	int ret = remove(pathname.c_str());
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnRmdir(const std::string &pathname) {
  int fd = startMark(SYS_rmdir);
  // resetCoverage();
	int ret = rmdir(pathname.c_str());
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnLink(const std::string &oldpath, const std::string &newpath) {
	int fd = startMark(SYS_link);
  // resetCoverage();
  int ret = link(oldpath.c_str(), newpath.c_str());
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnSymlink(const std::string &oldpath, const std::string &newpath, const std::string &mnt_dir) {
	int newdirfd = open(mnt_dir.c_str(), O_DIRECTORY | O_PATH);
  int fd = startMark(SYS_symlinkat);
  // resetCoverage();
	int ret = symlinkat(oldpath.c_str(), newdirfd, newpath.c_str());
  writeCoverage();
	endMark(fd, ret);
  close(newdirfd);
	return ret;
}

int DefaultFsFns::FnStat(const std::string &pathname, struct stat *buf) {
	// int fd = startMark(SYS_stat); 
  // resetCoverage();
  	int ret = stat(pathname.c_str(), buf);
  writeCoverage();
	// endMark(ret);
	return ret;
}

bool DefaultFsFns::FnPathExists(const std::string &pathname) {
  const int res = access(pathname.c_str(), F_OK);
  // TODO(ashmrtn): Should probably have some better way to handle errors.
  if (res != 0) {
    return false;
  }

  return true;
}

int DefaultFsFns::FnFsync(const int fd) {
	int fd_ = startMark(SYS_fsync);
  // resetCoverage();
	int ret = fsync(fd);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

int DefaultFsFns::FnFdatasync(const int fd) {
	int fd_ = startMark(SYS_fdatasync);
  // resetCoverage();
	int ret = fdatasync(fd);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

void DefaultFsFns::FnSync() {
	int fd = startMark(SYS_sync);
  // resetCoverage();
  	sync();
  writeCoverage();
	endMark(fd, 0);
}

int DefaultFsFns::FnTruncate(const char *path, off_t length) {
	int fd = startMark(SYS_truncate);
  resetCoverage();
	int ret = truncate(path, length);
  writeCoverage();
	endMark(fd, ret);
	return ret;
}

int DefaultFsFns::FnFtruncate(const int fd, off_t length) {
	int fd_ = startMark(SYS_ftruncate);
  // resetCoverage();
	int ret = ftruncate(fd, length);
  writeCoverage();
	endMark(fd_, ret);
	return ret;
}

int DefaultFsFns::FnRead(const int fd, void* buf, size_t nbytes) {
  int fd_ = startMark(SYS_read);
  resetCoverage();
  int ret = read(fd, buf, nbytes);
  writeCoverage();
  endMark(fd_, ret);
  return ret;
}

// int DefaultFsFns::FnSyncfs(const int fd) {
//   return syncfs(fd);
// }

int DefaultFsFns::FnSyncFileRange(const int fd, size_t offset, size_t nbytes,
    unsigned int flags) {
  return sync_file_range(fd, offset, nbytes, flags);
}

int DefaultFsFns::FnCheckpoint() {
  return Checkpoint();
}

int DefaultFsFns::FnMark() {
  return Mark();
}

int DefaultFsFns::FnWriteData(int fd, unsigned int offset, unsigned int size) {
  return 0;
}

RecordCmFsOps::RecordCmFsOps(FsFns *functions, string m) {
  fns_ = functions;
  mnt_dir = m;
}

// TODO: record a mod for mknod
int RecordCmFsOps::CmMknod(const string &pathname, const mode_t mode,
    const dev_t dev) {
  return fns_->FnMknod(pathname.c_str(), mode, dev);
}

int RecordCmFsOps::CmMkdir(const string &pathname, const mode_t mode) {
  DiskMod mod;
  mod.directory_mod = true;
  mod.path_mod = false;
  mod.path = pathname;
  mod.fd = 0;
  mod.mode = mode;
  mod.flags = 0; // ignored
  mod.mod_type = DiskMod::kCreateMod;
  mod.mod_opts = DiskMod::kNoneOpt;

  const int res = fns_->FnMkdir(pathname.c_str(), mode);
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

void RecordCmFsOps::CmOpenCommon(const int fd, const string &pathname,
    const bool exists, const int flags, mode_t mode) {
  fd_map_.insert({fd, pathname});

  if (!exists || (flags & O_TRUNC)) {
    // We only want to record this op if we changed something on the file
    // system.

    DiskMod mod;
    mod.return_value = fd;

    // Need something like stat() because umask could affect the file
    // permissions.
    const int post_stat_res = fns_->FnStat(pathname.c_str(),
        &mod.post_mod_stats);
    if (post_stat_res < 0) {
      // TODO(ashmrtn): Some sort of warning here?
      mod.mod_type = DiskMod::kOpenMod; // TODO: what should this be?
      mod.mod_opts = DiskMod::kNoneOpt;
      // mod.path = pathname;
      mod.directory_mod = false;
      mod.fd = fd;
      mod.mode = 0;
      mod.flags = flags;
      // if we run into a symlink issue, just record the open and return.
      // if (errno == ELOOP) {
      //   mods_.push_back(mod);
      //   return;
      // }
      mod.return_value = post_stat_res;
      mods_.push_back(mod);
      return;
    }

    mod.directory_mod = S_ISDIR(mod.post_mod_stats.st_mode);
    if (!exists) {
      mod.mod_type = DiskMod::kCreateMod;
      mod.mod_opts = DiskMod::kNoneOpt;
    } else {
      mod.mod_type = DiskMod::kDataMetadataMod;
      mod.mod_opts = DiskMod::kTruncateOpenOpt;
    }
    mod.path = pathname;
    mod.fd = fd;
    mod.mode = mode;
    mod.flags = flags;

    mods_.push_back(mod);
  } else {
    DiskMod mod;
    mod.directory_mod = S_ISDIR(mod.post_mod_stats.st_mode);
    mod.mod_type = DiskMod::kOpenMod;
    mod.mod_opts = DiskMod::kNoneOpt;
    mod.path = pathname;
    mod.fd = fd;
    mod.return_value = fd;
    mod.mode = 0; // will be ignored
    mod.flags = flags;
    mods_.push_back(mod);
  }
}

int RecordCmFsOps::CmOpen(const string &pathname, const int flags) {
  // Will this make a new file or is this path a directory?
  const bool exists = fns_->FnPathExists(pathname.c_str());
  const int res = fns_->FnOpen(pathname.c_str(), flags);
  if (res < 0) {
    DiskMod mod;
    mod.mod_type = DiskMod::kOpenMod; // TODO: what should this be?
    mod.mod_opts = DiskMod::kNoneOpt;
    // mod.path = pathname;
    mod.fd = 0;
    mod.mode = 0;
    mod.flags = flags;
    mod.return_value = res;
    mods_.push_back(mod);
    return res;
  }

  CmOpenCommon(res, pathname, exists, flags, 0);

  return res;
}



int RecordCmFsOps::CmOpen(const string &pathname, const int flags,
    const mode_t mode) {
  // Will this make a new file or is this path a directory?
  const bool exists = fns_->FnPathExists(pathname.c_str());

  const int res = fns_->FnOpen2(pathname.c_str(), flags, mode);
  if (res < 0) {
    DiskMod mod;
    mod.mod_type = DiskMod::kOpenMod; // TODO: what should this be?
    mod.mod_opts = DiskMod::kNoneOpt;
    // mod.path = pathname;
    mod.fd = 0;
    mod.mode = 0;
    mod.flags = flags;
    mod.return_value = res;
    mods_.push_back(mod);
    return res;
  }

  CmOpenCommon(res, pathname, exists, flags, mode);

  return res;
}

off_t RecordCmFsOps::CmLseek(const int fd, const off_t offset,
    const int whence) {
  int ret;
  // NOTE: we record that an lseek occurred, but we DON'T record any 
  // further information. the file offset is lost on crash, and CmWrite
  // records the offset at time of write. We don't even need to 
  // record the file on which it was called (right?)
  // we record that an lseek happened only so that we can keep an 
  // accurate picture of what system call we crash during in case the 
  // fuzzer ends up checking crashes during an lseek operation
  DiskMod mod;
  mod.mod_type = DiskMod::kLseekMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path_mod = false;
  mod.directory_mod = false;
  mod.flags = 0;
  mod.mode = 0;

  ret = fns_->FnLseek(fd, offset, whence);

  mod.return_value = ret;
  mods_.push_back(mod);
  return ret;
}

int RecordCmFsOps::CmWrite(const int fd, const void *buf, const size_t count) {
  DiskMod mod;
  mod.mod_type = DiskMod::kDataMod; // we'll update this later; if we fail out earlier, doesn't really matter what it is
  mod.mod_opts = DiskMod::kWriteOpt;
  if (fd_map_.find(fd) == fd_map_.end()) {
    const int write_res = fns_->FnWrite(fd, buf, count);
    mod.return_value = write_res;
    mods_.push_back(mod);
    return -1;
  }
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  // Get current file position and size. If stat fails, then assume lseek will
  // fail too and just bail out.
  struct stat pre_stat_buf;
  // This could be an fstat(), but I don't see a reason to add another call that
  // does only reads to the already large interface of FsFns.
  int res = fns_->FnStat(fd_map_.at(fd), &pre_stat_buf);
  if (res < 0) {
    mod.return_value = res;
    mods_.push_back(mod);
    return res;
  }

  // mod.file_mod_location = fns_->FnLseek(fd, 0, SEEK_CUR);
  // mod.file_mod_location = CmLseek(fd, 0, SEEK_CUR);/
  // TODO: is it ok to not record this?
  mod.file_mod_location = lseek(fd, 0, SEEK_CUR);
  if (mod.file_mod_location < 0) {
    return mod.file_mod_location;
  }

  const int write_res = fns_->FnWrite(fd, buf, count);
  if (write_res < 0) {
    mod.return_value = write_res;
    mods_.push_back(mod);
    return write_res;
  }

  mod.directory_mod = S_ISDIR(pre_stat_buf.st_mode);

  // TODO(ashmrtn): Support calling write directly on a directory.
  // if (!mod.directory_mod) {
    // Copy over as much data as was written and see what the new file size is.
    // This will determine how we set the type of the DiskMod.
    mod.file_mod_len = write_res;
    mod.mode = 0; // ignored
    mod.flags = 0;
    mod.directory_mod = 0;
    mod.path_mod = 0;

    res = fns_->FnStat(fd_map_.at(fd), &mod.post_mod_stats);
    if (res < 0) {
      mod.return_value = res;
      mods_.push_back(mod);
      return write_res;
    }

    if (pre_stat_buf.st_size != mod.post_mod_stats.st_size) {
      mod.mod_type = DiskMod::kDataMetadataMod;
    } else {
      mod.mod_type = DiskMod::kDataMod;
    }

    if (write_res > 0) {
      mod.file_mod_data.reset(new char[write_res], [](char* c) {delete[] c;});
      memcpy(mod.file_mod_data.get(), buf, write_res);
    }
  // }
  mod.return_value = write_res;
  mods_.push_back(mod);
  return write_res;
}

ssize_t RecordCmFsOps::CmPwrite(const int fd, const void *buf,
    const size_t count, const off_t offset) {
  if (fd_map_.find(fd) == fd_map_.end()) {
    const int write_res = fns_->FnPwrite(fd, buf, count, offset);
    DiskMod mod;
    mod.mod_type = DiskMod::kDataMod; 
    mod.mod_opts = DiskMod::kPwriteOpt;
    mod.return_value = write_res;
    mods_.push_back(mod);
    return -1;
  }
  DiskMod mod;
  mod.mod_type = DiskMod::kDataMod; // we'll update this later; if we fail out earlier, doesn't really matter what it is
  mod.mod_opts = DiskMod::kPwriteOpt;
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  // Get current file position and size. If stat fails, then assume lseek will
  // fail too and just bail out.
  struct stat pre_stat_buf;
  // This could be an fstat(), but I don't see a reason to add another call that
  // does only reads to the already large interface of FsFns.
  int res = fns_->FnStat(fd_map_.at(fd), &pre_stat_buf);
  if (res < 0) {
    mod.return_value = res;
    mods_.push_back(mod);
    return res;
  }

  const int write_res = fns_->FnPwrite(fd, buf, count, offset);
  if (write_res < 0) {
    mod.return_value = write_res;
    mods_.push_back(mod);
    return write_res;
  }

  mod.directory_mod = S_ISDIR(pre_stat_buf.st_mode);

  // TODO(ashmrtn): Support calling write directly on a directory.
  if (!mod.directory_mod) {
    // Copy over as much data as was written and see what the new file size is.
    // This will determine how we set the type of the DiskMod.
    mod.file_mod_location = offset;
    mod.file_mod_len = write_res;
    // mod.path = fd_map_.at(fd);
    mod.mode = 0; // ignored
    mod.flags = 0;

    res = fns_->FnStat(fd_map_.at(fd), &mod.post_mod_stats);
    if (res < 0) {
      mod.return_value = res;
      mods_.push_back(mod);
      return write_res;
    }

    if (pre_stat_buf.st_size != mod.post_mod_stats.st_size) {
      mod.mod_type = DiskMod::kDataMetadataMod;
    } else {
      mod.mod_type = DiskMod::kDataMod;
    }

    if (write_res > 0) {
      mod.file_mod_data.reset(new char[write_res], [](char* c) {delete[] c;});
      memcpy(mod.file_mod_data.get(), buf, write_res);
    }
  }
  mod.return_value = write_res;
  mods_.push_back(mod);

  return write_res;
//   return fns_->FnPwrite(fd, buf, count, offset);
}

// TODO: add a mod for mmap calls. we aren't checking mmap in brute force tests
// right now, so it's ok for now.
void * RecordCmFsOps::CmMmap(void *addr, const size_t length, const int prot,
    const int flags, const int fd, const off_t offset) {
  void *res = fns_->FnMmap(addr, length, prot, flags, fd, offset);
  if (res == (void*) -1) {
    return res;
  }

  if (!(prot & PROT_WRITE) || flags & MAP_PRIVATE || flags & MAP_ANON ||
      flags & MAP_ANONYMOUS) {
    // In these cases, the user cannot write to the mmap-ed region, the region
    // is not backed by a file, or the changes the user makes are not reflected
    // in the file, so we can just act like this never happened.
    return res;
  }

  // All other cases we actually need to keep track of the fact that we mmap-ed
  // this region.
  mmap_map_.insert({(long long) res,
      tuple<string, unsigned int, unsigned int>(
          fd_map_.at(fd), offset, length)});
  return res;
}

int RecordCmFsOps::CmMsync(void *addr, const size_t length, const int flags) {
  const int res = fns_->FnMsync(addr, length, flags);
  if (res < 0) {
    return res;
  }

  // Check which file this belongs to. We need to do a search because they may
  // not have passed the address that was returned in mmap.
  for (const pair<long long, tuple<string, unsigned int, unsigned int>> &kv :
      mmap_map_) {
    if (addr >= (void*) kv.first &&
        addr < (void*) (kv.first + std::get<2>(kv.second))) {
      // This is the mapping you're looking for.
      DiskMod mod;
      mod.mod_type = DiskMod::kDataMod;
      mod.mod_opts = (flags & MS_ASYNC) ?
        DiskMod::kMsAsyncOpt : DiskMod::kMsSyncOpt;
      mod.path = std::get<0>(kv.second);
      // Offset into the file is the offset given in mmap plus the how far addr
      // is from the pointer returned by mmap.
      mod.file_mod_location =
        std::get<1>(kv.second) + ((long long) addr - kv.first);
      mod.file_mod_len = length;

      // Copy over the data that is being sync-ed. We don't know how it is
      // different than what was there to start with, but we'll have it!
      mod.file_mod_data.reset(new char[length], [](char* c) {delete[] c;});
      memcpy(mod.file_mod_data.get(), addr, length);

      mods_.push_back(mod);
      break;
    }
  }

  return res;
}

// TODO: add a mod for munmap calls. again, not using this for brute-force tests
// right now, so it shouldn't really matter
int RecordCmFsOps::CmMunmap(void *addr, const size_t length) {
  const int res = fns_->FnMunmap(addr, length);
  if (res < 0) {
    return res;
  }

  // TODO(ashmrtn): Assume that we always munmap with the same pointer and
  // length that we mmap-ed with. May not actually remove anything if the
  // mapping was not something that caused writes to be reflected in the
  // underlying file (i.e. the key wasn't present to begin with).
  mmap_map_.erase((long long int) addr);

  return res;
}

int RecordCmFsOps::CmFallocate(const int fd, const int mode, const off_t offset,
    off_t len) {
  DiskMod mod;
  mod.mod_opts = DiskMod::kFallocateOpt;
  if (fd_map_.find(fd) == fd_map_.end()) {
    const int res = fns_->FnFallocate(fd, mode, offset, len);
    mod.mod_type = DiskMod::kDataMod;
    // mod.mod_opts = DiskMod::kPunchHoleKeepSizeOpt;
    mod.return_value = res;
    mods_.push_back(mod);
    return -1;
  }
  struct stat pre_stat;
  mod.mod_type = DiskMod::kDataMod; // this will be overwritten later if we don't fail out first
  mod.path = fd_map_[fd];
  mod.fd = fd;
  mod.mode = mode; // ensures we get the mode exactly so we can re-run it for the oracle
  mod.flags = 0;
  mod.file_mod_location = offset;
  mod.file_mod_len = len;

  const int pre_stat_res = fns_->FnStat(fd_map_[fd].c_str(), &pre_stat);
  if (pre_stat_res < 0) {
    mod.return_value = pre_stat_res;
    mods_.push_back(mod);
    return pre_stat_res;
  }

  const int res = fns_->FnFallocate(fd, mode, offset, len);
  if (res < 0) {
    mod.return_value = res;
    mods_.push_back(mod);
    return res;
  }
  mod.return_value = res;

  struct stat post_stat;
  const int post_stat_res = fns_->FnStat(fd_map_[fd].c_str(), &post_stat);
  if (post_stat_res < 0) {
    mod.return_value = post_stat_res;
    mods_.push_back(mod);
    return post_stat_res;
  }

  if (pre_stat.st_size != post_stat.st_size ||
      pre_stat.st_blocks != post_stat.st_blocks) {
    mod.mod_type = DiskMod::kDataMetadataMod;
  } else {
    mod.mod_type = DiskMod::kDataMod;
  }

  if (mode & FALLOC_FL_PUNCH_HOLE) {
    // TODO(ashmrtn): Do we want this here? I'm not sure if it will cause
    // failures that we don't want, though man fallocate(2) says that
    // FALLOC_FL_PUNCH_HOLE must also have FALLOC_FL_KEEP_SIZE.
    assert(mode & FALLOC_FL_KEEP_SIZE);
    mod.mod_opts = DiskMod::kPunchHoleKeepSizeOpt;
  } else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
    mod.mod_opts = DiskMod::kCollapseRangeOpt;
  } else if (mode & FALLOC_FL_ZERO_RANGE) {
    if (mode & FALLOC_FL_KEEP_SIZE) {
      mod.mod_opts = DiskMod::kZeroRangeKeepSizeOpt;
    } else {
      mod.mod_opts = DiskMod::kZeroRangeOpt;
    }
    /*
  } else if (mode & FALLOC_FL_INSERT_RANGE) {
    // TODO(ashmrtn): Figure out how to check with glibc defines.
    mod.mod_opts = DiskMod::kInsertRangeOpt;
    */
  } else if (mode & FALLOC_FL_KEEP_SIZE) {
    mod.mod_opts = DiskMod::kFallocateKeepSizeOpt;
  } else {
    mod.mod_opts = DiskMod::kFallocateOpt;
  }

  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmClose(const int fd) {
  if (fd_map_.find(fd) == fd_map_.end()) {
    const int res = fns_->FnClose(fd);
    DiskMod mod;
    mod.mod_type = DiskMod::kCloseMod;
    mod.mod_opts = DiskMod::kNoneOpt;
    mod.return_value = -1;
    mods_.push_back(mod);
    return -1;
  }
  const int res = fns_->FnClose(fd);

  DiskMod mod;
  mod.mod_type = DiskMod::kCloseMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.return_value = res;
  mods_.push_back(mod);

  if (res >= 0) {
    fd_map_.erase(fd);
  }

  return res;
}

int RecordCmFsOps::CmRename(const string &old_path, const string &new_path) {
  // // check if there are any open files with the old path
  // // change the file descriptors to point to the new path
  // for (auto it = fd_map_.begin(); it != fd_map_.end(); it++) {
  //   string& open_fd_old_path = it->second;
  //   if (open_fd_old_path.compare(old_path) == 0) {
  //     fd_map_[it->first] = new_path;
  //     continue;
  //   }
  //   // if we are renaming a directory that is open; we want to
  //   // change the mapping of the open files in that directory
  //   auto found = open_fd_old_path.find(old_path);
  //   if ( found != std::string::npos) {
  //     fd_map_[it->first].replace(found, old_path.length(), new_path);
  //   }
  // }
  const int res = fns_->FnRename(old_path, new_path);
  if (res >= 0) {
    // check if there are any open files with the old path
    // change the file descriptors to point to the new path
    for (auto it = fd_map_.begin(); it != fd_map_.end(); it++) {
      string& open_fd_old_path = it->second;
      if (open_fd_old_path.compare(old_path) == 0) {
        fd_map_[it->first] = new_path;
        continue;
      }
      // if we are renaming a directory that is open; we want to
      // change the mapping of the open files in that directory
      auto found = open_fd_old_path.find(old_path);
      if ( found != std::string::npos) {
        fd_map_[it->first].replace(found, old_path.length(), new_path);
      }
    }
  }
  DiskMod mod;
  mod.mod_type = DiskMod::kRenameMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = old_path;
  mod.fd = 0;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.directory_mod = false;
  mod.path_mod = true;
  mod.new_path = new_path;
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmUnlink(const string &pathname) {
  const int res = fns_->FnUnlink(pathname.c_str());

  DiskMod mod;
  mod.mod_type = DiskMod::kRemoveMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = pathname;
  mod.fd = 0;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmRemove(const string &pathname) {
  const int res = fns_->FnRemove(pathname.c_str());
  if (res < 0) {
    return res;
  }
  DiskMod mod;
  mod.mod_type = DiskMod::kRemoveMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = pathname;
  mod.fd = 0;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmRmdir(const string &pathname) {
  const int res = fns_->FnRmdir(pathname.c_str());
  DiskMod mod;
  mod.mod_type = DiskMod::kRemoveMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.directory_mod = true;
  mod.path = pathname;
  mod.fd = 0;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmLink(const string &oldpath, const string &newpath) {
  DiskMod mod;
  mod.mod_type = DiskMod::kLinkMod;
  mod.mod_opts = DiskMod::kLinkOpt;
  mod.path = oldpath;
  mod.fd = 0;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.directory_mod = false;
  mod.path_mod = true;
  mod.new_path = newpath;

  const int res = fns_->FnLink(oldpath.c_str(), newpath.c_str());
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmSymlink(const string &oldpath, const string &newpath) {
  string linkpath(newpath);
  // linkpath.erase(0,mnt_dir.size()+1);

  // set up relative target so that the link will be correct when we replay
  string target(oldpath);
  target.erase(0, mnt_dir.size()+1);
  if (target[0] == '.') {
    target.erase(0, 1);
  }
  if (target[0] == '/') {
    target.erase(0, 1);
  }
  // int index = 0; 
  // if (linkpath != ".") {
  //   // if relpath is just ., it refers to the mount point
  //   // in which case we don't need to make any changes 
  //   // otherwise, construct the relative path
  //   while (index < linkpath.size()) {
  //     if (linkpath[index] == '/') {
  //       target = "../" + target;
  //     }
  //     index++;
  //   }
  // }

  const int res = fns_->FnSymlink(target.c_str(), linkpath.c_str(), mnt_dir);

  DiskMod mod;
  mod.mod_type = DiskMod::kLinkMod;
  mod.mod_opts = DiskMod::kSymlinkOpt;
  mod.path = target;
  mod.fd = 0;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.directory_mod = false;
  mod.path_mod = true;
  mod.new_path = linkpath;
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}


int RecordCmFsOps::CmFsync(const int fd) {
  if (fd_map_.find(fd) == fd_map_.end()) {
    const int res = fns_->FnFsync(fd);
    DiskMod mod;
    mod.mod_type = DiskMod::kFsyncMod;
    mod.mod_opts = DiskMod::kNoneOpt;
    mod.path = "";
    mod.return_value = res;
    mods_.push_back(mod);
    return -1;
  }
  
  const int res = fns_->FnFsync(fd);

  DiskMod mod;
  mod.mod_type = DiskMod::kFsyncMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.return_value = res;;
  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmFdatasync(const int fd) {
  if (fd_map_.find(fd) == fd_map_.end()) {
    const int res = fns_->FnFdatasync(fd);
    DiskMod mod;
    mod.mod_type = DiskMod::kFsyncMod;
    mod.mod_opts = DiskMod::kNoneOpt;
    mod.return_value = res;
    mods_.push_back(mod);
    return -1;
  }
  const int res = fns_->FnFdatasync(fd);

  DiskMod mod;
  mod.mod_type = DiskMod::kFsyncMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  mod.mode = 0; // ignored
  mod.flags = 0;
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

void RecordCmFsOps::CmSync() {
  fns_->FnSync();
  
  DiskMod mod;
  mod.mod_type = DiskMod::kSyncMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.return_value = 0;
  mods_.push_back(mod);
}

// int RecordCmFsOps::CmSyncfs(const int fd) {
//   const int res = fns_->FnSyncfs(fd);
//   if (res < 0) {
//     return res;
//   }

//   DiskMod mod;
//   // Or should probably have a kSyncMod type with filepath (?)
//   mod.mod_type = DiskMod::kFsyncMod;
//   mod.mod_opts = DiskMod::kNoneOpt;
//   mod.path = fd_map_.at(fd);
//   mods_.push_back(mod);

//   return res;
// }

int RecordCmFsOps::CmSyncFileRange(const int fd, size_t offset, size_t nbytes,
    unsigned int flags) {
  if (fd_map_.find(fd) == fd_map_.end()) {
    const int res = fns_->FnSyncFileRange(fd, offset, nbytes, flags);
    DiskMod mod;
    mod.mod_type = DiskMod::kSyncFileRangeMod;
    mod.mod_opts = DiskMod::kNoneOpt;
    mod.return_value = res;
    mods_.push_back(mod);
    return -1;
  }
  DiskMod mod;
  mod.mod_type = DiskMod::kSyncFileRangeMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  mod.mode = 0; // ignored
  mod.flags = 0;
  const int res = fns_->FnSyncFileRange(fd, offset, nbytes, flags);
  if (res < 0) {
    mod.return_value = res;
    mods_.push_back(mod);
    return res;
  }
  
  const int post_stat_res = fns_->FnStat(fd_map_.at(fd), &mod.post_mod_stats);
  if (post_stat_res < 0) {
    // TODO(ashmrtn): Some sort of warning here?
    mod.return_value = post_stat_res;
    mods_.push_back(mod);
    return post_stat_res;
  }
  mod.file_mod_location = offset;
  mod.file_mod_len = nbytes;
  mod.return_value = res;
  mods_.push_back(mod);
  return res;
}

// int RecordCmFsOps::CmFchmod(int fd, mode_t mode) {
//   const int res = fns_->FnFchmod(fd, mode);
//   if (fd_map_.find(fd) == fd_map_.end()) {
//     DiskMod mod;
//     mod.mod_type = DiskMod::kMetadataMod;
//     mod.mod_opts = DiskMod::kChmodOpt;
//     mod.return_value = res;
//     mods_.push_back(mod);
//     return -1;
//   }

//   DiskMod mod;
//   mod.mod_type = DiskMod::kMetadataMod;
//   mod.mod_opts = DiskMod::kChmodOpt;
//   mod.path = fd_map_.at(fd);
//   mod.fd = fd;
//   mod.mode = mode;
//   mod.flags = 0;
//   mod.return_value = res;

//   mods_.push_back(mod);
//   return res;
// }

int RecordCmFsOps::CmTruncate(const char *path, off_t length) {
  const int res = fns_->FnTruncate(path, length);

  DiskMod mod;
  mod.mod_type = DiskMod::kDataMetadataMod; // I don't think we need to make a new type of mod; truncate can affect data and metadata but doesn't do anything else we need to keep track of?
  mod.mod_opts = DiskMod::kTruncateOpt;
  mod.path = path;
  mod.fd = 0;
  mod.mode = 0; // ignored
  mod.flags = 0;
  // starts from 0, modifies the following bytes? not sure if this is how we should use this
  mod.file_mod_location = 0;
  mod.file_mod_len = length;
  mod.return_value = res;

  mods_.push_back(mod);
  return res;
}


int RecordCmFsOps::CmFtruncate(const int fd, off_t length) {
  const int res = fns_->FnFtruncate(fd, length);
  if (fd_map_.find(fd) == fd_map_.end()) {
    DiskMod mod;
    mod.mod_type = DiskMod::kDataMetadataMod;
    mod.mod_opts = DiskMod::kTruncateOpt;
    mod.return_value = res;
    mods_.push_back(mod);
    return -1;
  }

  DiskMod mod;
  mod.mod_type = DiskMod::kDataMetadataMod; // I don't think we need to make a new type of mod; truncate can affect data and metadata but doesn't do anything else we need to keep track of?
  mod.mod_opts = DiskMod::kTruncateOpt;
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  mod.mode = 0; // ignored
  mod.flags = 0;
  // starts from 0, modifies the following bytes? not sure if this is how we should use this
  mod.file_mod_location = 0;
  mod.file_mod_len = length;
  mod.return_value = res;

  mods_.push_back(mod);
  return res;
}

int RecordCmFsOps::CmRead(const int fd, void* buf, size_t nbytes) {
  const int res = fns_->FnRead(fd, buf, nbytes);
  if (fd_map_.find(fd) == fd_map_.end()) {
    DiskMod mod;
    mod.mod_type = DiskMod::kReadMod;
    mod.mod_opts = DiskMod::kNoneOpt;
    mod.return_value = res;
    mods_.push_back(mod);
    return -1;
  }
  
  DiskMod mod;
  mod.mod_type = DiskMod::kReadMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.path = fd_map_.at(fd);
  mod.fd = fd;
  mod.mode = 0;
  mod.flags = 0;
  // TOOD: record location of the read?
  mod.return_value = res;

  mods_.push_back(mod);
  return res;
}

int RecordCmFsOps::CmWriteData(int fd, unsigned int offset, unsigned int size) {
  // Offset into a data block to start working at.
  const unsigned int rounded_offset =
    (offset + (kTestDataSize - 1)) & (~(kTestDataSize - 1));
  // Round down size to 4k for number of full pages to write.
  
  const unsigned int aligned_size = (size >= kTestDataSize) ?
    (size - (rounded_offset - offset)) & ~(kTestDataSize - 1) :
    0;
  unsigned int num_written = 0;

  // The start of the write range is not aligned with our data blocks.
  // Therefore, we should write out part of a data block for this segment,
  // with the first character in the data block aligning with the data block
  // boundary.
  if (rounded_offset != offset) {
    // We should never write more than kTestDataSize of unaligned data at the
    // start.
    const unsigned int to_write = (size < rounded_offset - offset) ?
      size : rounded_offset - offset;
    while (num_written < to_write){
      const unsigned int mod_offset =
        (num_written + offset) & (kTestDataSize - 1);
      assert(mod_offset < kTestDataSize);

      int res = CmPwrite(fd, kTestDataBlock + mod_offset, to_write - num_written,
          offset + num_written);
      if (res < 0) {
        return res;
      }
      num_written += res;
    }
  }

  // Write out the required number of full pages for this request. The first
  // byte will be aligned with kTestDataSize.
  unsigned int aligned_written = 0;
  while (aligned_written < aligned_size) {
    const unsigned int mod_offset = (aligned_written & (kTestDataSize - 1));
    // Write up to a full page of data at a time.
    int res = CmPwrite(fd, kTestDataBlock + mod_offset,
        kTestDataSize - mod_offset, offset + num_written);
    if (res < 0) {
      return res;
    }
    num_written += res;
    aligned_written += res;
  } 

  if (num_written == size) {
    return 0;
  }

  // Write out the last partial page of data. The first byte will be aligned
  // with kTestDataSize.
  unsigned int end_written = 0;
  while (num_written < size) {
    assert(end_written < kTestDataSize);
    const unsigned int mod_offset = (end_written & (kTestDataSize - 1));
    int res = CmPwrite(fd, kTestDataBlock + mod_offset,
        size - num_written, offset + num_written);
    if (res < 0) {
      return res;
    }
    num_written += res;
    end_written += res;
  } 

  return 0;
}

int RecordCmFsOps::CmCheckpoint() {
  const int res = fns_->FnCheckpoint();

  DiskMod mod;
  mod.mod_type = DiskMod::kCheckpointMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

int RecordCmFsOps::CmMark() {
  const int res = fns_->FnMark();
  // if (res < 0) {
  //   return res;
  // }

  DiskMod mod;
  mod.mod_type = DiskMod::kMarkMod;
  mod.mod_opts = DiskMod::kNoneOpt;
  mod.return_value = res;
  mods_.push_back(mod);

  return res;
}

// int RecordCmFsOps::WriteWhole(const int fd, const unsigned long long size,
//     shared_ptr<char> data) {
int RecordCmFsOps::WriteWhole(const int fd, const unsigned long long size,
  char* data) {
  unsigned long long written = 0;
  while (written < size) {
    // const int res = write(fd, data.get() + written, size - written);
    const int res = write(fd, data + written, size - written);
    if (res < 0) {
      return res;
    }
    written += res;
  }

  return 0;
}

int RecordCmFsOps::Serialize(const int fd) {
  for (auto &mod : mods_) {
    unsigned long long size;
    // shared_ptr<char> serial_mod = DiskMod::Serialize(mod, &size);
    char* serial_mod = DiskMod::Serialize(mod, &size); // serialize allocates serial_mod, so we'll free it at the end of this function
    if (serial_mod == nullptr) {
      return -1;
    }

    // const int res = WriteWhole(fd, size, serial_mod);
    const int res = WriteWhole(fd, size, serial_mod);
    if (res < 0) {
      delete[] serial_mod;
      return -1;
    }
    delete[] serial_mod;
  }

  return 0;
}



PassthroughCmFsOps::PassthroughCmFsOps(FsFns *functions, string m) {
  fns_ = functions;
  mnt_dir = m;
}

int PassthroughCmFsOps::CmMknod(const string &pathname, const mode_t mode,
    const dev_t dev) {
  return fns_->FnMknod(pathname.c_str(), mode, dev);
}

// int PassthroughCmFsOps::CmFchmod(int fd, mode_t mode) {
//   return fns_->FnFchmod(fd, mode);
// }

int PassthroughCmFsOps::CmMkdir(const string &pathname, const mode_t mode) {
  return fns_->FnMkdir(pathname.c_str(), mode);
}

int PassthroughCmFsOps::CmOpen(const string &pathname, const int flags) {
  return fns_->FnOpen(pathname.c_str(), flags);
}

int PassthroughCmFsOps::CmOpen(const string &pathname, const int flags,
    const mode_t mode) {
  return fns_->FnOpen2(pathname.c_str(), flags, mode);
}

off_t PassthroughCmFsOps::CmLseek(const int fd, const off_t offset,
    const int whence) {
  return fns_->FnLseek(fd, offset, whence);
}

int PassthroughCmFsOps::CmWrite(const int fd, const void *buf,
    const size_t count) {
  return fns_->FnWrite(fd, buf, count);
}

ssize_t PassthroughCmFsOps::CmPwrite(const int fd, const void *buf,
    const size_t count, const off_t offset) {
  return fns_->FnPwrite(fd, buf, count, offset);
}

void * PassthroughCmFsOps::CmMmap(void *addr, const size_t length,
    const int prot, const int flags, const int fd, const off_t offset) {
  return fns_->FnMmap(addr, length, prot, flags, fd, offset);
}

int PassthroughCmFsOps::CmMsync(void *addr, const size_t length,
    const int flags) {
  return fns_->FnMsync(addr, length, flags);
}

int PassthroughCmFsOps::CmMunmap(void *addr, const size_t length) {
  return fns_->FnMunmap(addr, length);
}

int PassthroughCmFsOps::CmFallocate(const int fd, const int mode,
    const off_t offset, off_t len) {
  return fns_->FnFallocate(fd, mode, offset, len);
}

int PassthroughCmFsOps::CmClose(const int fd) {
  return fns_->FnClose(fd);
}

int PassthroughCmFsOps::CmRename(const string &old_path,
    const string &new_path) {
  return fns_->FnRename(old_path, new_path);
}

int PassthroughCmFsOps::CmUnlink(const string &pathname) {
  return fns_->FnUnlink(pathname.c_str());
}

int PassthroughCmFsOps::CmRemove(const string &pathname) {
  return fns_->FnRemove(pathname.c_str());
}

int PassthroughCmFsOps::CmRmdir(const string &pathname) {
  return fns_->FnRmdir(pathname.c_str());
}

int PassthroughCmFsOps::CmLink(const string &oldpath, const string &newpath) {
  return fns_->FnLink(oldpath, newpath);
}

int PassthroughCmFsOps::CmSymlink(const string &oldpath, const string &newpath) {
  string relpath(newpath);
  relpath.erase(0,mnt_dir.size()+1);
  return fns_->FnSymlink(oldpath, relpath, mnt_dir);
}

int PassthroughCmFsOps::CmFsync(const int fd) {
  return fns_->FnFsync(fd);
}

int PassthroughCmFsOps::CmFdatasync(const int fd) {
  return fns_->FnFdatasync(fd);
}

void PassthroughCmFsOps::CmSync() {
  fns_->FnSync();
}

// int PassthroughCmFsOps::CmSyncfs(const int fd) {
//   return fns_->FnSyncfs(fd);
// }

int PassthroughCmFsOps::CmSyncFileRange(const int fd, size_t offset, size_t nbytes,
    unsigned int flags) {
  int ret = fns_->FnSyncFileRange(fd, offset, nbytes, flags);
  return ret;
}

int PassthroughCmFsOps::CmTruncate(const char *path, off_t length) {
  return fns_->FnTruncate(path, length);
}

int PassthroughCmFsOps::CmFtruncate(const int fd, off_t length) {
  return fns_->FnFtruncate(fd, length);
}

int PassthroughCmFsOps::CmRead(const int fd, void* buf, size_t nbytes) {
  return fns_->FnRead(fd, buf, nbytes);
}

int PassthroughCmFsOps::CmWriteData(int fd, unsigned int offset, unsigned int size) {
  // Offset into a data block to start working at.
  const unsigned int rounded_offset =
    (offset + (kTestDataSize - 1)) & (~(kTestDataSize - 1));
  // Round down size to 4k for number of full pages to write.
  
  const unsigned int aligned_size = (size >= kTestDataSize) ?
    (size - (rounded_offset - offset)) & ~(kTestDataSize - 1) :
    0;
  unsigned int num_written = 0;

  // The start of the write range is not aligned with our data blocks.
  // Therefore, we should write out part of a data block for this segment,
  // with the first character in the data block aligning with the data block
  // boundary.
  if (rounded_offset != offset) {
    // We should never write more than kTestDataSize of unaligned data at the
    // start.
    const unsigned int to_write = (size < rounded_offset - offset) ?
      size : rounded_offset - offset;
    while (num_written < to_write){
      const unsigned int mod_offset =
        (num_written + offset) & (kTestDataSize - 1);
      assert(mod_offset < kTestDataSize);

      int res = CmPwrite(fd, kTestDataBlock + mod_offset, to_write - num_written,
          offset + num_written);
      if (res < 0) {
        return res;
      }
      num_written += res;
    }
  }

  // Write out the required number of full pages for this request. The first
  // byte will be aligned with kTestDataSize.
  unsigned int aligned_written = 0;
  while (aligned_written < aligned_size) {
    const unsigned int mod_offset = (aligned_written & (kTestDataSize - 1));
    // Write up to a full page of data at a time.
    int res = CmPwrite(fd, kTestDataBlock + mod_offset,
        kTestDataSize - mod_offset, offset + num_written);
    if (res < 0) {
      return res;
    }
    num_written += res;
    aligned_written += res;
  } 

  if (num_written == size) {
    return 0;
  }

  // Write out the last partial page of data. The first byte will be aligned
  // with kTestDataSize.
  unsigned int end_written = 0;
  while (num_written < size) {
    assert(end_written < kTestDataSize);
    const unsigned int mod_offset = (end_written & (kTestDataSize - 1));
    int res = pwrite(fd, kTestDataBlock + mod_offset,
        size - num_written, offset + num_written);
    if (res < 0) {
      return res;
    }
    num_written += res;
    end_written += res;
  } 

  return 0;
}

int PassthroughCmFsOps::CmCheckpoint() {
  return fns_->FnCheckpoint();
}

int PassthroughCmFsOps::CmMark() {
  return fns_->FnMark();
}

} // api
} // user_tools
} // fs_testing
