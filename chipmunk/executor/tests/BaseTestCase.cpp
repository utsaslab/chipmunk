#include "BaseTestCase.h"

namespace fs_testing {
namespace tests {

using std::string;

using fs_testing::user_tools::api::CmFsOps;
using fs_testing::user_tools::api::DefaultFsFns;
using fs_testing::user_tools::api::RecordCmFsOps;
using fs_testing::user_tools::api::PassthroughCmFsOps;

int BaseTestCase::init_values(string mount_dir, long filesys_size, int threads) {
  mnt_dir_ = mount_dir;
  filesys_size_ = filesys_size;
  num_threads = threads;
  return 0;
}

int BaseTestCase::Run(const int change_fd, const int checkpoint) {
  DefaultFsFns default_fns;
  // default_fns.setCoverage(captureCoverage);
  RecordCmFsOps cm(&default_fns, mnt_dir_);
  PassthroughCmFsOps pcm(&default_fns, mnt_dir_);
  if (checkpoint == 0) {
    cm_ = &cm;
    test_threads = 1;
  } else {
    cm_ = &pcm;
    test_threads = num_threads;
  }

  int res_1 = run(checkpoint);
  if (res_1 < 0) {
    return res_1;
  }

  if (checkpoint == 0) {
    int res_2 = cm.Serialize(change_fd);
    if (res_2 < 0) {
      return res_2;
    }
  }
  return res_1;
}

}  // namespace tests
}  // namespace fs_testing
