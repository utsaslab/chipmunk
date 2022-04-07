#ifndef CODE_ACETESTER_H
#define CODE_ACETESTER_H

#include <string>
#include <vector>
#include <fstream>
#include <map>

#include "../utils/ClassLoader.h"
#include "../tests/BaseTestCase.h"
#include "../results/TestSuiteResult.h"
#include "../ioctl.h"
#include "Tester.h"

namespace fs_testing{

class AceTester : public Tester {
public:
    AceTester(std::string p,
                  std::string r,
                  std::string m,
                  std::string rm,
                  unsigned long start,
                  unsigned long size,
                  std::string k,
                  std::string f,
                  bool d,
                  std::string o,
                  unsigned long long mod,
                  int threads, bool coverage,
                  unsigned long replay_pm,
                  int maxk);

    ~AceTester() {};

    int cleanup(std::ofstream& log);

    int test_init_values(std::string mountDir, long filesysSize, int threads);

    int test_load_class(const char *path);

    void test_unload_class();

    int test_run(const int change_fd, const int checkpoint, std::ofstream &log);

    // int GetChangeData(const int fd);

    bool test_replay(std::ofstream &log, int checkpoint, std::string test_name, bool make_trace, bool reorder);

    bool test_replay_internal(std::ofstream &log, int checkpoint, std::string replay_img_path);

};

}

#endif