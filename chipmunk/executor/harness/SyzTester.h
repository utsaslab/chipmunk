#ifndef CODE_SYZTESTER_H
#define CODE_SYZTESTER_H

#include <string>
#include <vector>
#include <fstream>
#include <map>

#include "../utils/ClassLoader.h"
#include "../tests/BaseTestCase.h"
#include "../results/TestSuiteResult.h"
#include "../ioctl.h"
#include "Tester.h"
#include "../tester_defs.h"


namespace fs_testing {

class SyzTester : public Tester {
public:
    SyzTester(std::string p,
                  std::string r,
                  std::string m,
                  std::string rm,
                  unsigned long start,
                  unsigned long size,
                  std::string f,
                  bool d,
                  std::string o,
                  unsigned long long mod,
                  int threads, bool coverage,
                  unsigned long input_data,
                  uint32_t* output_data,
                  bool flag_collect_cover,
                  bool flag_dedup_cover,
                  thread_t* th,
                  bool mountCov,
                  unsigned long replay_pm,
                  std::string instanceId,
                  int maxk);

    virtual ~SyzTester() {}

    void setOutputPos(uint32_t* output_pos);

    int cleanup(std::ofstream &log);

    void setup();

    int resetLogger();

     int curSys;
    std::vector<std::vector<FILE*> > fptr_map; // TODO: do we still use this?
    bool collect_cover;
    std::ofstream logfile;

private:
    bool captureCoverage;

    unsigned long input_data;
    std::string instanceId;
    
    bool dedup_cover;

    int kOutFd;

    bool is64bit = true;
};

}

#endif
