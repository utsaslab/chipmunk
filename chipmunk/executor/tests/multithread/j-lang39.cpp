#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <dirent.h>
#include <cstring>
#include <errno.h>
#include <pthread.h>
#include <vector>
// #include <attr/xattr.h>

#include "../BaseTestCase.h"
#include "../../user_tools/api/workload.h"
#include "../../user_tools/api/actions.h"

using fs_testing::tests::DataTestResult;
using fs_testing::user_tools::api::WriteData;
using fs_testing::user_tools::api::WriteDataMmap;
using fs_testing::user_tools::api::Checkpoint;
using std::string;
using std::vector;

#define TEST_FILE_PERMS  ((mode_t) (S_IRWXU | S_IRWXG | S_IRWXO))

struct t_args {
	fs_testing::user_tools::api::CmFsOps *cm_;
	string mnt_dir_;
};
intptr_t fail = -1;
int error;

void* run_thread(void* varg) {
	struct t_args *args = (struct t_args*)varg;
	fs_testing::user_tools::api::CmFsOps *cm_ = args->cm_;
	string mnt_dir_(args->mnt_dir_);
	string test_path = mnt_dir_; 
	string A_path = mnt_dir_ + "/A";
	string AC_path = mnt_dir_ + "/A/C";
	string B_path = mnt_dir_ + "/B";
	string foo_path = mnt_dir_ + "/foo";
	string bar_path = mnt_dir_ + "/bar";
	string Afoo_path = mnt_dir_ + "/A/foo";
	string Abar_path = mnt_dir_ + "/A/bar";
	string Bfoo_path = mnt_dir_ + "/B/foo";
	string Bbar_path = mnt_dir_ + "/B/bar";
	string ACfoo_path = mnt_dir_ + "/A/C/foo";
	string ACbar_path = mnt_dir_ + "/A/C/bar";

	if ( cm_->CmMkdir(A_path.c_str() , 0777) < 0){ 
		if (errno != EEXIST) {
			 return &fail;
		}
	}

	int fd_Afoo = cm_->CmOpen(Afoo_path.c_str() , O_RDWR|O_CREAT , 0777); 
	if ( fd_Afoo < 0 ) { 
		if(errno != ENOENT) {
			return &fail;
		} else {
			return NULL;
		}
	}


	if ( cm_->CmClose ( fd_Afoo) < 0){ 
		return &fail;
	}


	if ( cm_->CmMark() < 0){
		return &fail;
	}


	if ( cm_->CmRename (Afoo_path.c_str() , bar_path.c_str() ) < 0){ 
		if (errno != ENOENT) {
			return &fail;
		}
	}

	if ( cm_->CmCheckpoint() < 0){ 
		return &fail;
	}
//	local_checkpoint += 1; 
//	if (local_checkpoint == checkpoint) { 
//		return 1;
//	}




    return NULL;
}

namespace fs_testing {
    namespace tests {
        
        
        class testName: public BaseTestCase {
            
            public:
            
            virtual int setup() override {
				test_path = mnt_dir_ ;
				A_path = mnt_dir_ + "/A";
				AC_path = mnt_dir_ + "/A/C";
				B_path = mnt_dir_ + "/B";
				foo_path = mnt_dir_ + "/foo";
				bar_path = mnt_dir_ + "/bar";
				Afoo_path = mnt_dir_ + "/A/foo";
				Abar_path = mnt_dir_ + "/A/bar";
				Bfoo_path = mnt_dir_ + "/B/foo";
				Bbar_path = mnt_dir_ + "/B/bar";
				ACfoo_path = mnt_dir_ + "/A/C/foo";
				ACbar_path = mnt_dir_ + "/A/C/bar";
                
                return 0;
            }
            
            virtual int run( int checkpoint ) override {
				test_path = mnt_dir_ ;
				A_path =  mnt_dir_ + "/A";
				AC_path =  mnt_dir_ + "/A/C";
				B_path =  mnt_dir_ + "/B";
				foo_path =  mnt_dir_ + "/foo";
				bar_path =  mnt_dir_ + "/bar";
				Afoo_path =  mnt_dir_ + "/A/foo";
				Abar_path =  mnt_dir_ + "/A/bar";
				Bfoo_path =  mnt_dir_ + "/B/foo";
				Bbar_path =  mnt_dir_ + "/B/bar";
				ACfoo_path =  mnt_dir_ + "/A/C/foo";
				ACbar_path =  mnt_dir_ + "/A/C/bar";
				int local_checkpoint = 0 ;
				void* ret;
				int retval = 0;
				struct t_args args;
				args.cm_ = cm_;
				args.mnt_dir_ = mnt_dir_;
				vector<pthread_t> pvec;
				for (int i = 0; i < test_threads; i++) {
					pthread_t tid;
					pthread_create(&tid, NULL, run_thread, &args);
					pvec.push_back(tid);
				}
				for (int i = 0; i < test_threads; i++) {
					pthread_join(pvec[i], &ret);
					if ((intptr_t)ret != 0) {
						retval = (intptr_t)ret;
					}
				}
                
                return retval;
            }
            
            virtual int check_test( unsigned int last_checkpoint, DataTestResult *test_result) override {
				test_path = mnt_dir_ ;
				A_path =  mnt_dir_ + "/A";
				AC_path =  mnt_dir_ + "/A/C";
				B_path =  mnt_dir_ + "/B";
				foo_path =  mnt_dir_ + "/foo";
				bar_path =  mnt_dir_ + "/bar";
				Afoo_path =  mnt_dir_ + "/A/foo";
				Abar_path =  mnt_dir_ + "/A/bar";
				Bfoo_path =  mnt_dir_ + "/B/foo";
				Bbar_path =  mnt_dir_ + "/B/bar";
				ACfoo_path =  mnt_dir_ + "/A/C/foo";
				ACbar_path =  mnt_dir_ + "/A/C/bar";
                
                return 0;
            }
                       
            private:
			 string test_path; 
			 string A_path; 
			 string AC_path; 
			 string B_path; 
			 string foo_path; 
			 string bar_path; 
			 string Afoo_path; 
			 string Abar_path; 
			 string Bfoo_path; 
			 string Bbar_path; 
			 string ACfoo_path; 
			 string ACbar_path; 
                       
                       
            };
                       
    }  // namespace tests
    }  // namespace fs_testing
                       
   extern "C" fs_testing::tests::BaseTestCase *test_case_get_instance() {
       return new fs_testing::tests::testName;
   }
                       
   extern "C" void test_case_delete_instance(fs_testing::tests::BaseTestCase *tc) {
       delete tc;
   }
