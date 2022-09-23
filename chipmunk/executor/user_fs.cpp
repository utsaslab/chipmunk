#if USERFS != USERFS_DISABLED
#include "user_fs.h"
#include <iostream>

using namespace std;

// This is not thread safe

static int initialized = 0;

static int init_splitfs(string mount_point) {
    if(initialized != 0) {
        cout << "Trying to initialize usplit when it has already been initialized. Crashing" << endl;
        exit(1);
    }

    cout << "Initializing u-split at " << mount_point << endl;
    init_splitfs(mount_point); // "/mnt/pmem_emul/"

    initialized = 1;
    return 0;
}

static int shutdown_splitfs() {
    if(initialized == 0) {
        cout << "Trying to shutdown usplit when it has not yet been initialized. Crashing" << endl;
        exit(1);
    }

    cout << "Shutting down u-split" << endl;

    shutdown_splitfs();

    initialized = 0;

    return 0;
}

int init_userspacefs(string mount_point) {
#if USERFS == USERFS_SPLITFS
    return init_splitfs(mount_point);
#else 
    cout << "Fatal error: Trying to initialize unknown user fs. Check USERFS macro" << endl;
    exit(1);
#endif
}

int shutdown_userspacefs() {
#if USERFS == USERFS_SPLITFS
    return shutdown_splitfs();
#else 
    cout << "Fatal error: Trying to shutdown unknown user fs. Check USERFS macro" << endl;
    exit(1);
#endif
}
#endif