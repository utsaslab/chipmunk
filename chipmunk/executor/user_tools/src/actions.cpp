#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <cerrno>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <iostream>

#include "../api/actions.h"
#include "../../ioctl.h"

// #include "../../utils/communication/ClientCommandSender.h"

namespace fs_testing {
namespace user_tools {
namespace api {

// using fs_testing::utils::communication::ClientCommandSender;
// using fs_testing::utils::communication::kSocketNameOutbound;
// using fs_testing::utils::communication::SocketMessage;

int Checkpoint() {
    int val = 0;
    int fd;

    fd = open("/dev/ioctl_dummy", 0);
    // if we fail to open and it's because the device isn't there,
    // we can assume that we are in the profiling stage and it's okay
    // that we can't open. Skipping this error is easier than loading 
    // the module and turning off logging until we need it
    if (fd < 0) {
        if (errno != ENOENT) {
            perror("open");
            return fd;
        }
    }
    else {
        val = ioctl(fd, LOGGER_CHECKPOINT, NULL);
        if (val < 0) {
            perror("LOGGER_CHECKPOINT");
            close(fd);
            return val;
        }
    }

    return 0;
}

int Mark() {
    int val = 0;
    int fd;

    fd = open("/dev/ioctl_dummy", 0);
    // if we fail to open and it's because the device isn't there,
    // we can assume that we are in the profiling stage and it's okay
    // that we can't open. Skipping this error is easier than loading 
    // the module and turning off logging until we need it
    if (fd < 0) {
        if (errno != ENOENT) {
            perror("open");
            return fd;
        }
    }
    else {
        val = ioctl(fd, LOGGER_MARK, NULL);
        if (val < 0) {
            perror("LOGGER_MARK");
            close(fd);
            return val;
        }
    }

    return 0;
}

} // fs_testing
} // user_tools
} // api
