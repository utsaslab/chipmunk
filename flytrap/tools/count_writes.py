import argparse
import os
import re
import statistics

syscalls = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    17: "pread64",
    18: "pwrite64",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    266: "symlinkat",
    285: "fallocate"
}

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("logdirs", type=str, nargs="*", help="list of paths representing the directories containing logs to process")
    parser.add_argument("outfile", type=str, help="csv file to write output to")

    args = parser.parse_args()

    return args

def main():
    args = parse_arguments()

    logdirs = args.logdirs
    
    outfile = args.outfile
    if os.path.exists(outfile):
        os.remove(outfile)
    outf = open(outfile, "a")
    outf.write("syscall,mean,median,mode,max,\n")

    write_count = 0
    current_syscall = None
    counts = {}

    for logdir in logdirs:
        if logdir[-1] != "/":
            logdir += "/"
        for filename in os.listdir(logdir):
            current_syscall = None
            if filename != ".gitignore":
                with open(logdir+filename) as f:
                    for line in f:
                        if line.startswith("CLWB"):
                            write_count += 1
                        elif line.startswith("NT"):
                            write_count += 1
                        elif line.startswith("SFENCE"):
                            if current_syscall != None:
                                counts[current_syscall][-1].append(write_count)
                            write_count = 0
                        elif line.startswith("MARK SYS") and not line.startswith("MARK SYS END"):
                            # obtain the system call number
                            pattern = "MARK SYS (\d+),"
                            res = re.match(pattern, line)
                            assert(res != None)
                            current_syscall = int(res.group(1))
                            if not current_syscall in counts:
                                counts[current_syscall] = []
                            counts[current_syscall].append([])

    for syscall in counts.keys():
        print(syscalls[syscall], "stats: ")
        outf.write(syscalls[syscall] + ",")

        count_list = counts[syscall]

        # get mean, median, mode number of writes
        sum = 0
        total = 0
        mode_map = {}
        all_writes = []
        for l1 in count_list:
            for l2 in l1:
                # don't count entries caused by redundant fences - they will 
                # artificially lower the counts 
                if l2 != 0:
                    sum += l2 
                    total += 1
                    if l2 in mode_map:
                        mode_map[l2] += 1
                    else:
                        mode_map[l2] = 1
                    all_writes.append(l2)
        if (total > 0):
            mean = sum / total
            print("\tmean:", str(mean))
            outf.write(str(mean) + ",")

            all_writes.sort()
            median = statistics.median(all_writes)
            print("\tmedian:", median)
            outf.write(str(median) + ",")

            mode = 0
            for count in mode_map.keys():
                if mode_map[count] > mode:
                    mode = count
            print("\tmode:", mode)
            outf.write(str(mode) + ",")

            max = all_writes[-1]
            print("\tmax:", str(max))
            outf.write(str(max) + ",\n")

        else:
            print("\tsyscall had no writes to PM")
            outf.write(",,,,\n")

    outf.close()

main()