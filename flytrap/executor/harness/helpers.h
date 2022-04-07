#ifndef HARNESS_HELPERS_H
#define HARNESS_HELPERS_H

#include <string>
#include <iostream>
#include <cassert>
#include <map>
#include <set>

using std::string;
using std::map;
using std::set;

struct paths {
    string canonical_path;
    string relative_path;
};

// remove .. from the given filepath
// this function doesn't do anything if the path does not include .., 
// so it is idempotent.
// TODO: realpath can replace this in most cases. sometimes we need this 
// function for files that don't exist anymore due to deletion or renames though
static string fix_filepath(string path) {
    size_t found;
    string pattern = "..";
    // iterates until it has eliminated all of the ..'s in the path,
    // removing one on each iteration
    while (true) {
        // this will find the first instance of .. in the path
        found = path.find(pattern);

        // we have a problem if .. is the first part of the path
        assert(found != 0);

        if (found != string::npos) {
            // search backwards through the path to find the part to remove
            // start from two characters back to exclude the preceding /
            size_t cur = found - 2; 
            while (cur >= 0) {
                if (path[cur] == '/') {
                    break;
                }
                cur--;
            }
            assert(cur != 0);
            path = path.substr(0, cur) + path.substr(found+2, string::npos);
        } else {
            break;
        }
    }
    return path;
}

// should only be called when path is a symlink target beginning with ..
// or is just "."
static string fix_symlink_target(string path, string mount_point) {
    if (path.size() == 1) {
        return mount_point;
    }
    string target = path;
    while (target[0] == '.') {
        target.erase(0, 3);
    }

    target = mount_point + target;
    return target;
}

// deep copy an element of the inum_to_files map so that we can keep a record of how 
// file linkages changed over the course of a workload
static map<int, set<string> > deep_copy_inum_map(map<int, set<string> > inum2files) {
    map<int, set<string> > map_copy;
    for (map<int, set<string> >::iterator it = inum2files.begin(); it != inum2files.end(); it++) {
        set<string> new_set(it->second);
        map_copy[it->first] = new_set;
    }
    return map_copy;
}

#endif