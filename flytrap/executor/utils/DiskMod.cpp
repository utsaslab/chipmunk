#include "DiskMod.h"

#include <assert.h>
#include <endian.h>
#include <string.h>
#include <iostream>

namespace fs_testing {
namespace utils {

using std::shared_ptr;
using std::vector;
using std::cout;
using std::endl;

uint64_t DiskMod::GetSerializeSize() {
  // mod_type, mod_opts, and a uint64_t for the size of the serialized mod.
  // plus an int for the return value; return value should go early because lseek can fail
  uint64_t res = (2 * sizeof(uint16_t)) + sizeof(uint64_t) + sizeof(int);

  if (mod_type == DiskMod::kCheckpointMod || mod_type == DiskMod::kSyncMod ||
      mod_type == DiskMod::kLseekMod || mod_type == DiskMod::kMarkMod) {
    return res;
  }

  res += sizeof(bool);  // path mod
  res += sizeof(bool);  // directory_mod.

  res += path.size() + 1;  // size() doesn't include null terminator.

  res += sizeof(mode_t);
  res += sizeof(int);

  res += sizeof(int); // fd

  if (mod_type == DiskMod::kFsyncMod ||
      mod_type == DiskMod::kRemoveMod ||
      mod_type == DiskMod::kCreateMod || 
      mod_type == DiskMod::kOpenMod ||
      mod_type == DiskMod::kCloseMod) {
    return res;
  }

  if (mod_type == DiskMod::kSyncFileRangeMod ||
      mod_opts == DiskMod::kFallocateOpt ||
      mod_opts == DiskMod::kFallocateKeepSizeOpt ||
      mod_opts == DiskMod::kPunchHoleKeepSizeOpt ||
      mod_opts == DiskMod::kCollapseRangeOpt ||
      mod_opts == DiskMod::kZeroRangeOpt ||
      mod_opts == DiskMod::kZeroRangeKeepSizeOpt ||
      mod_opts == DiskMod::kInsertRangeOpt) {
    // Do not contain the data for the range, just the offset and length.
    res += 2 * sizeof(uint64_t);
    return res;
  }

  if (path_mod) {
    res += new_path.size() + 1;
  }
  
  if (directory_mod) {
    // res += new_path.size() + 1;  // Path changed in directory.
    res += directory_added_entry.size() + 1;  // Path changed in directory.
  } else {
    // Data changed, location of change, length of change.
    res += 2 * sizeof(uint64_t);
    return res + file_mod_len;
  }

  return res;
}

/*
 * The basic serialized format is as follows:
 *    * uint64_t size of following region in bytes
 *    * uint16_t mod_type
 *    * uint16_t mod_opts
 *    ~~~~~~~~~~~~~~~~~~~~    <-- End of entry if kCheckpointMod.
 *    * null-terminated string for path the mod refers to (ex. file path)
 *    * 1-byte path_mod boolean
 *    * 1-byte directory_mod boolean
 *    ~~~~~~~~~~~~~~~~~~~~    <-- End of ChangeHeader function data.
 *    * null-terminated string for new path that the mod refers to (ex. path renamed to)
 *    ~~~~~~~~~~~~~~~~~~~~
 *    * uint64_t file_mod_location
 *    * uint64_t file_mod_len
 *    * <file_mod_len>-bytes of file mod data
 *
 * The final three lines of this layout are specific only to modifications on
 * files. Modifications to directories are not yet supported, though there are
 * some structures that may be used to help track them.
 *
 * All multi-byte data fields in the serialized format use big endian encoding.
 */

/*
 * Make things miserable on myself, and only store either the directory or the
 * file fields based on the value of directory_mod.
 *
 * Convert everything to big endian for the sake of reading dumps in a
 * consistent manner if need be.
 */
// shared_ptr<char> DiskMod::Serialize(DiskMod &dm, unsigned long long *size) {
char* DiskMod::Serialize(DiskMod &dm, unsigned long long *size) {
  // Standard code to serialize the front part of the DiskMod.
  // Get a block large enough for this DiskMod.
  uint64_t mod_size = dm.GetSerializeSize();
  if (size != nullptr) {
    *size = mod_size;
  }
  char* buf = new char[mod_size];
  // TODO(ashmrtn): May want to split this if it is very large.
  // shared_ptr<char> res_ptr(new (std::nothrow) char[mod_size],
  //     [](char *c) {delete[] c;});
  // shared_ptr<char> res_ptr(buffer, [](char *c) {delete[] c;});
  // char *buf = res_ptr.get();
  if (buf == nullptr) {
    // return res_ptr;
    return nullptr;
  }

  const uint64_t mod_size_be = htobe64(mod_size);
  memcpy(buf, &mod_size_be, sizeof(uint64_t));
  unsigned int buf_offset = sizeof(uint64_t);

  int res = SerializeHeader(buf, buf_offset, dm);
  if (res < 0) {
    printf("6.5\n");
    delete[] buf;
    // return shared_ptr<char>(nullptr);
    return nullptr;
  }
  buf_offset += res;

  if (dm.mod_type == DiskMod::kLseekMod) {
    cout << "SERIALIZING LSEEK" << endl;
  }

  // kCheckpointMod and kSyncMod don't need anything done after the type.
  if (!(dm.mod_type == DiskMod::kCheckpointMod ||
      dm.mod_type == DiskMod::kSyncMod ||
      dm.mod_type == DiskMod::kLseekMod ||
      dm.mod_type == DiskMod::kMarkMod)) {
    res = SerializeChangeHeader(buf, buf_offset, dm);
    if (res < 0) {
      printf("9\n");
      delete[] buf;
      // return shared_ptr<char>(nullptr);
      return nullptr;
    }

    if (dm.mod_type == DiskMod::kFsyncMod ||
        dm.mod_type == DiskMod::kCreateMod ||
        dm.mod_type == DiskMod::kRemoveMod ||
        dm.mod_type == DiskMod::kOpenMod ||
        dm.mod_type == DiskMod::kCloseMod ||
        dm.mod_type == DiskMod::kReadMod) {
          return buf;
      // return res_ptr;
    }

    buf_offset += res;

    if (dm.path_mod) {
      // serialize path_mod and new_path
      res = SerializeNewPath(buf, buf_offset, dm);
      if (res < 0) {
        printf("10\n");
        delete[] buf;
        return nullptr;
      }
      buf_offset += res;
    }
    
    // if (dm.directory_mod) {
    //   // We changed a directory, only put that down.
    //   res = SerializeDirectoryMod(buf, buf_offset, dm);
    //   if (res < 0) {
    //     // return shared_ptr<char>(nullptr);
    //     delete[] buf;
    //     return nullptr;
    //   }
    //   buf_offset += res;
    // } else {
      // TODO(ashmrtn): *Technically* fallocate and friends can be called on a
      // directory file descriptor. The current code will not play well with
      // that.
      // We changed a file, only put that down.
      res = SerializeDataRange(buf, buf_offset, dm);
      if (res < 0) {
        printf("11\n");
        delete[] buf;
        // return shared_ptr<char>(nullptr);
        return nullptr;
      }
      buf_offset += res;
    // }
  }

  // return res_ptr;
  return buf;
}

int DiskMod::SerializeHeader(char *buf, const unsigned int buf_offset,
    DiskMod &dm) {
  buf = buf + buf_offset;
  uint16_t mod_type = htobe16((uint16_t) dm.mod_type);
  uint16_t mod_opts = htobe16((uint16_t) dm.mod_opts);
  memcpy(buf, &mod_type, sizeof(uint16_t));
  buf += sizeof(uint16_t);
  memcpy(buf, &mod_opts, sizeof(uint16_t));
  buf += sizeof(uint16_t);
  int32_t retval = htobe32((int32_t) dm.return_value);
  memcpy(buf, &retval, sizeof(int));
  
  return 2 * sizeof(uint16_t) + sizeof(int32_t);
}

int DiskMod::SerializeChangeHeader(char *buf,
    const unsigned int buf_offset, DiskMod &dm) {
  buf += buf_offset;
  unsigned int size = dm.path.size() + 1;
  // Add the path that was changed to the buffer.
  // size() doesn't include null-terminator.
  // TODO(ashmrtn): The below assumes 1 character per byte encoding.
  memcpy(buf, dm.path.c_str(), size);
  buf += size;
  mode_t mode = htobe32((mode_t) dm.mode);
  memcpy(buf, &mode, sizeof(mode_t));
  buf += sizeof(mode_t);

  int flags = htobe32((int) dm.flags);
  memcpy(buf, &flags, sizeof(int));
  buf += sizeof(int);

  int fd = htobe32((int) dm.fd);
  memcpy(buf, &fd, sizeof(int));
  buf += sizeof(int);

  // add path_mod to buffer
  uint8_t mod_path_mod = dm.path_mod;
  memcpy(buf, &mod_path_mod, sizeof(uint8_t));
  buf += sizeof(uint8_t);
  // printf("%c\n", buf);

  // Add directory_mod to buffer.
  uint8_t mod_directory_mod = dm.directory_mod;
  memcpy(buf, &mod_directory_mod, sizeof(uint8_t));

  return size + sizeof(mode_t) + sizeof(int) + sizeof(int) + sizeof(uint8_t) + sizeof(uint8_t);
}

int DiskMod::SerializeDataRange(char *buf, const unsigned int buf_offset,
    DiskMod &dm) {
  buf += buf_offset;
  // Add file_mod_location.
  uint64_t file_mod_location = htobe64(dm.file_mod_location);
  memcpy(buf, &file_mod_location, sizeof(uint64_t));
  buf += sizeof(uint64_t);

  // Add file_mod_len.
  uint64_t file_mod_len = htobe64(dm.file_mod_len);
  memcpy(buf, &file_mod_len, sizeof(uint64_t));
  buf += sizeof(uint64_t);

  if (dm.mod_type == DiskMod::kSyncFileRangeMod ||
      dm.mod_opts == DiskMod::kFallocateOpt ||
      dm.mod_opts == DiskMod::kFallocateKeepSizeOpt ||
      dm.mod_opts == DiskMod::kPunchHoleKeepSizeOpt ||
      dm.mod_opts == DiskMod::kCollapseRangeOpt ||
      dm.mod_opts == DiskMod::kZeroRangeOpt ||
      dm.mod_opts == DiskMod::kZeroRangeKeepSizeOpt ||
      dm.mod_opts == DiskMod::kInsertRangeOpt ||
      (dm.mod_type == DiskMod::kDataMetadataMod && dm.mod_opts == DiskMod::kTruncateOpt)) {
    // kSyncFileRangeMod does not contain the data range, just the offset and
    // length.
    return 2 * sizeof(uint64_t);
  }

  // Add file_mod_data (non-null terminated).
  memcpy(buf, dm.file_mod_data.get(), dm.file_mod_len);

  return (2 * sizeof(uint64_t)) + dm.file_mod_len;
}

int DiskMod::SerializeDirectoryMod(char *buf, const unsigned int buf_offset,
    DiskMod &dm) {
  // assert(0 && "Not implemented");
  // buf += buf_offset;
  // unsigned int size = dm.new_path.size() + 1;
  // memcpy(buf, dm.new_path.c_str(), size);
  // buf += size;

  // return size;
}

int DiskMod::SerializeNewPath(char *buf, const unsigned int buf_offset,
    DiskMod &dm) {
  buf += buf_offset;
  unsigned int size = dm.new_path.size() + 1;
  memcpy(buf, dm.new_path.c_str(), size);
  buf += size;

  return size;
}

char* deserialize_string(std::string &path, char* data_ptr) {
  // read in the null-terminated path string
  // Small buffer to read characters into so we aren't adding to a string one
  // character at a time until the end of the string.
  const unsigned int tmp_size = 128;
  char tmp[tmp_size];
  memset(tmp, 0, tmp_size);
  unsigned int chars_read = 0;
  while (data_ptr[0] != '\0') {
    // We still haven't seen a null terminator, so read another character.
    tmp[chars_read] = data_ptr[0];
    ++chars_read;
    if (chars_read == tmp_size - 1) {
      // Fall into this at one character short so that we have an automatic null
      // terminator
      path += tmp;
      chars_read = 0;
      // Required because we just add the char[] to the string and we don't want
      // extra junk. An alternative would be to make sure you always had a null
      // terminator the character after the one that was just assigned.
      memset(tmp, 0, tmp_size);
    }
    ++data_ptr;
  }
  // Add the remaining data that is in tmp.
  path += tmp;
  // Move past the null terminating character.
  ++data_ptr;
  return data_ptr;
  
}

int DiskMod::Deserialize(shared_ptr<char> data, DiskMod &res) {
  res.Reset();
  // Skip the first uint64 which is the size of this region. This is a blind
  // deserialization of the object!
  char *data_ptr = data.get();
  data_ptr += sizeof(uint64_t);

  // read in the mod type
  uint16_t mod_type;
  uint16_t mod_opts;
  mode_t mode;
  int return_value;
  int flags;
  int fd;
  memcpy(&mod_type, data_ptr, sizeof(uint16_t));
  data_ptr += sizeof(uint16_t);
  res.mod_type = (DiskMod::ModType) be16toh(mod_type);

  // read in the mod opts
  memcpy(&mod_opts, data_ptr, sizeof(uint16_t));
  data_ptr += sizeof(uint16_t);
  res.mod_opts = (DiskMod::ModOpts) be16toh(mod_opts);

  // read in the return value
  memcpy(&return_value, data_ptr, sizeof(int32_t));
  data_ptr += sizeof(int32_t);
  res.return_value = (int32_t)be32toh(return_value);

  if (res.mod_type == DiskMod::kCheckpointMod ||
    res.mod_type == DiskMod::kSyncMod || 
    res.mod_type == DiskMod::kLseekMod || 
    res.mod_type == DiskMod::kMarkMod || 
    res.mod_type == DiskMod::kReadMod) {
    // No more left to do here.
    return 0;
  }

  data_ptr = deserialize_string(res.path, data_ptr);
  memcpy(&mode, data_ptr, sizeof(mode_t));
  res.mode = (mode_t) be32toh(mode);
  data_ptr += sizeof(mode_t);

  memcpy(&flags, data_ptr, sizeof(int));
  res.flags = (int) be32toh(flags);
  data_ptr += sizeof(int);

  memcpy(&fd, data_ptr, sizeof(int));
  res.fd = (int) be32toh(fd);
  data_ptr += sizeof(int);

  // read in whether this modified multiple file paths 
  res.path_mod = (bool) data_ptr[0];
  ++data_ptr;

  // read in whether this is a directory mod or not
  res.directory_mod = (bool) data_ptr[0];
  ++data_ptr;

  if (res.mod_type == DiskMod::kFsyncMod ||
      res.mod_type == DiskMod::kCreateMod ||
      res.mod_type == DiskMod::kRemoveMod ||
      res.mod_type == DiskMod::kOpenMod ||
      res.mod_type == DiskMod::kCloseMod) {
    return 0;
  }

  if (res.path_mod) {
    data_ptr = deserialize_string(res.new_path, data_ptr);
  }

  // // deserialize info about a file content update or a rename operation
  // if (res.directory_mod) {
  //   // data_ptr = deserialize_string(res.new_path, data_ptr);
  //   assert(0 && "Directory mod deserialization not supported");
  // }  else { 
    uint64_t file_mod_location;
    uint64_t file_mod_len;
    memcpy(&file_mod_location, data_ptr, sizeof(uint64_t));
    data_ptr += sizeof(uint64_t);
    file_mod_location = be64toh(file_mod_location);
    res.file_mod_location = file_mod_location;

    memcpy(&file_mod_len, data_ptr, sizeof(uint64_t));
    data_ptr += sizeof(uint64_t);
    file_mod_len = be64toh(file_mod_len);
    res.file_mod_len = file_mod_len;

    // Some mods have file length and location, but no actual data associated with
    // them.
    if (res.mod_type == DiskMod::kSyncFileRangeMod ||
        res.mod_opts == DiskMod::kFallocateOpt ||
        res.mod_opts == DiskMod::kFallocateKeepSizeOpt ||
        res.mod_opts == DiskMod::kPunchHoleKeepSizeOpt ||
        res.mod_opts == DiskMod::kCollapseRangeOpt ||
        res.mod_opts == DiskMod::kZeroRangeOpt ||
        res.mod_opts == DiskMod::kZeroRangeKeepSizeOpt ||
        res.mod_opts == DiskMod::kInsertRangeOpt) {
      return 0;
    }

    if (res.file_mod_len > 0) {
      // Read the data for this mod.
      res.file_mod_data.reset(new (std::nothrow) char[res.file_mod_len],
          [](char *c) {delete[] c;});
      if (res.file_mod_data.get() == nullptr) {
        return -1;
      }
      memcpy(res.file_mod_data.get(), data_ptr, res.file_mod_len);
    }
  // }

  return 0;
}



DiskMod::DiskMod() {
  Reset();
}

void DiskMod::Reset() {
  path.clear();
  mod_type = kCreateMod;
  mod_opts = kNoneOpt;
  memset(&post_mod_stats, 0, sizeof(struct stat));
  directory_mod = false;
  file_mod_data.reset();
  file_mod_location = 0;
  file_mod_len = 0;
  path_mod = false;
  new_path.clear();
}

}  // namespace utils
}  // namespace fs_testing