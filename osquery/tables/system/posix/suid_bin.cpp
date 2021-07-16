/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

std::vector<std::string> kBinarySearchPaths = {
    "/bin",           "/sbin",           "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin", "/tmp",
};

Status genBin(const fs::path& path, int perms, QueryData& results) {
  struct stat info;
  // store user and group
  if (stat(path.c_str(), &info) != 0) {
    return Status(1, "stat failed");
  }

  // store path
  Row r;
  r["path"] = path.string();
  struct passwd* pw = getpwuid(info.st_uid);
  struct group* gr = getgrgid(info.st_gid);

  // get user name + group
  std::string user;
  if (pw != nullptr) {
    user = std::string(pw->pw_name);
  } else {
    user = std::to_string(info.st_uid);
  }

  std::string group;
  if (gr != nullptr) {
    group = std::string(gr->gr_name);
  } else {
    group = std::to_string(info.st_gid);
  }

  r["username"] = user;
  r["groupname"] = group;

  r["permissions"] = "";
  if ((perms & 04000) == 04000) {
    r["permissions"] += "S";
  }

  if ((perms & 02000) == 02000) {
    r["permissions"] += "G";
  }
  r["pid_with_namespace"] = "0";
  results.push_back(r);
  return Status::success();
}

bool isSuidBin(const fs::path& path, int perms) {
  if (!fs::is_regular_file(path)) {
    return false;
  }

  if ((perms & 04000) == 04000 || (perms & 02000) == 02000) {
    return true;
  }
  return false;
}

void genSuidBinsFromPath(const std::string& path,
                         QueryData& results,
                         Logger& logger) {
  if (!pathExists(path).ok()) {
    // Creating an iterator on a missing path will except.
    return;
  }

  auto it = fs::recursive_directory_iterator(fs::path(path));
  fs::recursive_directory_iterator end;
  while (it != end) {
    fs::path subpath = *it;
    try {
      // Do not traverse symlinked directories.
      if (fs::is_directory(subpath) && fs::is_symlink(subpath)) {
        it.no_push();
      }

      int perms = it.status().permissions();
      if (isSuidBin(subpath, perms)) {
        // Only emit suid bins.
        genBin(subpath, perms, results);
      }

      ++it;
    } catch (fs::filesystem_error& e) {
      logger.vlog(1, "Cannot read binary from " + subpath.string());
      it.no_push();
      // Try to recover, otherwise break.
      try {
        ++it;
      } catch (fs::filesystem_error& e) {
        break;
      }
    }
  }
}

QueryData genSuidBinImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // Todo: add hidden column to select on that triggers non-std path searches.
  for (const auto& path : kBinarySearchPaths) {
    genSuidBinsFromPath(path, results, logger);
  }

  return results;
}

QueryData genSuidBin(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "suid_bin", genSuidBinImpl);
  } else {
    GLOGLogger logger;
    return genSuidBinImpl(context, logger);
  }
}
}
}
