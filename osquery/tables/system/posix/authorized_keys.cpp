/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/system/system.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kSSHAuthorizedkeys = {".ssh/authorized_keys",
                                                     ".ssh/authorized_keys2"};

void genSSHkeysForUser(const std::string& uid,
                       const std::string& gid,
                       const std::string& directory,
                       QueryData& results,
                       Logger& logger) {
  for (const auto& kfile : kSSHAuthorizedkeys) {
    boost::filesystem::path keys_file = directory;
    keys_file /= kfile;

    std::string keys_content;

    auto s = forensicReadFile(keys_file, keys_content, false, false);
    if (!s.ok()) {
      // Cannot read a specific keys file.
      logger.log(google::GLOG_WARNING, s.getMessage());
      logger.vlog(1, s.getMessage());
      continue;
    }
    // Protocol 1 public key consist of: options, bits, exponent, modulus,
    // comment; Protocol 2 public key consist of: options, keytype,
    // base64-encoded key, comment.
    for (const auto& line : split(keys_content, "\n")) {
      if (!line.empty() && line[0] != '#') {
        Row r = {{"uid", uid}, {"key", line}, {"key_file", keys_file.string()}};
        r["pid_with_namespace"] = "0";
        results.push_back(r);
      }
    }
  }
}

QueryData getAuthorizedKeysImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHkeysForUser(
          uid->second, gid->second, directory->second, results, logger);
    }
  }

  return results;
}

QueryData getAuthorizedKeys(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(
        context, "authorized_keys", getAuthorizedKeysImpl);
  } else {
    GLOGLogger logger;
    return getAuthorizedKeysImpl(context, logger);
  }
}
}
}
