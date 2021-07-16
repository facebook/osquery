/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <pwd.h>

#include <mutex>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/mutex.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

void genUser(const struct passwd* pwd, QueryData& results) {
  Row r;
  r["uid"] = BIGINT(pwd->pw_uid);
  r["gid"] = BIGINT(pwd->pw_gid);
  r["uid_signed"] = BIGINT((int32_t)pwd->pw_uid);
  r["gid_signed"] = BIGINT((int32_t)pwd->pw_gid);

  if (pwd->pw_name != nullptr) {
    r["username"] = TEXT(pwd->pw_name);
  }

  if (pwd->pw_gecos != nullptr) {
    r["description"] = TEXT(pwd->pw_gecos);
  }

  if (pwd->pw_dir != nullptr) {
    r["directory"] = TEXT(pwd->pw_dir);
  }

  if (pwd->pw_shell != nullptr) {
    r["shell"] = TEXT(pwd->pw_shell);
  }
  r["pid_with_namespace"] = "0";
  results.push_back(r);
}

QueryData genUsersImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  struct passwd pwd;
  struct passwd* pwd_results;
  size_t bufsize;

  bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == (size_t)-1) { /* Value was indeterminate */
    bufsize = 16384; /* Should be more than enough */
  }
  auto buf = std::make_unique<char[]>(bufsize);

  if (context.constraints["uid"].exists(EQUALS)) {
    auto uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid : uids) {
      auto const auid_exp = tryTo<long>(uid, 10);
      if (auid_exp.isValue()) {
        getpwuid_r(auid_exp.get(), &pwd, buf.get(), bufsize, &pwd_results);
        if (pwd_results != nullptr) {
          genUser(pwd_results, results);
        }
      }
    }
  } else if (context.constraints["username"].exists(EQUALS)) {
    auto usernames = context.constraints["username"].getAll(EQUALS);
    for (const auto& username : usernames) {
      getpwnam_r(username.c_str(), &pwd, buf.get(), bufsize, &pwd_results);
      if (pwd_results != nullptr) {
        genUser(pwd_results, results);
      }
    }
  } else {
    setpwent();
    while (1) {
      getpwent_r(&pwd, buf.get(), bufsize, &pwd_results);
      if (pwd_results == nullptr)
        break;
      genUser(pwd_results, results);
    }
    endpwent();
  }

  return results;
}

QueryData genUsers(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "users", genUsersImpl);
  } else {
    GLOGLogger logger;
    return genUsersImpl(context, logger);
  }
}
}
}
