/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/user_groups.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/mutex.h>

namespace osquery {
namespace tables {

QueryData genUserGroups(QueryContext& context) {
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
    std::set<std::string> uids = context.constraints["uid"].getAll(EQUALS);
    for (const auto& uid : uids) {
      auto const auid_exp = tryTo<long>(uid, 10);
      if (auid_exp.isValue()) {
        getpwuid_r(auid_exp.get(), &pwd, buf.get(), bufsize, &pwd_results);
        if (pwd_results != nullptr) {
          user_t<uid_t, gid_t> user;
          user.name = pwd_results->pw_name;
          user.uid = pwd_results->pw_uid;
          user.gid = pwd_results->pw_gid;
          getGroupsForUser<uid_t, gid_t>(results, user);
        }
      }
    }
  } else {
    std::set<gid_t> users_in;
    setpwent();
    while (1) {
      getpwent_r(&pwd, buf.get(), bufsize, &pwd_results);
      if (pwd_results == nullptr)
        break;
      if (std::find(users_in.begin(), users_in.end(), pwd_results->pw_uid) ==
          users_in.end()) {
        user_t<uid_t, gid_t> user;
        user.name = pwd_results->pw_name;
        user.uid = pwd_results->pw_uid;
        user.gid = pwd_results->pw_gid;
        getGroupsForUser<uid_t, gid_t>(results, user);
        users_in.insert(pwd_results->pw_uid);
      }
    }
    endpwent();
    users_in.clear();
  }

  return results;
}
}
}
