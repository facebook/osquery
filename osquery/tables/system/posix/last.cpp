/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <utmpx.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

namespace impl {

std::string typeNameForType(const utmpx& ut) {
  switch (ut.ut_type) {
  case EMPTY:
    return "empty";
  case RUN_LVL:
    return "run-level";
  case BOOT_TIME:
    return "boot-time";
  case NEW_TIME:
    return "new-time";
  case OLD_TIME:
    return "old-time";
  case INIT_PROCESS:
    return "init-process";
  case LOGIN_PROCESS:
    return "login-process";
  case USER_PROCESS:
    return "user-process";
  case DEAD_PROCESS:
    return "dead-process";
  }

  return "";
}

void genLastAccessForRow(const utmpx& ut, QueryData& results) {
  if (ut.ut_type == USER_PROCESS || ut.ut_type == DEAD_PROCESS) {
    Row r;
    r["username"] = TEXT(ut.ut_user);
    r["tty"] = TEXT(ut.ut_line);
    r["pid"] = INTEGER(ut.ut_pid);
    r["type"] = INTEGER(ut.ut_type);
    r["type_name"] = TEXT(typeNameForType(ut));
    r["time"] = INTEGER(ut.ut_tv.tv_sec);
    r["host"] = TEXT(ut.ut_host);
    results.push_back(r);
  }
}

} // namespace impl

QueryData genLastAccess(QueryContext& context) {
  QueryData results;
  struct utmpx* ut;
#ifdef __APPLE__
  setutxent_wtmp(0); // 0 = reverse chronological order

  while ((ut = getutxent_wtmp()) != nullptr) {
#else

#ifndef __FreeBSD__
  utmpxname(_PATH_WTMP);
#endif
  setutxent();

  while ((ut = getutxent()) != nullptr) {
#endif
    impl::genLastAccessForRow(*ut, results);
  }

#ifdef __APPLE__
  endutxent_wtmp();
#else
  endutxent();
#endif
  return results;
}
}
}
