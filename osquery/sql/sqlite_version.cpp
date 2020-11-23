/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <assert.h>

#include <osquery/logger.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/versioning/semantic.h>

#include <string>

#include <sqlite3.h>

namespace osquery {

// The collating function must return an integer that is negative,
// zero, or positive if the first string is less than, equal to, or
// greater than the second, respectively
int version_collate(void* userdata, // UNUSED
                    int alen,
                    const void* a,
                    int blen,
                    const void* b) {
  std::string aStr((const char*)a);
  auto aVer = tryTo<SemanticVersion>(aStr);
  if (aVer.isError()) {
    LOG(INFO) << "Unable to collate <<" << aStr
              << ">> as version. Treating as equal\n";
    return 0;
  }

  std::string bStr((const char*)b);
  auto bVer = tryTo<SemanticVersion>(bStr);
  if (bVer.isError()) {
    LOG(INFO) << "Unable to collate <<" << bStr
              << ">> as version. Treating as equal\n";
    return 0;
  }

  return aVer.get().compare(bVer.get());
}

void registerVersionExtensions(sqlite3* db) {
  sqlite3_create_collation(
      db,
      "VERSION",
      SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS,
      nullptr,
      version_collate);
}

} // namespace osquery
