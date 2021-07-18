/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for last
// Spec file: specs/posix/last.table

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class last : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(last, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from last");
  // 2. Check size before validation
  if (data.empty()) {
    LOG(WARNING) << "No entries in wtmp, skipping test";
    return;
  }
  // 3. Build validation map
  ValidationMap row_map = {
      {"username", NormalType},
      {"tty", NormalType},
      {"pid", NonNegativeInt},
      {"type", IntMinMaxCheck(7, 8)},
      {"type_name", NormalType},
      {"time", NonNegativeInt},
      {"host", NormalType},
  };
  // 4. Perform validation
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
