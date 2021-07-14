/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class machoFunctions : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(machoFunctions, test_sanity) {
  ValidationMap row_map = {
      {"path", NormalType},
      {"filename", NormalType},
      {"arch", NormalType},
      {"function_type", NormalType},
      {"function_name", NormalType},
      {"function_address", NormalType},
  };

  QueryData const rows =
      execute_query("select * from macho_functions where path = '/bin/ls'");
  ASSERT_GT(rows.size(), 0ul);
  validate_rows(rows, row_map);

  QueryData const rows_arch = execute_query(
      "select * from macho_functions where path = '/bin/ls' and arch = "
      "'x86_64' and function_name = 'atoi'");
  ASSERT_GT(rows_arch.size(), 0ul);
  validate_rows(rows_arch, row_map);
}

} // namespace table_tests
} // namespace osquery
