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

class peLibraries : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(peLibraries, test_sanity) {
  ValidationMap row_map = {
      {"path", NormalType},
      {"filename", NormalType},
      {"library_name", NormalType},
      {"import_address_table_rva", NormalType},
      {"import_lookup_table_rva", NormalType},
      {"timestamp", NormalType},
      {"forwarder_chain", NormalType},
  };

  QueryData const rows = execute_query(
      "select * from pe_libraries where path = "
      "'C:\\Windows\\System32\\svchost.exe'");
  ASSERT_GT(rows.size(), 0ul);
  validate_rows(rows, row_map);

  QueryData const rows_arch = execute_query(
      "select * from pe_libraries where path = "
      "'C:\\Windows\\System32\\svchost.exe' "
      "and library_name = 'api-ms-win-core-threadpool-private-l1-1-0.dll'");
  ASSERT_GT(rows_arch.size(), 0ul);
  validate_rows(rows_arch, row_map);
}

} // namespace table_tests
} // namespace osquery
