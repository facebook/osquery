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

class peInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(peInfo, test_sanity) {
  ValidationMap row_map = {
      {"path", NormalType},
      {"filename", NormalType},
      {"company_name", NormalType},
      {"entrypoint", NormalType},
      {"imphash", NormalType},
      {"signed", IntType},
      {"file_version", NormalType},
      {"number_of_language_codes", IntType},
      {"has_resources", IntType},
      {"is_pie", IntType},
      {"file_description", NormalType},
      {"product_name", NormalType},
      {"internal_name", NormalType},
      {"legal_copyright", NormalType},
      {"legal_trademarks", NormalType},
      {"original_filename", NormalType},
      {"language", NormalType},
      {"comments", NormalType},
      {"private_build", NormalType},
      {"special_build", NormalType},
      {"product_version", NormalType},
  };

  QueryData const rows = execute_query(
      "select * from pe_info where path = "
      "'C:\\Windows\\System32\\svchost.exe'");
  ASSERT_GT(rows.size(), 0ul);
  validate_rows(rows, row_map);

  QueryData const rows_arch = execute_query(
      "select * from pe_info where path = 'C:\\Windows\\System32\\svchost.exe' "
      "and signed = 1");
  ASSERT_GT(rows_arch.size(), 0ul);
  validate_rows(rows_arch, row_map);
}

} // namespace table_tests
} // namespace osquery
