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

class peSig : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(peSig, test_sanity) {
  ValidationMap row_map = {
      {"path", NormalType},
      {"filename", NormalType},
      {"certificate_valid_from", NormalType},
      {"certificate_valid_to", NormalType},
      {"certificate_issuer", NormalType},
      {"certificate_subject", NormalType},
      {"certificate_version", NormalType},
      {"certificate_serial_number", NormalType},
  };

  QueryData const rows = execute_query(
      "select * from pe_sig where path = 'C:\\Windows\\System32\\svchost.exe'");
  ASSERT_GT(rows.size(), 0ul);
  validate_rows(rows, row_map);

  QueryData const rows_arch = execute_query(
      "select * from pe_sig where path = 'C:\\Windows\\System32\\svchost.exe' "
      "and "
      "certificate_issuer = 'C=US, ST=Washington, L=Redmond, O=Microsoft "
      "Corporation, CN=Microsoft Root Certificate Authority 2010'");
  ASSERT_GT(rows_arch.size(), 0ul);
  validate_rows(rows_arch, row_map);
}

} // namespace table_tests
} // namespace osquery
