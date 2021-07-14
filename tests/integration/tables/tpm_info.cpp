/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for wmi_tpm_info
// Spec file: specs/windows/wmi_script_event_consumers.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class TpmInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(TpmInfo, test_sanity) {
  auto const data = execute_query("select * from tpm_info");

  ValidationMap row_map{
      {"activated", IntType},
      {"enabled", IntType},
      {"owned", IntType},
      {"manufacturer_version", NormalType},
      {"manufacturer_id", IntType},
      {"manufacturer_name", NormalType},
      {"product_name", NormalType},
      {"physical_presence_version", NormalType},
      {"spec_version", NormalType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
