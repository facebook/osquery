/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for windows_events
// Spec file: specs/windows/windows_eventlog.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class windowsEventLog : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(windowsEventLog, test_sanity) {
  // Query event data for Application channel
  auto const data = execute_query(
      "select * from windows_eventlog where channel = 'Application'");
  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {
      {"channel", NonEmptyString},
      {"datetime", NonEmptyString},
      {"eventid", IntType},
      {"pid", IntType},
      {"tid", IntType},
      {"provider_name", NormalType},
      {"provider_guid", NormalType},
      {"task", IntType},
      {"level", IntType},
      {"keywords", NormalType},
      {"data", NormalType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
