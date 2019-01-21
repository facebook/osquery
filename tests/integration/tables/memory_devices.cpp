
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

// Sanity check integration test for memory_devices
// Spec file: specs/posix/memory_devices.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class memoryDevices : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(memoryDevices, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from memory_devices");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"handle", NormalType}
  //      {"array_handle", NormalType}
  //      {"form_factor", NormalType}
  //      {"total_width", IntType}
  //      {"data_width", IntType}
  //      {"size", IntType}
  //      {"set", IntType}
  //      {"device_locator", NormalType}
  //      {"bank_locator", NormalType}
  //      {"memory_type", NormalType}
  //      {"memory_type_details", NormalType}
  //      {"max_speed", IntType}
  //      {"configured_clock_speed", IntType}
  //      {"manufacturer", NormalType}
  //      {"serial_number", NormalType}
  //      {"asset_tag", NormalType}
  //      {"part_number", NormalType}
  //      {"min_voltage", IntType}
  //      {"max_voltage", IntType}
  //      {"configured_voltage", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
