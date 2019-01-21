
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

// Sanity check integration test for iptables
// Spec file: specs/linux/iptables.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class iptables : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(iptables, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from iptables");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"filter_name", NormalType}
  //      {"chain", NormalType}
  //      {"policy", NormalType}
  //      {"target", NormalType}
  //      {"protocol", IntType}
  //      {"src_port", NormalType}
  //      {"dst_port", NormalType}
  //      {"src_ip", NormalType}
  //      {"src_mask", NormalType}
  //      {"iniface", NormalType}
  //      {"iniface_mask", NormalType}
  //      {"dst_ip", NormalType}
  //      {"dst_mask", NormalType}
  //      {"outiface", NormalType}
  //      {"outiface_mask", NormalType}
  //      {"match", NormalType}
  //      {"packets", IntType}
  //      {"bytes", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
