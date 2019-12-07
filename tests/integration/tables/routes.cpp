/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for routes
// Spec file: specs/routes.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class RoutesTest : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(RoutesTest, test_sanity) {
  auto const row_map = ValidationMap{
      {"destination", verifyIpAddress},
      {"netmask", IntMinMaxCheck(0, 128)},
      {"gateway", NormalType},
      {"source", verifyEmptyStringOrIpAddress},
      {"flags", IntType},
      {"interface", NormalType},
      {"mtu", IntType},
      {"metric", IntType},
      {"type",
       SpecificValuesCheck{
           "anycast",
           "broadcast",
           "dynamic",
           "gateway",
           "local",
           "other",
           "remote",
           "router",
           "static",
       }},
#ifdef OSQUERY_POSIX
      {"hopcount", IntMinMaxCheck(0, 255)},
#endif
  };

  auto const data = execute_query("select * from routes");
  ASSERT_GE(data.size(), 1ul);
  validate_rows(data, row_map);

  auto const datatype = execute_query("select * from routes where type = 'local'");
  ASSERT_GE(datatype.size(), 1ul);
  validate_rows(datatype, row_map);


}

} // namespace table_tests
} // namespace osquery
