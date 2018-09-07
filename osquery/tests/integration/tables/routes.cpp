
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for routes
// Spec file: specs/routes.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class routes : public IntegrationTableTest {};

TEST_F(routes, test_sanity) {
  QueryData const data = execute_query("select * from routes");

  auto const row_map = ValidatatioMap{
      {"destination", verifyIpAddress},
      {"netmask", IntType},
      {"gateway", verifyEmptyStringOrIpAddress},
      {"source", verifyEmptyStringOrIpAddress},
      {"flags", IntType},
      {"interface", NonEmptyString},
      {"mtu", IntType},
      {"metric", IntType},
      {"type",
       SpecificValuesCheck{
           "local", "broadcast", "anycast", "gateway", "other"}},
      {"hopcount", IntMinMaxCheck(0, 255)},
  };
  validate_rows(data, row_map);
}

} // namespace osquery
