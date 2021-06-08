/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpftestsmain.h"

#include <osquery/events/linux/bpf/usertracer.h>

namespace osquery {

TEST_F(UserTracerTests, limitMapSize) {
  std::map<int, int> test_map;
  for (int i = 1; i <= 100; ++i) {
    test_map.insert({i, i});
  }

  UserTracer::limitMapSize(test_map, 200);
  EXPECT_EQ(test_map.size(), 100);

  UserTracer::limitMapSize(test_map, 100);
  EXPECT_EQ(test_map.size(), 100);

  UserTracer::limitMapSize(test_map, 99);
  EXPECT_EQ(test_map.size(), 99);
  EXPECT_EQ(test_map.count(1), 0);
  EXPECT_EQ(test_map.count(2), 1);
  EXPECT_EQ(test_map.count(100), 1);

  UserTracer::limitMapSize(test_map, 50);
  EXPECT_EQ(test_map.size(), 50);
  EXPECT_EQ(test_map.count(50), 0);
  EXPECT_EQ(test_map.count(51), 1);
  EXPECT_EQ(test_map.count(100), 1);

  UserTracer::limitMapSize(test_map, 1);
  EXPECT_EQ(test_map.size(), 1);
  EXPECT_EQ(test_map.count(100), 1);

  UserTracer::limitMapSize(test_map, 0);
  EXPECT_TRUE(test_map.empty());
}

} // namespace osquery
