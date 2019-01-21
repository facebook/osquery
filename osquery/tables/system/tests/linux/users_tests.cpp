/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <pwd.h>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/system.h>

namespace osquery {

class UsersTests : public testing::Test {};

TEST_F(UsersTests, test_nobody_drop_username) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping (username) deprivilege testing";
    return;
  }

  auto nobody = getpwnam("nobody");
  auto nobody_uid = nobody->pw_uid;
  ASSERT_NE(geteuid(), nobody_uid);
  ASSERT_EQ(geteuid(), getuid());

  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropTo("nobody"));
    EXPECT_EQ(geteuid(), nobody_uid);
  }

  EXPECT_NE(geteuid(), nobody_uid);
}
} // namespace osquery
