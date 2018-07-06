/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/packs.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/core/process.h"
#include "osquery/killswitch.h"
#include "osquery/killswitch/killswitch_plugin.h"
#include "osquery/killswitch/plugins/killswitch_filesystem.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_uint32(killswitch_refresh_rate);

class KillswitchFilesystemTests : public testing::Test {};

TEST_F(KillswitchFilesystemTests, test_killswitch_filesystem_plugin) {
  KillswitchFilesystem plugin(kTestDataPath + "test_killswitch.conf");
  auto content = plugin.getJSON();
  EXPECT_TRUE(content);
  content->erase(remove_if(content->begin(), content->end(), isspace),
                 content->end());
  EXPECT_EQ(*content, "{\"testSwitch\":true,\"test2Switch\":false}");
}

} // namespace osquery
