/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sstream>

#include <boost/algorithm/string.hpp>

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core.h>
#include <osquery/system.h>
#include <osquery/utils/system/env.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {

class WmiTests : public testing::Test {
 protected:
  void SetUp() {
    Initializer::platformSetup();
  }
};

TEST_F(WmiTests, test_methodcall_inparams) {
  auto windir = getEnvVar("WINDIR");
  EXPECT_TRUE(windir);

  std::stringstream ss;
  ss << "SELECT * FROM Win32_Directory WHERE Name = \"" << *windir << "\"";

  auto query = ss.str();

  // This is dirty, we need to escape the WINDIR path
  boost::replace_all(query, "\\", "\\\\");

  WmiRequest req(query);
  const auto& wmiResults = req.results();

  EXPECT_EQ(wmiResults.size(), 1);

  WmiMethodArgs args;
  WmiResultItem out;

  // Setting in-parameter Permissions to 1 (FILE_LIST_DIRECTORY)
  // The odd part here is that despite Permissions requiring a uint32 in
  // MSDN documentation, this is actually a VT_BSTR...
  args.Put<std::string>("Permissions", "1");

  // Get the first item off the result vector since we should only have one.
  auto& resultItem = wmiResults.front();
  auto status = resultItem.ExecMethod("GetEffectivePermission", args, out);

  EXPECT_EQ(status.getMessage(), "OK");
  EXPECT_TRUE(status.ok());

  bool retval = false;

  // The reutnr value is stored in the ReturnValue key within the out-parameter
  // object
  status = out.GetBool("ReturnValue", retval);

  EXPECT_EQ(status.getMessage(), "OK");
  EXPECT_TRUE(status.ok());

  // As both Administrator and normal user, we should be able to
  // FILE_LIST_DIRECTORY on WINDIR
  EXPECT_TRUE(retval);
}

TEST_F(WmiTests, test_methodcall_outparams) {
  WmiRequest req("SELECT * FROM Win32_Process WHERE Name = \"wininit.exe\"");
  const auto& wmiResults = req.results();

  // We should expect only one wininit.exe instance?
  EXPECT_EQ(wmiResults.size(), 1);

  WmiMethodArgs args;
  WmiResultItem out;

  // Get the first item off the result vector since we should only have one.
  auto& resultItem = wmiResults.front();
  auto status = resultItem.ExecMethod("GetOwner", args, out);

  // We use this check to make debugging errors faster
  EXPECT_EQ(status.getMessage(), "OK");
  EXPECT_TRUE(status.ok());

  long retval;

  // For some reason, this is a VT_I4
  status = out.GetLong("ReturnValue", retval);
  EXPECT_EQ(status.getMessage(), "OK");
  EXPECT_TRUE(status.ok());

  // Make sure the return value is successful
  EXPECT_EQ(retval, 0);

  std::string user_name;
  std::string domain_name;

  status = out.GetString("User", user_name);
  EXPECT_EQ(status.getMessage(), "OK");
  EXPECT_TRUE(status.ok());

  status = out.GetString("Domain", domain_name);
  EXPECT_EQ(status.getMessage(), "OK");
  EXPECT_TRUE(status.ok());

  // Only NT AUTHORITY\SYSTEM should be running wininit.exe
  EXPECT_EQ(user_name, "SYSTEM");
  EXPECT_EQ(domain_name, "NT AUTHORITY");
}

} // namespace osquery
