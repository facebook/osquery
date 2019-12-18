/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <pwd.h>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace tables {
Status keyNameFromFilePath(std::string& key_name, const std::string& file_path);

bool isBooleanKey(const std::string& key_name);

Status translateBooleanKeyValue(std::string& value,
                                const std::string& raw_value);

class SELinuxSettingsTests : public testing::Test {};

TEST_F(SELinuxSettingsTests, keyNameFromFilePath) {
  struct TestCase final {
    bool expected_status{false};
    std::string expected_key_name;
    std::string file_path;
  };

  const std::vector<TestCase> test_case_list = {
      {false, "", "/sys/fs/selinux"},
      {false, "", "/sys/fs/selinux/"},
      {true, "devnull", "/sys/fs/selinux/initial_contexts/devnull"},
      {true, "name_bind", "/sys/fs/selinux/class/smc_socket/perms/name_bind"},
      {true,
       "nnp_nosuid_transition",
       "/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition"}};

  for (const auto& test_case : test_case_list) {
    std::string key_name;
    auto status = keyNameFromFilePath(key_name, test_case.file_path);

    CHECK_EQ(key_name, test_case.expected_key_name);
    ASSERT_EQ(status.ok(), test_case.expected_status);
  }
}

TEST_F(SELinuxSettingsTests, translateBooleanKeyValue) {
  struct TestCase final {
    bool expected_status{false};
    std::string expected_value;
    std::string raw_value;
  };

  const std::vector<TestCase> test_case_list = {
      {true, "on", "1 1"}, {true, "off", "0 0"}, {false, "", "0"}};

  for (const auto& test_case : test_case_list) {
    std::string translated_value;
    auto status =
        translateBooleanKeyValue(translated_value, test_case.raw_value);

    ASSERT_EQ(status.ok(), test_case.expected_status);
    ASSERT_EQ(translated_value, test_case.expected_value);
  }
}
} // namespace tables
} // namespace osquery
