/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <vector>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/core/test_util.h"

namespace osquery {

// The config_path flag is defined in the filesystem config plugin.
DECLARE_string(config_path);

class ConfigTests : public testing::Test {
 public:
  ConfigTests() {
    Registry::setActive("config", "filesystem");
    FLAGS_config_path = kTestDataPath + "test.config";
  }

 protected:

  void SetUp() {
    createMockFileStructure();
    Registry::setUp();
    Config::load();
  }

  void TearDown() { tearDownMockFileStructure(); }
};

class TestConfigPlugin : public ConfigPlugin {
 public:
  TestConfigPlugin() {}
  Status genConfig(std::map<std::string, std::string>& config) {
    config["data"] = "foobar";
    return Status(0, "OK");
    ;
  }
};

TEST_F(ConfigTests, test_plugin) {
  Registry::add<TestConfigPlugin>("config", "test");

  // Change the active config plugin.
  EXPECT_TRUE(Registry::setActive("config", "test").ok());

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);

  EXPECT_EQ(status.ok(), true);
  EXPECT_EQ(status.toString(), "OK");
  EXPECT_EQ(response[0].at("data"), "foobar");
}

TEST_F(ConfigTests, test_queries_execute) {
  auto queries = Config::getInstance().getScheduledQueries();
  EXPECT_EQ(queries.size(), 2);
}

TEST_F(ConfigTests, test_threatfiles_execute) {
  auto files = Config::getWatchedFiles();

  EXPECT_EQ(files.size(), 2);
  EXPECT_EQ(files["downloads"].size(), 1);
  EXPECT_EQ(files["system_binaries"].size(), 2);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
