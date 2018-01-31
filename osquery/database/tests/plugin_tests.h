/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <gtest/gtest.h>

#include <osquery/database.h>

#include "osquery/tests/test_util.h"

/// The following test macros allow pretty test output.
#define CREATE_DATABASE_TESTS(n)                                               \
  TEST_F(n, test_plugin_check) {                                               \
    testPluginCheck();                                                         \
  }                                                                            \
  TEST_F(n, test_reset) {                                                      \
    testReset();                                                               \
  }                                                                            \
  TEST_F(n, test_put) {                                                        \
    testPut();                                                                 \
  }                                                                            \
  TEST_F(n, test_get) {                                                        \
    testGet();                                                                 \
  }                                                                            \
  TEST_F(n, test_delete) {                                                     \
    testDelete();                                                              \
  }                                                                            \
  TEST_F(n, test_delete_range) {                                               \
    testDeleteRange();                                                         \
  }                                                                            \
  TEST_F(n, test_scan) {                                                       \
    testScan();                                                                \
  }                                                                            \
  TEST_F(n, test_scan_limit) {                                                 \
    testScanLimit();                                                           \
  }

namespace osquery {

class DatabasePluginTests : public testing::Test {
 public:
  void SetUp() override;

  void TearDown() override;

 protected:
  /// Path to testing database.
  std::string path_;

 protected:
  /// Require each plugin tester to implement a set name.
  virtual std::string name() = 0;

 private:
  void setName(const std::string& name) {
    name_ = name;
  }

  const std::string& getName() {
    return name_;
  }

  std::shared_ptr<DatabasePlugin> getPlugin() {
    return plugin_;
  }

 private:
  /// Plugin name
  std::string name_;

  /// Plugin casted from setUp, ready to run tests.
  std::shared_ptr<DatabasePlugin> plugin_{nullptr};

  /// Previous active database plugin.
  std::string existing_plugin_;

 protected:
  void testPluginCheck();
  void testReset();
  void testPut();
  void testGet();
  void testDelete();
  void testDeleteRange();
  void testScan();
  void testScanLimit();
};
}
