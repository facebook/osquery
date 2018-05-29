/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/optional.hpp>
#include <gtest/gtest.h>
#include <osquery/error.h>
#include <osquery/expected.h>

namespace osquery {

enum class TestError { SomeError = 1, AnotherError = 2 };

GTEST_TEST(ExpectedValueTest, initialization) {
  Expected<std::string> value = std::string("Test");
  if (!value) {
    GTEST_FAIL();
  }
  EXPECT_EQ(value.get(), "Test");

  Expected<std::string> error =
      std::make_shared<Error<TestError>>(TestError::SomeError);
  if (error) {
    GTEST_FAIL();
  }
  EXPECT_EQ(*error.getError(), TestError::SomeError);
}

osquery::ExpectedUnique<std::string> testFunction() {
  return std::make_unique<std::string>("Test");
}

GTEST_TEST(ExpectedPointerTest, initialization) {
  osquery::Expected<std::shared_ptr<std::string>> sharedPointer =
      std::make_shared<std::string>("Test");
  if (!sharedPointer) {
    GTEST_FAIL();
  }
  EXPECT_EQ(**sharedPointer, "Test");

  osquery::ExpectedUnique<std::string> uniquePointer = testFunction();
  if (!uniquePointer) {
    GTEST_FAIL();
  }
  EXPECT_EQ(**uniquePointer, "Test");

  osquery::ExpectedShared<std::string> sharedPointer2 =
      std::make_shared<std::string>("Test");

  if (!sharedPointer2) {
    GTEST_FAIL();
  }
  EXPECT_EQ(**sharedPointer2, "Test");

  osquery::ExpectedShared<std::string> error =
      std::make_shared<Error<TestError>>(TestError::AnotherError);
  if (error) {
    GTEST_FAIL();
  }
  EXPECT_EQ(*error.getError(), TestError::AnotherError);

  boost::optional<std::string> optional = std::string("123");
  osquery::Expected<boost::optional<std::string>> optionalExpected = optional;
  if (!optionalExpected) {
    GTEST_FAIL();
  }
  EXPECT_EQ(**optionalExpected, "123");
}

} // namespace osquery
