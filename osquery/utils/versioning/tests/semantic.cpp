/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/utils/versioning/semantic.h>

namespace osquery {
namespace {

class SemanticVersionTests : public testing::Test {};

TEST_F(SemanticVersionTests, pass) {
  auto exp = tryTo<SemanticVersion>("1.6.9");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 1u);
  EXPECT_EQ(exp.get().minor, 6u);
  EXPECT_EQ(exp.get().patches, 9u);
  EXPECT_EQ(exp.get().build, 0u);
}

TEST_F(SemanticVersionTests, pass_2) {
  auto exp = tryTo<SemanticVersion>("7.25.999");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 7u);
  EXPECT_EQ(exp.get().minor, 25u);
  EXPECT_EQ(exp.get().patches, 999u);
  EXPECT_EQ(exp.get().build, 0u);
}

TEST_F(SemanticVersionTests, pass_suffix) {
  auto exp = tryTo<SemanticVersion>("0.8.2_50_302b_1");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 0u);
  EXPECT_EQ(exp.get().minor, 8u);
  EXPECT_EQ(exp.get().patches, 2u);
  EXPECT_EQ(exp.get().build, 50u);
}

TEST_F(SemanticVersionTests, pass_git_format) {
  auto exp = tryTo<SemanticVersion>("0.5.5-19-ga7b9229");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 0u);
  EXPECT_EQ(exp.get().minor, 5u);
  EXPECT_EQ(exp.get().patches, 5u);
  EXPECT_EQ(exp.get().build, 19u);
}

TEST_F(SemanticVersionTests, pass_despite_bad_build) {
  auto exp = tryTo<SemanticVersion>("0.1.2-somenote");
  ASSERT_TRUE(exp.isValue());
  EXPECT_EQ(exp.get().major, 0u);
  EXPECT_EQ(exp.get().minor, 1u);
  EXPECT_EQ(exp.get().patches, 2u);
  EXPECT_EQ(exp.get().build, 0u);
}

TEST_F(SemanticVersionTests, fail_major) {
  auto exp = tryTo<SemanticVersion>("a4.5.9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_minor) {
  auto exp = tryTo<SemanticVersion>("9.f1.9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_patches) {
  auto exp = tryTo<SemanticVersion>("1.6.c9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_separator_minus) {
  auto exp = tryTo<SemanticVersion>("1-6-9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_separator_colon) {
  auto exp = tryTo<SemanticVersion>("1:6:9");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_empty) {
  auto exp = tryTo<SemanticVersion>("");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_one_digit) {
  auto exp = tryTo<SemanticVersion>("818");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, fail_two_digits) {
  auto exp = tryTo<SemanticVersion>("66.66");
  ASSERT_TRUE(exp.isError());
  EXPECT_EQ(exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(SemanticVersionTests, operators) {
  // Test operator plumbing. The more indepth tests are on compare
  auto v1_1_1 = tryTo<SemanticVersion>("1.1.1");
  auto v1_1_1_0 = tryTo<SemanticVersion>("1.1.1.0");
  auto v1_1_1_1 = tryTo<SemanticVersion>("1.1.1.1");
  auto v1_2_1_1 = tryTo<SemanticVersion>("1.2.1.1");
  auto v1_11_1 = tryTo<SemanticVersion>("1.11.1");

  // equals should equal
  EXPECT_TRUE(v1_1_1.get().eq(v1_1_1_0.get()));
  EXPECT_TRUE(v1_1_1.get() == v1_1_1_0.get());
  EXPECT_FALSE(v1_1_1.get() != v1_1_1_0.get());

  // Not equals
  EXPECT_FALSE(v1_1_1.get().eq(v1_1_1_1.get()));
  EXPECT_FALSE(v1_1_1.get() == v1_1_1_1.get());
  EXPECT_TRUE(v1_1_1.get() != v1_1_1_1.get());

  // with equal values
  EXPECT_FALSE(v1_1_1.get() < v1_1_1_0.get());
  EXPECT_TRUE(v1_1_1.get() <= v1_1_1_0.get());
  EXPECT_FALSE(v1_1_1.get() > v1_1_1_0.get());
  EXPECT_TRUE(v1_1_1.get() >= v1_1_1_0.get());

  // with trivial compare, would pass lexiraphical
  EXPECT_TRUE(v1_1_1_1.get() < v1_2_1_1.get());
  EXPECT_TRUE(v1_1_1_1.get() <= v1_2_1_1.get());
  EXPECT_FALSE(v1_1_1_1.get() > v1_2_1_1.get());
  EXPECT_FALSE(v1_1_1_1.get() >= v1_2_1_1.get());

  // with non-trivial values, needs numeric
  EXPECT_TRUE(v1_2_1_1.get() < v1_11_1.get());
  EXPECT_TRUE(v1_2_1_1.get() <= v1_11_1.get());
  EXPECT_FALSE(v1_2_1_1.get() > v1_11_1.get());
  EXPECT_FALSE(v1_2_1_1.get() >= v1_11_1.get());
}
TEST_F(SemanticVersionTests, operator_le) {}
TEST_F(SemanticVersionTests, operator_gt) {}
TEST_F(SemanticVersionTests, operator_ge) {}

TEST_F(SemanticVersionTests, equals) {
  auto v1exp = tryTo<SemanticVersion>("1.1.1");
  auto v2exp = tryTo<SemanticVersion>("1.1.1.0");

  ASSERT_TRUE(v1exp.isValue());
  ASSERT_TRUE(v2exp.isValue());

  auto v1 = v1exp.get();
  auto v2 = v2exp.get();

  EXPECT_TRUE(v1.eq(v2));
  EXPECT_TRUE(v2.eq(v1));
  EXPECT_TRUE(v1 == v2);
  EXPECT_TRUE(v2 == v1);
  EXPECT_TRUE(v1 <= v2);
  EXPECT_TRUE(v1 >= v2);

  EXPECT_EQ(v1.compare(v2), 0);
  EXPECT_EQ(v2.compare(v1), 0);
}

TEST_F(SemanticVersionTests, comparisons) {
  std::vector<std::tuple<std::string, std::string>> tests;
  tests.push_back(std::make_tuple("1.1.1.1", "2.1.1.1"));
  tests.push_back(std::make_tuple("1.1.1.1", "1.2.1.1"));
  tests.push_back(std::make_tuple("1.1.1.1", "1.1.2.1"));
  tests.push_back(std::make_tuple("1.1.1.1", "1.1.1.2"));
  tests.push_back(
      std::make_tuple("0.5.5-19-g85b16ae", "0.5.5-22-g85b16ae")); // git tags
  tests.push_back(
      std::make_tuple("2.6.32-74-generic-pae", "4.15.0-74-generic")); // kernel
  tests.push_back(std::make_tuple("2.6.32-74.142", "4.15.0-74.84")); // dpkg

  for (int i = 0; i < tests.size(); i++) {
    auto v1exp = tryTo<SemanticVersion>(std::get<0>(tests[i]));
    auto v2exp = tryTo<SemanticVersion>(std::get<1>(tests[i]));

    ASSERT_TRUE(v1exp.isValue());
    ASSERT_TRUE(v2exp.isValue());

    auto v1 = v1exp.get();
    auto v2 = v2exp.get();

    EXPECT_EQ(v1.compare(v2), -1);
    EXPECT_EQ(v2.compare(v1), 1);
  }
}

} // namespace
} // namespace osquery
