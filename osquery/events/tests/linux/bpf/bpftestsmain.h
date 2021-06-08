/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <gtest/gtest.h>

namespace osquery {

class SystemStateTrackerTests : public testing::Test {
 protected:
  virtual void SetUp() override{};
};

class BPFEventPublisherTests : public testing::Test {
 protected:
  virtual void SetUp() override{};
};

class ProcessContextFactoryTests : public testing::Test {
 protected:
  virtual void SetUp() override{};
};

class UserTracerTests : public testing::Test {
 protected:
  virtual void SetUp() override{};
};

} // namespace osquery
