/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/utils/system/env.h>

#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmts.h>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <utility>

using namespace testing;

namespace osquery {
namespace tables {

rpmlogCallback gPreviousCallback{nullptr};

class RpmTests : public ::testing::Test {
 public:
  static int Callback(rpmlogRec rec, rpmlogCallbackData data) {
    return 0;
  }

 protected:
  void SetUp() {
    gPreviousCallback = rpmlogSetCallback(&RpmTests::Callback, nullptr);
  }

  void setConfig(const std::string& path) {
    config_ = getEnvVar("RPM_CONFIGDIR");
    setEnvVar("RPM_CONFIGDIR", path);
    addMacro(nullptr, "_dbpath", nullptr, path.c_str(), 0);
    addMacro(nullptr, "rpmdb", nullptr, path.c_str(), 0);
  }

  void TearDown() {
    rpmlogSetCallback(gPreviousCallback, nullptr);

    if (config_.is_initialized()) {
      setEnvVar("RPM_CONFIGDIR", *config_);
      config_ = boost::none;
    } else {
      unsetEnvVar("RPM_CONFIGDIR");
    }

    delMacro(nullptr, "_dbpath");
    delMacro(nullptr, "rpmdb");
  }

 private:
  // Previous configuration directory.
  boost::optional<std::string> config_;
};

struct PackageDetails {
  std::string name;
  std::string version;
  std::string sha1;

  friend bool operator==(const PackageDetails& pd1, const PackageDetails& pd2);
  friend std::ostream& operator<<(std::ostream& s, const PackageDetails& pd);
};

bool operator==(const PackageDetails& pd1, const PackageDetails& pd2) {
  return pd1.name == pd2.name && pd1.version == pd2.version &&
         pd1.sha1 == pd2.sha1;
}

std::ostream& operator<<(std::ostream& s, const PackageDetails& pd) {
  s << pd.name << "-" << pd.version << " (" << pd.sha1 << ") ";
  return s;
}

typedef std::function<void(struct PackageDetails&)> packageCallback;

Status queryRpmDb(packageCallback predicate) {
  rpmInitCrypto();
  if (rpmReadConfigFiles(nullptr, nullptr) != 0) {
    rpmFreeCrypto();
    Status::failure("Cannot read configuration");
  }

  rpmts ts = rpmtsCreate();
  auto matches = rpmtsInitIterator(ts, RPMTAG_NAME, nullptr, 0);

  Header header;
  while ((header = rpmdbNextIterator(matches)) != nullptr) {
    rpmtd td = rpmtdNew();

    struct PackageDetails pd;
    if (headerGet(header, RPMTAG_NAME, td, HEADERGET_DEFAULT) != 0) {
      pd.name = rpmtdGetString(td);
    }

    if (headerGet(header, RPMTAG_VERSION, td, HEADERGET_DEFAULT) != 0) {
      pd.version = rpmtdGetString(td);
    }

    if (headerGet(header, RPMTAG_SHA1HEADER, td, HEADERGET_DEFAULT) != 0) {
      pd.sha1 = rpmtdGetString(td);
    }

    rpmtdFree(td);

    predicate(pd);
  }

  rpmdbFreeIterator(matches);
  rpmtsFree(ts);
  rpmFreeCrypto();
  rpmFreeRpmrc();

  return Status::success();
}

TEST_F(RpmTests, test_bdb_packages) {
  auto dropper = DropPrivileges::get();
  if (isUserAdmin()) {
    ASSERT_TRUE(dropper->dropTo("nobody"));
  }

  auto bdb_config = getTestConfigDirectory() / "rpm" / "rpm-bdb";
  bdb_config = boost::filesystem::absolute(bdb_config);
  this->setConfig(bdb_config.string());

  std::vector<struct PackageDetails> packages;
  auto getPackage = [&packages](struct PackageDetails& pd) {
    packages.push_back(pd);
  };

  ASSERT_TRUE(queryRpmDb(getPackage).ok());

  std::vector<struct PackageDetails> expected = {
      {"rpm-libs", "4.8.0", "4bdccd7d66ec292581ae047c73e476869f43c704"},
      {"rpm-python", "4.8.0", "e308afd6a0c0a0dc31ad8dbf64c0bd1651462c02"},
      {"rpm", "4.8.0", "3b1c9206487936ed0d6190a794a2f3c40e3dd5b1"},
  };

  EXPECT_EQ(expected, packages);
};

} // namespace tables
} // namespace osquery
