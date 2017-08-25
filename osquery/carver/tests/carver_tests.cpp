/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <gtest/gtest.h>

#include <osquery/sql.h>

#include "osquery/carver/carver.h"
#include "osquery/core/json.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/hash.h"
#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

namespace osquery {

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

/// Prefix used for posix tar archive.
const std::string kTestCarveNamePrefix = "carve_";

std::string genGuid() {
  return boost::uuids::to_string(boost::uuids::random_generator()());
};

class CarverTests : public testing::Test {
 public:
  CarverTests() {
    fs::create_directories(kFakeDirectory + "/files_to_carve/");
    writeTextFile(kFakeDirectory + "/files_to_carve/secrets.txt",
                  "This is a message I'd rather no one saw.");
    writeTextFile(kFakeDirectory + "/files_to_carve/evil.exe",
                  "MZP\x00\x02\x00\x00\x00\x04\x00\x0f\x00\xff\xff");

    auto paths = platformGlob(kFakeDirectory + "/files_to_carve/*");
    for (const auto& p : paths) {
      carvePaths.insert(p);
    }
  };

  std::set<std::string>& getCarvePaths() {
    return carvePaths;
  }

 protected:
  void SetUp() override {
    createMockFileStructure();

    // Start a server.
    TLSServerRunner::start();
    TLSServerRunner::setClientConfig();

    // Configure the carver endpoints
    carver_start_endpoint_ = Flag::getValue("carver_start_endpoint");
    Flag::updateValue("carver_start_endpoint", "/carve_init");

    carver_continue_endpoint_ = Flag::getValue("carver_continue_endpoint");
    Flag::updateValue("carver_continue_endpoint", "/carve_block");

    disable_carver_ = Flag::getValue("disable_carver");
    Flag::updateValue("disable_carver", "false");
  }

  void TearDown() override {
    tearDownMockFileStructure();

    // Stop the server.
    TLSServerRunner::unsetClientConfig();
    TLSServerRunner::stop();

    Flag::updateValue("carver_start_endpoint", carver_start_endpoint_);
    Flag::updateValue("carver_continue_endpoint", carver_continue_endpoint_);
    Flag::updateValue("disable_carver", disable_carver_);
  }

 private:
  std::set<std::string> carvePaths;
  std::string carver_start_endpoint_;
  std::string carver_continue_endpoint_;
  std::string disable_carver_;
};

TEST_F(CarverTests, test_carve_files_locally) {
  auto guid_ = genGuid();
  auto paths_ = getCarvePaths();
  std::string requestId = "";
  Carver carve(getCarvePaths(), guid_, requestId);

  Status s;
  for (const auto& p : paths_) {
    s = carve.carve(fs::path(p));
    EXPECT_TRUE(s.ok());
  }

  std::string carveFSPath = carve.getCarveDir().string();
  auto paths = platformGlob(carveFSPath + "/*");
  std::set<fs::path> carves;
  for (const auto& p : paths) {
    carves.insert(fs::path(p));
  }

  EXPECT_EQ(carves.size(), 2U);
  s = archive(carves,
              carveFSPath + "/" + kTestCarveNamePrefix + guid_ + ".tar");
  EXPECT_TRUE(s.ok());

  auto tarPath = carveFSPath + "/" + kTestCarveNamePrefix + guid_ + ".tar";
  PlatformFile tar(tarPath, PF_OPEN_EXISTING | PF_READ);
  EXPECT_TRUE(tar.isValid());
  EXPECT_GT(tar.size(), 0U);
}

TEST_F(CarverTests, test_full_carve) {
  {
    SQL results("select * from carves where carve=1 and path='" +
                kFakeDirectory + "/files_to_carve/evil.exe'");
  }

  SQL carveResults("select sha256, carve_guid, status from carves");
  EXPECT_TRUE(carveResults.rows().size() > 0);

  int tries = 0;
  auto status = carveResults.rows()[0].at("status");
  std::string carveShaSum = "";
  while (status == "PENDING" && tries < 10) {
// Failing with unresolved symbol :(
// pauseMilli(100);
#ifdef WIN32
    Sleep(1);
#else
    sleep(1);
#endif
    SQL carveResultsCont(
        "select status, sha256 from carves where carve_guid = '" +
        carveResults.rows()[0].at("carve_guid") + "'");
    status = carveResultsCont.rows()[0].at("status");

    // The sha256 isn't updated until after the carve completes
    carveShaSum = carveResultsCont.rows()[0].at("sha256");
    tries++;
  }
  EXPECT_TRUE(!carveShaSum.empty());

  auto fileShaSum = hashFromFile(
      HASH_TYPE_SHA256,
      (fs::temp_directory_path() / carveResults.rows()[0].at("carve_guid"))
              .string() +
          ".tar");
  EXPECT_EQ(fileShaSum, carveShaSum);
}

TEST_F(CarverTests, test_compression) {
  auto s = osquery::compress(
      kTestDataPath + "test.config",
      fs::temp_directory_path() / fs::path("test.config.zst"));
  EXPECT_TRUE(s.ok());
}

TEST_F(CarverTests, test_decompression) {
  auto s = osquery::decompress(
      fs::temp_directory_path() / fs::path("test.config.zst"),
      fs::temp_directory_path() / fs::path("test.config"));
  EXPECT_TRUE(s.ok());
  EXPECT_TRUE(
      hashFromFile(
          HashType::HASH_TYPE_SHA256,
          (fs::temp_directory_path() / fs::path("test.config")).string()) ==
      hashFromFile(HashType::HASH_TYPE_SHA256, kTestDataPath + "test.config"));
}
} // namespace osquery
