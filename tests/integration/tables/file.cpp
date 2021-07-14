/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for file
// Spec file: specs/utility/file.table

#include <fstream>

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

#include <boost/filesystem.hpp>

namespace osquery {
namespace table_tests {

class FileTests : public testing::Test {
 public:
  boost::filesystem::path filepath;

  virtual void SetUp() {
    setUpEnvironment();
    auto directory =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("test-integration-file-table.%%%%-%%%%");
    ASSERT_TRUE(boost::filesystem::create_directory(directory));
    filepath = directory / boost::filesystem::path("file-table-test.txt");
    {
      auto fout = std::ofstream(filepath.native(), std::ios::out);
      fout.open(filepath.string(), std::ios::out);
      fout << "test";
    }
  }

  virtual void TearDown() {
    boost::filesystem::remove_all(filepath.parent_path());
  }
};

TEST_F(FileTests, test_sanity) {
  std::string path_constraint =
      (filepath.parent_path() / boost::filesystem::path("%.txt")).string();
  QueryData data = execute_query("select * from file where path like \"" +
                                 path_constraint + "\"");
  EXPECT_EQ(data.size(), 1ul);

  ValidationMap row_map = {{"path", FileOnDisk},
                           {"directory", DirectoryOnDisk},
                           {"filename", NonEmptyString},
                           {"inode", IntType},
                           {"uid", NonNegativeInt},
                           {"gid", NonNegativeInt},
                           {"mode", NormalType},
                           {"device", IntType},
                           {"size", NonNegativeInt},
                           {"block_size", NonNegativeInt},
                           {"atime", NonNegativeInt},
                           {"mtime", NonNegativeInt},
                           {"ctime", NonNegativeInt},
                           {"btime", NonNegativeInt},
                           {"hard_links", IntType},
                           {"symlink", IntType},
                           {"type", NonEmptyString}};
#ifdef WIN32
  row_map["attributes"] = NormalType;
  row_map["volume_serial"] = NormalType;
  row_map["file_id"] = NormalType;
  row_map["product_version"] = NormalType;
  row_map["file_version"] = NormalType;
  row_map["original_filename"] = NormalType;
#endif

#ifdef __APPLE__
  row_map["bsd_flags"] = NormalType;
#endif

  ASSERT_EQ(data[0]["path"], filepath.string());
  ASSERT_EQ(data[0]["directory"], filepath.parent_path().string());
  ASSERT_EQ(data[0]["filename"], filepath.filename().string());

  validate_rows(data, row_map);

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    validate_container_rows(
        "file", row_map, "path like \"" + path_constraint + "\"");
  }
}

} // namespace table_tests
} // namespace osquery
