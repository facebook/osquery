/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/filesystem/filesystem.h>

#include <boost/filesystem/path.hpp>

namespace osquery {

namespace fs = boost::filesystem;

fs::path createMockFileStructure() {
  const auto root_dir =
      fs::temp_directory_path() /
      fs::unique_path("osquery.tests.%%%%.%%%%");
  fs::create_directories(root_dir / "toplevel/");
  fs::create_directories(root_dir / "toplevel/secondlevel1");
  fs::create_directories(root_dir / "toplevel/secondlevel2");
  fs::create_directories(root_dir / "toplevel/secondlevel3");
  fs::create_directories(root_dir / "toplevel/secondlevel3/thirdlevel1");
  fs::create_directories(root_dir / "deep11/deep2/deep3/");
  fs::create_directories(root_dir / "deep1/deep2/");
  writeTextFile(root_dir / "root.txt", "root");
  writeTextFile(root_dir / "door.txt", "toor", 0550);
  writeTextFile(root_dir / "roto.txt", "roto");
  writeTextFile(root_dir / "deep1/level1.txt", "l1");
  writeTextFile(root_dir / "deep11/not_bash", "l1");
  writeTextFile(root_dir / "deep1/deep2/level2.txt", "l2");

  writeTextFile(root_dir / "deep11/level1.txt", "l1");
  writeTextFile(root_dir / "deep11/deep2/level2.txt", "l2");
  writeTextFile(root_dir / "deep11/deep2/deep3/level3.txt", "l3");

#ifdef WIN32
  writeTextFile(root_dir / "root2.txt", "l1");
  writeTextFile(
      fs::path(root_dir.wstring()) / L"\x65b0\x5efa\x6587\x4ef6\x5939.txt",
      "l2");
#else
  boost::system::error_code ec;
  fs::create_symlink(
      root_dir / "root.txt", root_dir / "root2.txt", ec);
#endif
  return root_dir;
}

} // namespace osquery
