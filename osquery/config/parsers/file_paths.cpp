/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for an "file_paths" dictionary key.
 */
class FilePathsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() { return {"file_paths"}; }

  Status setUp() {
    data_.put_child("file_paths", pt::ptree());
    return Status(0, "OK");
  }

  Status update(const std::map<std::string, pt::ptree>& config) {
    if (config.count("file_paths") > 0) {
      data_ = pt::ptree();
      data_.put_child("file_paths", config.at("file_paths"));
    }

    for (const auto& category : data_.get_child("file_paths")) {
      for (const auto& path : category.second) {
        auto pattern = path.second.get_value<std::string>("");
        if (pattern.empty()) {
          continue;
        }
        replaceGlobWildcards(pattern);
        Config::getInstance().addFile(category.first, pattern);
      }
    }

    return Status(0, "OK");
  }
};

REGISTER_INTERNAL(FilePathsConfigParserPlugin, "config_parser", "file_paths");
}
