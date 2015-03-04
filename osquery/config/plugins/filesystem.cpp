/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fstream>
#include <iostream>

#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/filesystem.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
using osquery::Status;

namespace osquery {

FLAG(string, config_path, "/var/osquery/osquery.conf", "Path to config file");
FLAG(string,
     config_extra_files,
     "/var/osquery/osquery.conf.d/%.conf",
     "Path to extra config files");

class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  virtual std::pair<osquery::Status, std::string> genConfig();
};

REGISTER(FilesystemConfigPlugin, "config", "filesystem");

std::pair<osquery::Status, std::string> FilesystemConfigPlugin::genConfig() {
  std::string config;
  std::vector<std::string> conf_files;
  Status stat = resolveFilePattern(FLAGS_config_extra_files, conf_files);
  if (!stat.ok()) {
    VLOG(1) << "Error is resolving extra configuration files: "
            << stat.getMessage();
  }
  VLOG(1) << "Finished resolving, merging " << conf_files.size()
          << " additional JSONs";

  conf_files.push_back(FLAGS_config_path);

  pt::ptree merged;

  for (const auto& conf_file : conf_files) {
    VLOG(1) << "Filesystem ConfigPlugin reading: " << conf_file;
    std::ifstream config_stream(conf_file);

    config_stream.seekg(0, std::ios::end);
    config.reserve(config_stream.tellg());
    config_stream.seekg(0, std::ios::beg);

    config.assign((std::istreambuf_iterator<char>(config_stream)),
                  std::istreambuf_iterator<char>());

    std::stringstream json(config);
    pt::ptree tree;
    pt::read_json(json, tree);

    for (const auto& elem : tree) {
      merged.push_back(elem);
    }
  }
  std::stringstream complete;
  write_json(complete, merged);
  return std::make_pair(Status(0, "OK"), complete.str());
}
}
