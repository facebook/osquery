/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/property_tree/ini_parser.hpp>
#include <fstream>
#include <iostream>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/system/system.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

const std::string kYumConf{"/etc/yum.conf"};
const std::string kYumReposDir{"/etc/yum.repos.d"};
const std::string kYumConfigFileExtension{".repo"};

void parseYumConf(std::istream& source,
                  QueryData& results,
                  std::string& repos_dir) {
  boost::property_tree::ptree tree;
  boost::property_tree::ini_parser::read_ini(source, tree);
  repos_dir = tree.get("main.reposdir", kYumReposDir);

  for (auto it1 : tree) {
    // Section
    if (it1.first == "main") {
      continue;
    }

    Row r;
    for (auto it2 : it1.second) {
      // Option
      if ("baseurl" == it2.first || "enabled" == it2.first ||
          "gpgcheck" == it2.first || "name" == it2.first ||
          "gpgkey" == it2.first) {
        r[it2.first] = it2.second.data();
      }
    }
    r["pid_with_namespace"] = "0";
    results.push_back(r);
  }
}

void parseYumConf(const std::string& source,
                  QueryData& results,
                  std::string& repos_dir,
                  Logger& logger) {
  std::ifstream stream(source.c_str());
  if (!stream) {
    logger.vlog(1, "File " + source + " cannot be read");
    repos_dir = kYumReposDir;
    return;
  }

  try {
    parseYumConf(stream, results, repos_dir);
  } catch (boost::property_tree::ini_parser::ini_parser_error& e) {
    logger.vlog(
        1,
        "File " + source + " either cannot be read or cannot be parsed as ini");
    repos_dir = kYumReposDir;
  }
}

QueryData genYumSrcsImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  // Expect the YUM home to be /etc/yum.conf
  std::string repos_dir;
  parseYumConf(kYumConf, results, repos_dir, logger);

  std::vector<std::string> sources;
  if (!resolveFilePattern(
          repos_dir + "/%" + kYumConfigFileExtension, sources, GLOB_FILES)) {
    logger.vlog(1,
                "Cannot resolve yum conf files under " + repos_dir + "/*" +
                    kYumConfigFileExtension);
    return results;
  }

  for (const auto& source : sources) {
    parseYumConf(source, results, repos_dir, logger);
  }

  return results;
}

QueryData genYumSrcs(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "yum_sources", genYumSrcsImpl);
  } else {
    GLOGLogger logger;
    return genYumSrcsImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
