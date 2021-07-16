/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>

#include <stdlib.h>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

#ifdef WIN32
#include "windows/registry.h"
#endif

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// Number of fields when splitting metadata and info.
const size_t kNumFields = 2;
const std::set<std::string> kPythonPath = {
    "/usr/local/lib/python%/dist-packages",
    "/usr/local/lib/python%/site-packages",
    "/usr/lib/python%/dist-packages",
    "/usr/lib/python%/site-packages",
    "/Library/Python/%/site-packages",
};

const std::set<std::string> kDarwinPythonPath = {
    "/System/Library/Frameworks/Python.framework/Versions",
};

const std::string kWinPythonInstallKey =
    "SOFTWARE\\Python\\PythonCore\\%\\InstallPath";

void genPackage(const std::string& path, Row& r, Logger& logger) {
  std::string content;
  auto s = readFile(path, content, false, false);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    logger.vlog(1, s.getMessage());
    logger.vlog(1, "Cannot find info file: " + path);
    return;
  }

  auto lines = split(content, "\n");

  for (const auto& line : lines) {
    auto fields = split(line, ":");

    if (fields.size() != kNumFields) {
      continue;
    }

    if (fields[0] == "Name") {
      r["name"] = fields[1];
    } else if (fields[0] == "Version") {
      r["version"] = fields[1];
    } else if (fields[0] == "Summary") {
      r["summary"] = fields[1];
    } else if (fields[0] == "Author") {
      r["author"] = fields[1];
    } else if (fields[0] == "License") {
      r["license"] = fields[1];
      break;
    }
  }
}

void genSiteDirectories(const std::string& site,
                        QueryData& results,
                        Logger& logger) {
  std::vector<std::string> directories;
  if (!listDirectoriesInDirectory(site, directories, true).ok()) {
    return;
  }

  for (const auto& directory : directories) {
    if (!isDirectory(directory).ok()) {
      continue;
    }

    Row r;
    if (directory.find(".dist-info") != std::string::npos) {
      auto path = directory + "/METADATA";
      genPackage(path, r, logger);
    } else if (directory.find(".egg-info") != std::string::npos) {
      auto path = directory + "/PKG-INFO";
      genPackage(path, r, logger);
    } else {
      continue;
    }

    r["directory"] = site;
    r["path"] = directory;
    r["pid_with_namespace"] = "0";
    results.push_back(r);
  }
}

void genWinPythonPackages(const std::string& keyGlob,
                          QueryData& results,
                          Logger& logger) {
#ifdef WIN32
  std::set<std::string> installPathKeys;
  expandRegistryGlobs(keyGlob, installPathKeys);
  QueryData pythonInstallLocation;
  for (const auto& installKey : installPathKeys) {
    queryKey(installKey, pythonInstallLocation);
    for (const auto& p : pythonInstallLocation) {
      if (p.at("name") != "(Default)") {
        continue;
      }
      genSiteDirectories(p.at("data"), results, logger);
    }
    pythonInstallLocation.clear();
  }
#endif
}

QueryData genPythonPackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  std::set<std::string> paths;
  if (context.constraints.count("directory") > 0 &&
      context.constraints.at("directory").exists(EQUALS)) {
    paths = context.constraints["directory"].getAll(EQUALS);
  } else {
    for (const auto& path : kPythonPath) {
      std::vector<std::string> sites;
      resolveFilePattern(path, sites);
      for (const auto& site : sites) {
        paths.insert(site);
      }
    }
  }
  for (const auto& key : paths) {
    genSiteDirectories(key, results, logger);
  }

  if (isPlatform(PlatformType::TYPE_OSX)) {
    for (const auto& dir : kDarwinPythonPath) {
      std::vector<std::string> versions;
      if (!listDirectoriesInDirectory(dir, versions, false).ok()) {
        continue;
      }

      for (const auto& version : versions) {
        // macOS will link older versions to 2.6.
        auto version_path = fs::path(version).parent_path();
        if (fs::is_symlink(symlink_status(version_path))) {
          continue;
        }

        auto complete = version + "lib/python" +
                        version_path.filename().string() + "/site-packages";
        genSiteDirectories(complete, results, logger);
      }
    }
  } else if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    // Enumerate any system installed python packages
    auto installPathKey = "HKEY_LOCAL_MACHINE\\" + kWinPythonInstallKey;
    genWinPythonPackages(installPathKey, results, logger);

    // Enumerate any user installed python packages
    installPathKey = "HKEY_USERS\\%\\" + kWinPythonInstallKey;
    genWinPythonPackages(installPathKey, results, logger);
  }

  return results;
}

QueryData genPythonPackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(
        context, "python_packages", genPythonPackagesImpl);
  } else {
    GLOGLogger logger;
    return genPythonPackagesImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
