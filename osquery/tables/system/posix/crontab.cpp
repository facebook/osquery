/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <vector>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

const std::string kSystemCron = "/etc/crontab";

const std::vector<std::string> kCronSearchDirs = {
    "/etc/cron.d/", // system all
    "/var/at/tabs/", // user mac:lion
    "/var/spool/cron/", // user linux:centos
    "/var/spool/cron/crontabs/", // user linux:debian
};

std::vector<std::string> cronFromFile(const std::string& path, Logger& logger) {
  std::string content;
  std::vector<std::string> cron_lines;
  if (!isReadable(path).ok()) {
    return cron_lines;
  }

  auto s = forensicReadFile(path, content, false, false);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    logger.vlog(1, s.getMessage());
    return cron_lines;
  }

  auto lines = split(content, "\n");

  // Only populate the lines that are not comments or blank.
  for (auto& line : lines) {
    // Cheat and use a non-const iteration, to inline trim.
    boost::trim(line);
    if (line.size() > 0 && line.at(0) != '#') {
      cron_lines.push_back(line);
    }
  }

  return cron_lines;
}

void genCronLine(const std::string& path,
                 const std::string& line,
                 QueryData& results) {
  Row r;

  r["path"] = path;
  auto columns = split(line, " \t");

  size_t index = 0;
  auto iterator = columns.begin();
  for (; iterator != columns.end(); ++iterator) {
    if (index == 0) {
      if ((*iterator).at(0) == '@') {
        // If the first value is an 'at' then skip to the command.
        r["event"] = *iterator;
        index = 5;
        continue;
      }
      r["minute"] = *iterator;
    } else if (index == 1) {
      r["hour"] = *iterator;
    } else if (index == 2) {
      r["day_of_month"] = *iterator;
    } else if (index == 3) {
      r["month"] = *iterator;
    } else if (index == 4) {
      r["day_of_week"] = *iterator;
    } else if (index == 5) {
      r["command"] = *iterator;
    } else {
      // Long if switch to handle command breaks from space delim.
      r["command"] += " " + *iterator;
    }
    index++;
  }

  if (r["command"].size() == 0) {
    // The line was not well-formed, perhaps it was a variable?
    return;
  }
  r["pid_with_namespace"] = "0";

  results.push_back(r);
}

QueryData genCronTabImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  std::vector<std::string> file_list;

  file_list.push_back(kSystemCron);

  for (const auto cron_dir : kCronSearchDirs) {
    osquery::listFilesInDirectory(cron_dir, file_list);
  }

  for (const auto& file_path : file_list) {
    auto lines = cronFromFile(file_path, logger);
    for (const auto& line : lines) {
      genCronLine(file_path, line, results);
    }
  }

  return results;
}

QueryData genCronTab(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "crontab", genCronTabImpl);
  } else {
    GLOGLogger logger;
    return genCronTabImpl(context, logger);
  }
}
}
}
