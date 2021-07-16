/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

#ifndef WIN32
fs::path kEtcHosts = "/etc/hosts";
#else
fs::path kEtcHosts = (getSystemRoot() / "system32\\drivers\\etc\\hosts");
fs::path kEtcHostsIcs = (getSystemRoot() / "system32\\drivers\\etc\\hosts.ics");
#endif
QueryData parseEtcHostsContent(const std::string& content) {
  QueryData results;

  for (const auto& _line : osquery::split(content, "\n")) {
    auto line = split(_line);
    if (line.size() == 0 || boost::starts_with(line[0], "#")) {
      continue;
    }

    Row r;
    r["address"] = line[0];
    if (line.size() > 1) {
      std::vector<std::string> hostnames;
      for (size_t i = 1; i < line.size(); ++i) {
        if (boost::starts_with(line[i], "#")) {
          break;
        }
        hostnames.push_back(line[i]);
      }
      r["hostnames"] = boost::algorithm::join(hostnames, " ");
    }
    r["pid_with_namespace"] = "0";
    results.push_back(r);
  }

  return results;
}

QueryData genEtcHostsImpl(QueryContext& context, Logger& logger) {
  std::string content;
  QueryData qres = {};

  auto s = readFile(kEtcHosts, content, 0, false, false, false, false);
  if (s.ok()) {
    qres = parseEtcHostsContent(content);
  } else {
    logger.log(google::GLOG_WARNING, s.getMessage());
    logger.vlog(1, s.getMessage());
  }

#ifdef WIN32
  content.clear();
  QueryData qres_ics = {};
  if (readFile(kEtcHostsIcs, content).ok()) {
    qres_ics = parseEtcHostsContent(content);
    qres.insert(qres.end(), qres_ics.begin(), qres_ics.end());
  }
#endif

  return qres;
}

QueryData genEtcHosts(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "etc_hosts", genEtcHostsImpl);
  } else {
    GLOGLogger logger;
    return genEtcHostsImpl(context, logger);
  }
}
}
}
