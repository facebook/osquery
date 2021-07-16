/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/replace.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/posix/apt_sources.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/system/system.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

Status parseAptSourceLine(const std::string& input_line,
                          AptSource& apt_source) {
  // attempts to follow conventions in this doc
  // http://manpages.ubuntu.com/manpages/xenial/man5/sources.list.5.html

  // Remove everything after # from the line for comments
  auto comment_pos = input_line.find("#");
  std::string line;
  if (comment_pos != std::string::npos) {
    line = input_line.substr(0, comment_pos);
  } else {
    line = input_line;
  }

  // Only look for deb names (not deb-src).
  auto deb_pos = line.find("deb ");
  if (deb_pos == std::string::npos) {
    return Status::failure("No deb prefix");
  }
  line = line.substr(deb_pos + 4); // for "deb " length

  // Split on whitespace
  // additional leading whitespace will get clobbered by split
  auto tokens = osquery::split(line, " ");
  if (tokens.empty()) {
    return Status::failure("Empty line");
  }
  if (tokens.size() < 2) {
    return Status::failure("not enough tokens specified");
  }

  size_t offset = 0;

  // The source name could set [arch=ARCH option2=something ].
  if (tokens[offset][0] == '[') {
    // Seek to the end of the options
    for (size_t i = offset; i < tokens.size(); i++) {
      if (tokens[i].find("]") != std::string::npos) {
        offset = i;
        break;
      }
    }
    // go to the next token after the close of options ']'
    offset++;
  }
  if (offset >= tokens.size()) {
    return Status::failure("incomplete line no suite");
  }

  auto host = tokens[offset].find("://");
  if (host == std::string::npos) {
    return Status::failure("Cannot find protocol");
  }

  apt_source.base_uri = tokens[offset];
  // Cannot have trailing slashes
  while (apt_source.base_uri.back() == '/') {
    apt_source.base_uri.pop_back();
  }

  // go on to parse the suite
  offset++;
  if (offset >= tokens.size()) {
    return Status::failure("incomplete line no suite");
  }
  std::string suite = tokens[offset];

  // get the target of the uri for the name
  if (apt_source.base_uri.size() < host + 3) {
    return Status::failure("empty uri");
  }
  apt_source.name = apt_source.base_uri.substr(host + 3); // remove "://"
  // include target uri in cache name
  apt_source.cache_file.push_back(apt_source.name);

  // Construct the source 'name' from uri and suite.
  apt_source.name += ' ' + suite;

  auto suite_parts = osquery::split(suite, "/");
  if (suite_parts.size() == 1) { // this means it is a dists format
    apt_source.cache_file.push_back(suite);
    apt_source.cache_file.insert(apt_source.cache_file.begin() + 1, "dists");
  } else {
    apt_source.cache_file.insert(
        apt_source.cache_file.end(), suite_parts.begin(), suite_parts.end());
  }

  return Status::success();
}

std::string getCacheFilename(const std::vector<std::string>& cache_file) {
  // The name is the full set of components.
  auto filename = osquery::join(cache_file, "_");
  boost::replace_all(filename, "/", "_");
  return filename;
}

void genAptUrl(const std::string& source,
               const std::string& line,
               QueryData& results,
               Logger& logger) {
  AptSource apt_source;
  if (!parseAptSourceLine(line, apt_source).ok()) {
    return;
  }

  Row r;
  r["source"] = source;
  r["base_uri"] = std::move(apt_source.base_uri);
  r["name"] = std::move(apt_source.name);

  std::vector<std::string> cache_files;
  auto cache_filename = getCacheFilename(apt_source.cache_file);
  resolveFilePattern("/var/lib/apt/lists/" + cache_filename + "_%Release",
                     cache_files,
                     GLOB_FILES);
  if (cache_files.empty()) {
    return;
  }

  std::string content;
  auto s = readFile(cache_files[0], content, 0, false, false, false, false);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    logger.vlog(1, s.getMessage());
    return;
  }

  for (const auto& header : osquery::split(content, "\n")) {
    if (header.empty()) {
      continue;
    }
    if (header == "-----BEGIN PGP SIGNATURE-----") {
      // We have entered the file hashes section.
      break;
    }
    auto fields = osquery::split(header, ":");
    if (fields.size() != 2) {
      continue;
    }

    if (fields[0] == "Codename") {
      r["release"] = fields[1];
    } else if (fields[0] == "Version") {
      r["version"] = fields[1];
    } else if (fields[0] == "Origin") {
      r["maintainer"] = fields[1];
    } else if (fields[0] == "Components") {
      r["components"] = fields[1];
    } else if (fields[0] == "Architectures") {
      r["architectures"] = fields[1];
    }
  }
  r["pid_with_namespace"] = "0";
  results.push_back(r);
}

static void genAptSource(const std::string& source,
                         QueryData& results,
                         Logger& logger) {
  std::string content;

  auto s = readFile(source, content, 0, false, false, false, false);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    logger.vlog(1, s.getMessage());
    return;
  }

  for (const auto& line : osquery::split(content, "\n")) {
    // Skip empty lines
    if (line.empty()) {
      continue;
    }
    genAptUrl(source, line, results, logger);
  }
}

QueryData genAptSrcsImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // We are going to read a few files.
  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  // Expect the APT home to be /etc/apt.
  std::vector<std::string> sources;
  sources.push_back("/etc/apt/sources.list");
  if (!resolveFilePattern(
          "/etc/apt/sources.list.d/%.list", sources, GLOB_FILES)) {
    logger.vlog(1, "Cannot resolve apt sources /etc/apt/sources.list.d");
    return results;
  }

  for (const auto& source : sources) {
    genAptSource(source, results, logger);
  }

  return results;
}

QueryData genAptSrcs(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "apt_sources", genAptSrcsImpl);
  } else {
    GLOGLogger logger;
    return genAptSrcsImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
