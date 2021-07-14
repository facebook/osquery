/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include <LIEF/MACHO.hpp>
#include <sstream>

namespace osquery {
namespace tables {

std::set<std::string> expandPaths(QueryContext& context) {
  std::set<std::string> paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));
  return paths;
}

QueryData genMachoFunctions(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    // Skip non-macho files
    if (!LIEF::MachO::is_macho(path_string)) {
      continue;
    }
    auto config = LIEF::MachO::ParserConfig().deep();
    std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
        LIEF::MachO::Parser::parse(path_string, config.deep());
    try {
      for (const auto& data : mac_binary->begin()) {
        for (const auto& function : data.imported_functions()) {
          Row r;

          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
          r["function_type"] = "import";
          // Macho function names have extra "_", strip first character if its
          // "_"
          if (function.name().at(0) == '_') {
            std::string func = function.name();
            r["function_name"] = func.erase(0, 1);

          } else {
            r["function_name"] = function.name();
          }

          std::ostringstream stream;
          stream << std::hex << function.address();
          r["function_address"] = stream.str();
          results.push_back(r);
        }
        for (const auto& function : data.exported_functions()) {
          Row r;
          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
          r["function_type"] = "export";
          r["function_name"] = function.name();
          std::ostringstream stream;
          stream << std::hex << function.address();
          r["function_address"] = stream.str();
          results.push_back(r);
        }
      }

    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse MachO file: " << error.what();
    }
  }
  return results;
}

QueryData genMachoLibraries(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    // Skip non-macho files
    if (!LIEF::MachO::is_macho(path_string)) {
      continue;
    }
    try {
      auto config = LIEF::MachO::ParserConfig().deep();
      // Parse macho file and get some information
      std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
          LIEF::MachO::Parser::parse(path_string, config.deep());

      for (const auto& data : mac_binary->begin()) {
        for (const auto& library : data.libraries().begin()) {
          Row r;
          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
          r["library_name"] = library.name();
          std::ostringstream ss;
          for (const auto& version : library.current_version()) {
            ss << std::to_string(version) << ".";
          }
          r["version"] = ss.str().substr(0, ss.str().size() - 1);
          ss.str("");
          for (const auto& version : library.compatibility_version()) {
            ss << std::to_string(version) << ".";
          }
          r["compatibility_version"] = ss.str().substr(0, ss.str().size() - 1);
          ss.str("");

          results.push_back(r);
        }
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse MachO file: " << error.what();
    }
  }
  return results;
}

QueryData genMachoSections(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    // Skip non-macho files
    if (!LIEF::MachO::is_macho(path_string)) {
      continue;
    }
    try {
      auto config = LIEF::MachO::ParserConfig().deep();
      std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
          LIEF::MachO::Parser::parse(path_string, config.deep());

      for (const auto& data : mac_binary->begin()) {
        for (const auto& section : data.sections().begin()) {
          Row r;

          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
          r["section_name"] = section.name();
          std::ostringstream stream;
          stream << std::hex << section.address();
          r["section_address"] = stream.str();
          stream.str("");
          stream << std::hex << section.flags();
          r["section_flags"] = stream.str();
          r["section_size"] = INTEGER(section.Section::size());

          // LIEF returns 0 as -0.0000, strip negative sign from 0 value
          if (std::to_string(section.entropy()).find("-") !=
              std::string::npos) {
            r["entropy"] = std::to_string(section.entropy()).erase(0, 1);

          } else {
            r["entropy"] = std::to_string(section.entropy());
          }
          results.push_back(r);
        }
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse MachO file: " << error.what();
    }
  }
  return results;
}

QueryData genMachoInfo(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    // Skip non-macho files
    if (!LIEF::MachO::is_macho(path_string)) {
      continue;
    }
    try {
      auto config = LIEF::MachO::ParserConfig().deep();
      std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
          LIEF::MachO::Parser::parse(path_string, config.deep());

      for (const auto& data : mac_binary->begin()) {
        Row r;
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
        if (data.has_encryption_info()) {
          r["is_encrypted"] = INTEGER(1);
        } else {
          r["is_encrypted"] = INTEGER(0);
        }
        if (data.has_entrypoint()) {
          std::ostringstream stream;
          stream << std::hex << data.entrypoint();
          r["entrypoint"] = stream.str();
        }

        if (data.has_build_version()) {
          std::ostringstream ss;

          for (const auto& min : data.build_version().minos()) {
            ss << std::to_string(min) << ".";
          }
          r["build_version_min"] = ss.str().substr(0, ss.str().size() - 1);
          ss.str("");
          for (const auto& build : data.build_version().sdk()) {
            ss << std::to_string(build) << ".";
          }
          r["build_version_sdk"] = ss.str().substr(0, ss.str().size() - 1);
        }
        if (data.has_version_min()) {
          std::ostringstream ss;

          for (const auto& min : data.version_min().version()) {
            ss << std::to_string(min) << ".";
          }
          r["version_min"] = ss.str().substr(0, ss.str().size() - 1);
          ss.str("");
          for (const auto& build : data.version_min().sdk()) {
            ss << std::to_string(build) << ".";
          }
          r["version_sdk"] = ss.str().substr(0, ss.str().size() - 1);
        }

        r["is_pie"] = INTEGER(data.is_pie());
        r["has_nx"] = INTEGER(data.has_nx());
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse MachO file: " << error.what();
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
