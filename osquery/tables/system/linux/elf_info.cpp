/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include <LIEF/ELF.hpp>
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

QueryData getELFStrings(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      Row r;
      for (const auto& string : elf_binary->strings()) {
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["string"] = string;
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

QueryData getELFInfo(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      Row r;

      // Get basic ELF file info
      r["path"] = path_string;
      r["filename"] = path.filename().string();
      r["class"] = LIEF::ELF::to_string(elf_binary->header().identity_class());
      r["abi"] = LIEF::ELF::to_string(elf_binary->header().identity_os_abi());
      std::ostringstream stream;
      stream << std::hex << elf_binary->entrypoint();
      r["entrypoint"] = stream.str();
      r["abi_version"] = INTEGER(elf_binary->header().identity_abi_version());
      r["is_pie"] = INTEGER(elf_binary->is_pie());
      r["type"] = LIEF::ELF::to_string(elf_binary->header().file_type());
      r["version"] =
          LIEF::ELF::to_string(elf_binary->header().object_file_version());
      r["machine"] = LIEF::ELF::to_string(elf_binary->header().machine_type());
      r["flags"] = INTEGER(elf_binary->header().processor_flag());
      r["has_nx"] = INTEGER(elf_binary->has_nx());
      results.push_back(r);
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

QueryData getELFSegments(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      for (const auto& binary : elf_binary->segments()) {
        Row r;

        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["segment_name"] = LIEF::ELF::to_string(binary.type());
        std::ostringstream stream;
        stream << std::hex << binary.file_offset();
        r["segment_file_offset"] = stream.str();
        stream.str("");
        stream << std::hex << binary.virtual_address();
        r["segment_virtual_address"] = stream.str();
        stream.str("");
        stream << std::hex << binary.physical_address();
        r["segment_physical_address"] = stream.str();
        r["segment_physical_size"] = BIGINT(binary.physical_size());
        r["segment_virtual_size"] = BIGINT(binary.virtual_size());
        r["alignment"] = INTEGER(binary.alignment());

        r["segment_flags"] = LIEF::ELF::to_string(binary.flags());
        results.push_back(r);
      }

    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

QueryData getELFSymbols(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      for (const auto& binary : elf_binary->symbols()) {
        Row r;

        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["symbol_name"] = binary.name();
        r["symbol_type"] = LIEF::ELF::to_string(binary.type());
        r["binding"] = LIEF::ELF::to_string(binary.binding());
        r["symbol_shndx"] = INTEGER(binary.shndx());
        if (binary.has_version() &&
            binary.symbol_version().has_auxiliary_version()) {
          r["symbol_version"] =
              binary.symbol_version().symbol_version_auxiliary().name();
        } else {
          r["symbol_version"] = "";
        }
        r["symbol_size"] = INTEGER(binary.size());
        results.push_back(r);
      }

    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

QueryData getELFSections(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      for (const auto& binary : elf_binary->sections()) {
        Row r;

        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["section_name"] = binary.name();
        r["type"] = LIEF::ELF::to_string(binary.type());
        std::ostringstream stream;
        stream << std::hex << binary.offset();
        r["section_address"] = stream.str();
        std::string section_flags;
        for (const auto& flags : binary.flags_list()) {
          section_flags += LIEF::ELF::to_string(flags);
          section_flags += "|";
        }
        section_flags.pop_back();
        r["section_flags"] = section_flags;
        r["link"] = INTEGER(binary.link());
        r["align"] = INTEGER(binary.alignment());
        r["section_size"] = INTEGER(binary.size());

        // LIEF returns 0 as -0.0000, strip negative sign from 0 value
        if (std::to_string(binary.entropy()).find("-") != std::string::npos) {
          r["entropy"] = std::to_string(binary.entropy()).erase(0, 1);
        } else {
          r["entropy"] = std::to_string(binary.entropy());
        }
        results.push_back(r);
      }

    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

QueryData getELFDynamic(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      for (const auto& binary : elf_binary->dynamic_entries()) {
        Row r;

        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["dynamic_tag"] = LIEF::ELF::to_string(binary.tag());
        ;
        r["dynamic_value"] = INTEGER(binary.value());
        r["class"] =
            LIEF::ELF::to_string(elf_binary->header().identity_class());
        ;
        results.push_back(r);
      }

    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
