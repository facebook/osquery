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
#include <osquery/utils/conversions/windows/strings.h>

#include <LIEF/PE.hpp>
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

QueryData genPeSig(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-pe files
      if (!LIEF::PE::is_pe(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::PE::Binary> pe_binary =
          LIEF::PE::Parser::parse(path_string);
      if (!pe_binary->has_signatures()) {
        continue;
      }

      auto sig = pe_binary->signatures();

      // Get Signature info from PE file
      for (const auto& certs : sig->certificates()) {
        Row r;
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["certificate_issuer"] = certs.issuer();
        r["certificate_subject"] = certs.subject();
        std::string valid_from = "";
        for (int dates = 0; dates < certs.valid_from().size(); dates++) {
          if (dates > 2) {
            valid_from += std::to_string(certs.valid_from()[dates]) + ":";
            continue;
          }
          if (dates == 2) {
            valid_from += std::to_string(certs.valid_from()[dates]) + " ";
            continue;
          }
          valid_from += std::to_string(certs.valid_from()[dates]) + "-";
        }
        valid_from.pop_back();
        r["certificate_valid_from"] = valid_from;
        std::string valid_to = "";
        for (int dates = 0; dates < certs.valid_to().size(); dates++) {
          if (dates > 2) {
            valid_to += std::to_string(certs.valid_to()[dates]) + ":";
            continue;
          }
          if (dates == 2) {
            valid_to += std::to_string(certs.valid_to()[dates]) + " ";
            continue;
          }
          valid_to += std::to_string(certs.valid_to()[dates]) + "-";
        }
        valid_to.pop_back();
        r["certificate_valid_to"] = valid_to;
        r["certificate_version"] = INTEGER(certs.version());
        std::string serial = "";
        for (const auto& serial_num : certs.serial_number()) {
          std::ostringstream stream;
          stream << std::hex << (int)serial_num;
          serial += stream.str() + ":";
        }
        serial.pop_back();
        r["certificate_serial_number"] = serial;
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse PE file: " << error.what();
    }
  }
  return results;
}

QueryData genPeSections(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-pe files
      if (!LIEF::PE::is_pe(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::PE::Binary> pe_binary =
          LIEF::PE::Parser::parse(path_string);

      // Get Section info from PE file
      for (const auto& section : pe_binary->sections()) {
        Row r;
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["section_name"] = section.name();
        r["section_size"] = INTEGER(section.sizeof_raw_data());
        r["virtual_size"] = INTEGER(section.virtual_size());
        // LIEF returns 0 as -0.0000, strip negative sign from 0 value
        if (std::to_string(section.entropy()).find("-") != std::string::npos) {
          r["entropy"] = std::to_string(section.entropy()).erase(0, 1);
        } else {
          r["entropy"] = std::to_string(section.entropy());
        }
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse PE file: " << error.what();
    }
  }
  return results;
}

QueryData genPeLibraries(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-pe files
      if (!LIEF::PE::is_pe(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::PE::Binary> pe_binary =
          LIEF::PE::Parser::parse(path_string);

      // Get Library info from PE file
      for (const auto& imports : pe_binary->imports()) {
        Row r;
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["library_name"] = imports.name();
        std::ostringstream stream;
        stream << std::hex << imports.import_address_table_rva();
        r["import_address_table_rva"] = stream.str();
        stream.str("");
        stream << std::hex << imports.import_lookup_table_rva();
        r["import_lookup_table_rva"] = stream.str();
        r["timestamp"] = INTEGER(imports.timedatestamp());
        r["forwarder_chain"] = INTEGER(imports.forwarder_chain());
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse PE file: " << error.what();
    }
  }
  return results;
}

QueryData genPeFunctions(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);

  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-pe files
      if (!LIEF::PE::is_pe(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::PE::Binary> pe_binary =
          LIEF::PE::Parser::parse(path_string);

      // Get imported functions from PE file
      for (const auto& imports : pe_binary->imports()) {
        for (const auto& entries : imports.entries()) {
          Row r;
          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["type"] = "import";
          r["function_name"] = entries.name();
          std::ostringstream stream;
          stream << std::hex << entries.iat_value();
          r["function_address"] = stream.str();
          r["library"] = imports.name();
          if (entries.is_ordinal()) {
            r["ordinal"] = INTEGER(entries.ordinal());
          }
          results.push_back(r);
        }
      }
      auto& exports = pe_binary->get_export();

      // Get exported functiosn from PE file
      for (const auto& entries : exports.entries()) {
        Row r;
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["type"] = "export";
        r["library"] = exports.name();
        r["function_name"] = entries.name();
        std::ostringstream stream;
        stream << std::hex << entries.address();
        r["function_address"] = stream.str();
        r["ordinal"] = INTEGER(entries.ordinal());
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse PE file: " << error.what();
    }
  }
  return results;
}

QueryData genPeInfo(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-pe files
      if (!LIEF::PE::is_pe(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::PE::Binary> pe_binary =
          LIEF::PE::Parser::parse(path_string);
      Row r;

      // Get basic PE file info
      r["path"] = path_string;
      r["filename"] = path.filename().string();
      r["signed"] = INTEGER(pe_binary->has_signatures());
      r["imphash"] = LIEF::PE::get_imphash(*pe_binary);
      std::ostringstream stream;
      stream << std::hex << pe_binary->entrypoint();
      r["entrypoint"] = stream.str();
      r["is_pie"] = INTEGER(pe_binary->is_pie());
      r["has_resources"] = INTEGER(pe_binary->has_resources());

      // Check if resources contain additional metadata
      if (pe_binary->has_resources() &&
          pe_binary->resources_manager().has_version() &&
          pe_binary->resources_manager().version().has_string_file_info()) {
        r["number_of_language_codes"] = INTEGER(pe_binary->resources_manager()
                                                    .version()
                                                    .string_file_info()
                                                    .langcode_items()
                                                    .size());

        int items = 0;
        while (items < pe_binary->resources_manager()
                           .version()
                           .string_file_info()
                           .langcode_items()
                           .size()) {
          std::unordered_map<std::u16string, std::u16string> string_info =
              pe_binary->resources_manager()
                  .version()
                  .string_file_info()
                  .langcode_items()[items]
                  .items();
          r["language"] = LIEF::PE::to_string(pe_binary->resources_manager()
                                                  .version()
                                                  .string_file_info()
                                                  .langcode_items()[items]
                                                  .lang());
          if (string_info.find(u"CompanyName") != string_info.end()) {
            std::wstring info_data(string_info[u"CompanyName"].begin(),
                                   string_info[u"CompanyName"].end());
            r["company_name"] = wstringToString(info_data);
          }
          if (string_info.find(u"ProductVersion") != string_info.end()) {
            std::wstring info_data(string_info[u"ProductVersion"].begin(),
                                   string_info[u"ProductVersion"].end());
            r["product_version"] = wstringToString(info_data);
          }
          if (string_info.find(u"FileVersion") != string_info.end()) {
            std::wstring info_data(string_info[u"FileVersion"].begin(),
                                   string_info[u"FileVersion"].end());
            r["file_version"] = wstringToString(info_data);
          }
          if (string_info.find(u"FileDescription") != string_info.end()) {
            std::wstring info_data(string_info[u"FileDescription"].begin(),
                                   string_info[u"FileDescription"].end());
            r["file_description"] = wstringToString(info_data);
          }
          if (string_info.find(u"ProductName") != string_info.end()) {
            std::wstring info_data(string_info[u"ProductName"].begin(),
                                   string_info[u"ProductName"].end());
            r["product_name"] = wstringToString(info_data);
          }
          if (string_info.find(u"InternalName") != string_info.end()) {
            std::wstring info_data(string_info[u"InternalName"].begin(),
                                   string_info[u"InternalName"].end());
            r["internal_name"] = wstringToString(info_data);
          }
          if (string_info.find(u"LegalCopyright") != string_info.end()) {
            std::wstring info_data(string_info[u"LegalCopyright"].begin(),
                                   string_info[u"LegalCopyright"].end());
            r["legal_copyright"] = wstringToString(info_data);
          }
          if (string_info.find(u"OriginalFilename") != string_info.end()) {
            std::wstring info_data(string_info[u"OriginalFilename"].begin(),
                                   string_info[u"OriginalFilename"].end());
            r["original_filename"] = wstringToString(info_data);
          }
          if (string_info.find(u"LegalTrademarks") != string_info.end()) {
            std::wstring info_data(string_info[u"LegalTrademarks"].begin(),
                                   string_info[u"LegalTrademarks"].end());
            r["legal_trademarks"] = wstringToString(info_data);
          }
          if (string_info.find(u"Comments") != string_info.end()) {
            std::wstring info_data(string_info[u"Comments"].begin(),
                                   string_info[u"Comments"].end());
            r["comments"] = wstringToString(info_data);
          }
          if (string_info.find(u"PrivateBuild") != string_info.end()) {
            std::wstring info_data(string_info[u"PrivateBuild"].begin(),
                                   string_info[u"PrivateBuild"].end());
            r["private_build"] = wstringToString(info_data);
          }
          if (string_info.find(u"SpecialBuild") != string_info.end()) {
            std::wstring info_data(string_info[u"SpecialBuild"].begin(),
                                   string_info[u"SpecialBuild"].end());
            r["special_build"] = wstringToString(info_data);
          }
          results.push_back(r);
          items++;
        }
      } else {
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse PE file: " << error.what();
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery