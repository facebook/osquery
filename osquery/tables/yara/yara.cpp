/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>
#include <thread>

#ifdef LINUX
#include <malloc.h>
#endif

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>

#include "osquery/tables/yara/yara_utils.h"

#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

namespace osquery {

// After a large scan of many files, the memory allocation could be
// substantial.  free() may not return it to operating system, but
// rather keep it around in anticipation that app will reallocate.
// Call malloc_trim() on linux to try to convince it to release.
#ifdef LINUX
FLAG(bool,
     yara_malloc_trim,
     true,
     "Call malloc_trim() after YARA scans (linux)");
#endif

FLAG(uint32,
     yara_delay,
     50,
     "Time in ms to sleep after scan of each file (default 50) to reduce "
     "memory spikes");

HIDDEN_FLAG(bool,
            enable_yara_sigrule,
            false,
            "Enable yara table extension to pass sigrule with query ");

HIDDEN_FLAG(bool,
            enable_yara_string,
            false,
            "The yara strings are private by default. The flag will disable "
            "the feature and string column will show with the table");

namespace tables {

using YaraRuleSet = std::set<std::string>;

typedef enum { YC_NONE = 0, YC_GROUP, YC_FILE, YC_RULE } YaraRuleType;

using YARAConfigParser = std::shared_ptr<YARAConfigParserPlugin>;

using YaraScanContext = std::set<std::pair<YaraRuleType, std::string>>;

// Check if the YARAConfigParser is nullptr
static inline bool isNull(std::shared_ptr<ConfigParserPlugin> parser) {
  return (parser == nullptr) || (parser.get() == nullptr);
}

static inline std::string hashStr(const std::string& str, YaraRuleType yc) {
  switch (yc) {
  case YC_RULE:
    return "rule_" +
           hashFromBuffer(HASH_TYPE_SHA256, str.c_str(), str.length());
  default:
    return str;
  }
};

// Get the yara configuration parser
static YARAConfigParser getYaraParser(void) {
  auto parser = Config::getParser("yara");
  if (isNull(parser)) {
    LOG(ERROR) << "YARA config parser plugin not found";
    return nullptr;
  }

  YARAConfigParser yaraParser = nullptr;
  try {
    yaraParser = std::dynamic_pointer_cast<YARAConfigParserPlugin>(parser);
  } catch (const std::bad_cast& e) {
    LOG(ERROR) << "Cannot cast YARA config parser plugin";
    return nullptr;
  }

  return yaraParser;
}

void doYARAScan(YR_RULES* rules,
                const std::string& path,
                QueryData& results,
                YaraRuleType yr_type,
                const std::string& sigfile) {
  Row row;

  // These are default values, to be updated in YARACallback.
  row["count"] = INTEGER(0);
  row["matches"] = SQL_TEXT("");
  row["strings"] = SQL_TEXT("");
  row["tags"] = SQL_TEXT("");
  row["sig_group"] = SQL_TEXT("");
  row["sigfile"] = SQL_TEXT("");
  row["sigrule"] = SQL_TEXT("");

  // This could use target_path instead to be consistent with yara_events.
  row["path"] = path;

  switch (yr_type) {
  case YC_GROUP:
    row["sig_group"] = SQL_TEXT(sigfile);
    break;
  case YC_FILE:
    row["sigfile"] = SQL_TEXT(sigfile);
    break;
  case YC_RULE:
    row["sigrule"] = SQL_TEXT(sigfile);
    break;
  case YC_NONE:
    break;
  }

  // Perform the scan, using the static YARA subscriber callback.
  int result = yr_rules_scan_file(
      rules, path.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&row, 0);
  if (result == ERROR_SUCCESS) {
    results.push_back(std::move(row));
  }
}

Status getYaraRules(YARAConfigParser parser,
                    YaraRuleSet signature_set,
                    YaraRuleType sign_type,
                    YaraScanContext& context) {
  if (isNull(parser)) {
    return Status::failure("YARA config parser plugin not found");
  }

  auto& rules_map = parser->rules();

  // Compile signature string and add them to the scan context
  for (const auto& sign : signature_set) {
    // Check if the signature string has been used/compiled
    if (rules_map.count(hashStr(sign, sign_type)) > 0) {
      context.insert(std::make_pair(sign_type, sign));
      continue;
    }

    YR_RULES* tmp_rules = nullptr;
    switch (sign_type) {
    case YC_FILE: {
      auto path = (sign[0] != '/') ? (kYARAHome + sign) : sign;
      auto status = compileSingleFile(path, &tmp_rules);
      if (!status.ok()) {
        LOG(WARNING) << "YARA compile error: " << status.toString();
        continue;
      }
      break;
    }

    case YC_RULE: {
      auto status = compileFromString(sign, &tmp_rules);
      if (!status.ok()) {
        LOG(WARNING) << "YARA compile error: " << status.toString();
        continue;
      }
      break;
    }

    default:
      return Status::failure("Unsupported YARA rule type");
    }

    // Cache the compiled rules by setting the unique hashed signature
    // string as the lookup name. Additional signature file uses will
    // skip the compile step and be added to the scan context
    rules_map[hashStr(sign, sign_type)] = tmp_rules;
    context.insert(std::make_pair(sign_type, sign));
  }

  return Status::success();
}

QueryData genYara(QueryContext& context) {
  QueryData results;
  YaraScanContext scanContext;

  // Initialize yara library
  auto init_status = yaraInitilize();
  if (!init_status.ok()) {
    LOG(WARNING) << init_status.toString();
    return results;
  }

  auto yaraParser = getYaraParser();
  if (isNull(yaraParser)) {
    return results;
  }

  // The query must specify one of sig_groups, sigfile, or sigrule
  // for scan. The signature rules are compiled and added to the
  // scan context.
  if (context.hasConstraint("sig_group", EQUALS)) {
    auto groups = context.constraints["sig_group"].getAll(EQUALS);
    for (const auto& group : groups) {
      scanContext.insert(std::make_pair(YC_GROUP, group));
    }
  }

  if (context.hasConstraint("sigfile", EQUALS)) {
    // Compile signature files and add them to the scan context
    auto sigfiles = context.constraints["sigfile"].getAll(EQUALS);
    auto status = getYaraRules(yaraParser, sigfiles, YC_FILE, scanContext);
    if (!status.ok()) {
      return results;
    }
  }

  if (FLAGS_enable_yara_sigrule && context.hasConstraint("sigrule", EQUALS)) {
    // Compile signature strings and add them to the scan context
    auto sigrules = context.constraints["sigrule"].getAll(EQUALS);
    auto status = getYaraRules(yaraParser, sigrules, YC_RULE, scanContext);
    if (!status.ok()) {
      return results;
    }
  }

  // return if scan context is empty. One of sig_group, sigfile, or
  // sigrule must be specified.
  if (scanContext.empty()) {
    VLOG(1) << "Query must specify sig_group, sigfile, or sigrule for scan";
    return results;
  }

  // Get all the paths specified
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FILES | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            struct stat sb;
            if (0 != stat(resolved.c_str(), &sb)) {
              continue; // failed to stat the file
            }

            // Check that each resolved path is readable.
            if (isReadable(resolved) &&
                !yaraShouldSkipFile(resolved, sb.st_mode)) {
              paths.insert(resolved);
            }
          }
        }
        return status;
      }));

  // Scan every path pair with the yara rules
  auto& rules = yaraParser->rules();
  for (const auto& path : paths) {
    for (const auto& sign : scanContext) {
      if (rules.count(hashStr(sign.second, sign.first)) > 0) {
        doYARAScan(rules[hashStr(sign.second, sign.first)],
                   path.c_str(),
                   results,
                   sign.first,
                   sign.second);

        // sleep between each file to help smooth out malloc spikes
        std::this_thread::sleep_for(
            std::chrono::milliseconds(FLAGS_yara_delay));
      }
    }
  }

  // Rule string is hashed before adding to the cache. There are
  // possibilities of collision when arbitrary queries are executed
  // with distributed API. Clear the hash string from the cache
  for (const auto& sign : scanContext) {
    if (sign.first == YC_RULE) {
      auto it = rules.find(hashStr(sign.second, sign.first));
      if (it != rules.end()) {
        rules.erase(hashStr(sign.second, sign.first));
      }
    }
  }

  // Clean-up after finish scanning; If yr_initialize is called
  // more than once it will decrease the reference counter and return
  auto fini_status = yaraFinalize();
  if (!fini_status.ok()) {
    LOG(WARNING) << fini_status.toString();
  }

#ifdef LINUX
  if (osquery::FLAGS_yara_malloc_trim) {
    malloc_trim(0);
  }
#endif

  return results;
}
} // namespace tables
} // namespace osquery
