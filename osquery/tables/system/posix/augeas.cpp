/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <augeas.h>

#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>

#include <boost/algorithm/string/join.hpp>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {

/**
 * @brief Augeas lenses path.
 *
 * Directory that contains augeus lenses.
 */
#ifdef __APPLE__
FLAG(string,
     augeas_lenses,
     "/private/var/osquery/lenses",
     "Directory that contains augeas lenses files");
#else
FLAG(string,
     augeas_lenses,
     "/usr/share/osquery/lenses",
     "Directory that contains augeas lenses files");
#endif

namespace tables {

void reportAugeasError(augeas* aug) {
  const char* error_message = aug_error_message(aug);
  LOG(ERROR) << "An error has occurred while trying to query augeas: "
             << error_message;
}

void matchAugeasPattern(augeas* aug,
                        const std::string& pattern,
                        QueryData& results,
                        QueryContext& context) {
  // The caller may supply an Augeas PATH/NODE expression or filesystem path.
  // Below we formulate a Augeas pattern from a path if needed.
  int result = aug_defvar(aug, "matches", pattern.c_str());
  if (result == -1) {
    reportAugeasError(aug);
    return;
  }

  char** matches = nullptr;
  int len = aug_match(aug, "$matches", &matches);

  // Handle matching errors.
  if (matches == nullptr) {
    return;
  } else if (len < 0) {
    reportAugeasError(aug);
    return;
  }

  // Emit a row for each match.
  results.reserve(len);
  for (size_t i = 0; i < static_cast<size_t>(len); i++) {
    if (matches[i] == nullptr) {
      continue;
    }

    // The caller is responsible for the matching memory.
    std::string node(matches[i]);
    free(matches[i]);

    const char *value = nullptr, *label = nullptr;
    char* file = nullptr;
    result = aug_ns_attr(aug, "matches", i, &value, &label, &file);
    if (result == -1) {
      reportAugeasError(aug);
      return;
    }

    std::string path;
    if (file != nullptr) {
      path = file;
      path = path.substr(6);
      // The caller is responsible for the matching memory.
      free(file);
    } else if (node.compare(0, 6, "/files") == 0) {
      // If the iterator is currently pointing to a directory, the
      // node should appear in /files. Extract the path and from the
      // node.
      path = node.substr(6);
    }

    results.emplace_back(
        std::initializer_list<std::pair<const std::string, std::string>>{
            {"node", node},
            {"value", value == nullptr ? "" : value},
            {"path", path},
            {"label", label == nullptr ? "" : label}});
  }

  // aug_match() allocates the matches array and expects the caller to free it.
  free(matches);
}

class AugeasHandle {
 public:
  augeas* aug{nullptr};
  bool error{false};

  void initialize() {
    std::call_once(initialized, [this]() {
      this->aug = aug_init(
          nullptr,
          FLAGS_augeas_lenses.c_str(),
          AUG_NO_ERR_CLOSE | AUG_NO_LOAD | AUG_NO_STDINC | AUG_SAVE_NOOP);
      // Handle initialization errors.
      if (this->aug == nullptr) {
        LOG(ERROR) << "An error has occurred while trying to initialize augeas";
        error = true;
      } else if (aug_error(this->aug) != AUG_NOERROR) {
        error = true;
        // Do not use aug_error_details() here since augeas is not fully
        // initialized.
        LOG(ERROR)
            << "An error has occurred while trying to initialize augeas: "
            << aug_error_message(this->aug);
        aug_close(this->aug);
        this->aug = nullptr;
      }
    });
  }

  ~AugeasHandle() {
    aug_close(aug);
    aug = nullptr;
  }

 private:
  std::once_flag initialized;
};

static AugeasHandle kAugeasHandle;

std::string patternFromOsquery(const std::string& input,
                               bool isLike,
                               bool isPath) {
  // If this is a path, then we must prepend /files. Otherwise we
  // assume the caller knows what it's doing.
  std::string pattern = isPath ? "/files" + input : input;

  // Augeas presents data as a slash seperated tree. It uses `/*` as a
  // single level wildcard, and `//*` as a recursive wildcard. However,
  // sqlite uses % as a wildcard. To allow for LIKE expressions, we need
  // to convert.
  if (isLike) {
    size_t pos;
    while ((pos = pattern.find("%%")) != std::string::npos) {
      pattern.replace(pos, 2, "/*");
    }
    while ((pos = pattern.find("%")) != std::string::npos) {
      pattern.replace(pos, 1, "*");
    }
  }

  // augues blurs filename and contents into the node. So when
  // dealing with files, osquery must append the recuse wildcard. To
  // allow a LIKE query some flexibility, and to prevent augeas
  // syntax errors on extra wildcards, we only do this if there is
  // not already a wildcard there. (This handles both the LIKE and
  // EQUALS case)
  if (isPath) {
    if (strncmp(&pattern.back(), "*", 1) != 0) {
      pattern.append("//*");
    }
  }

  return pattern;
}

QueryData genAugeas(QueryContext& context) {
  // Strategy for handling augeas
  // (As informed by forensic examination of the underlying code)
  //
  // Augeas is a powerful tool for representing configuration files
  // as a tree, and then querying against it. However, it's native
  // interfaces don't feel osquery's underlying model. So we shim a bit.
  //
  // Augeas normally reads everything it can into a giant
  // tree. Files are rooted at `/files`, while augeas is rooted at
  // `/augeas`. Information is queried from augeas by running
  // matches against the tree paths.  In contrast, osquery tends to
  // operate by loading data at runtime, frequently by file path.
  //
  // We bridge these worlds, by adding a `path` column to the
  // osquery output. This path is the filepath, and not the tree
  // path.
  //
  // To query, we append the augeas wildcard, and then match. The
  // returned path records have the appropriate value because they
  // refer to real paths.

  kAugeasHandle.initialize();

  if (kAugeasHandle.error == true) {
    return {};
  }

  augeas* aug = kAugeasHandle.aug;

  // Load everything. While it would be interesting to do this for
  // only the requested files, it's not clearly possible to
  // _unload_. So at present, load everything. (For reference, it
  // takes abvout 0.3 seconds to run aug_load on seph's laptop.)
  int ret = aug_load(aug);
  if (ret != 0) {
    LOG(ERROR) << "An error has occurred while trying to load augeas: "
               << aug_error_message(aug);
    return {};
  }

  QueryData results;
  std::unordered_set<std::string> patterns;

  if (context.hasConstraint("node", EQUALS)) {
    auto nodes = context.constraints["node"].getAll(EQUALS);
    patterns.insert(nodes.begin(), nodes.end());
  }

  if (context.hasConstraint("node", LIKE)) {
    auto nodes = context.constraints["node"].getAll(LIKE);
    for (const auto& node : nodes) {
      if (node.empty()) {
        continue;
      }
      patterns.insert(patternFromOsquery(node, true, false));
    }
  }

  if (context.hasConstraint("path", EQUALS)) {
    // Allow requests via filesystem path.
    auto paths = context.constraints["path"].getAll(EQUALS);
    for (const auto& path : paths) {
      if (path.empty()) {
        continue;
      }
      patterns.insert(patternFromOsquery(path, false, true));
    }
  }

  // This LIKE strategy only works because we've loaded the entire
  // augeas system. If we ever move to loading by explicit files, this
  // will break.
  if (context.hasConstraint("path", LIKE)) {
    auto paths = context.constraints["path"].getAll(LIKE);
    for (const auto& path : paths) {
      if (path.empty()) {
        continue;
      }
      patterns.insert(patternFromOsquery(path, true, true));
    }
  }

  if (patterns.empty()) {
    matchAugeasPattern(aug, "/files//*", results, context);
  } else {
    matchAugeasPattern(
        aug, boost::algorithm::join(patterns, "|"), results, context);
  }

  return results;
}
}
}
