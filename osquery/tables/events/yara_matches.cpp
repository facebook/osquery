/*
 *  Copyright (c) 2015, Wesley Shields
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>

#include <osquery/config.h>
#include <osquery/logger.h>

/// The file change event publishers are slightly different in OS X and Linux.
#ifdef __APPLE__
#include "osquery/events/darwin/fsevents.h"
#else
#include "osquery/events/linux/inotify.h"
#endif

#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

namespace osquery {
namespace tables {

/// The file change event publishers are slightly different in OS X and Linux.
#ifdef __APPLE__
typedef EventSubscriber<FSEventsEventPublisher> FileEventSubscriber;
typedef FSEventsEventContextRef FileEventContextRef;
#define FILE_CHANGE_MASK \
  kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemModified
#else
typedef EventSubscriber<INotifyEventPublisher> FileEventSubscriber;
typedef INotifyEventContextRef FileEventContextRef;
#define FILE_CHANGE_MASK IN_CREATE | IN_CLOSE_WRITE | IN_MODIFY
#endif

/**
 * The callback used when there are compilation problems in the rules.
 */
void YARACompilerCallback(int error_level,
                          const char* file_name,
                          int line_number,
                          const char* message,
                          void* user_data) {
  if (error_level == YARA_ERROR_LEVEL_ERROR) {
    VLOG(1) << file_name << "(" << line_number << "): error: " << message;
  } else {
    VLOG(1) << file_name << "(" << line_number << "): warning: " << message;
  }
}

Status handleRuleFiles(const std::string& category,
                       const pt::ptree& rule_files,
                       std::map<std::string, YR_RULES*>* rules) {
  YR_COMPILER* compiler = nullptr;
  int result = yr_compiler_create(&compiler);
  if (result != ERROR_SUCCESS) {
    VLOG(1) << "Could not create compiler: " + std::to_string(result);
    return Status(1, "Could not create compiler: " + std::to_string(result));
  }

  yr_compiler_set_callback(compiler, YARACompilerCallback, NULL);

  bool compiled = false;
  for (const auto& item : rule_files) {
    YR_RULES* tmp_rules;
    const auto rule = item.second.get("", "");
    VLOG(1) << "Loading " << rule;

    // First attempt to load the file, in case it is saved (pre-compiled)
    // rules. Sadly there is no way to load multiple compiled rules in
    // succession. This means that:
    //
    // saved1, saved2
    // results in saved2 being the only file used.
    //
    // Also, mixing source and saved rules results in the saved rules being
    // overridden by the combination of the source rules once compiled, e.g.:
    //
    // file1, saved1
    // result in file1 being the only file used.
    //
    // If you want to use saved rule files you must have them all in a single
    // file. This is easy to accomplish with yarac(1).
    result = yr_rules_load(rule.c_str(), &tmp_rules);
    if (result != ERROR_SUCCESS && result != ERROR_INVALID_FILE) {
      yr_compiler_destroy(compiler);
      return Status(1, "Error loading YARA rules: " + std::to_string(result));
    } else if (result == ERROR_SUCCESS) {
      // If there are already rules there, destroy them and put new ones in.
      if (rules->count(category) > 0) {
        yr_rules_destroy((*rules)[category]);
      }
      (*rules)[category] = tmp_rules;
    } else {
      compiled = true;
      // Try to compile the rules.
      FILE* rule_file = fopen(rule.c_str(), "r");

      if (rule_file == nullptr) {
        yr_compiler_destroy(compiler);
        return Status(1, "Could not open file: " + rule);
      }

      int errors =
          yr_compiler_add_file(compiler, rule_file, NULL, rule.c_str());

      fclose(rule_file);
      rule_file = nullptr;

      if (errors > 0) {
        yr_compiler_destroy(compiler);
        // Errors printed via callback.
        return Status(1, "Compilation errors");
      }
    }
  }

  if (compiled) {
    // All the rules for this category have been compiled, save them in the map.
    result = yr_compiler_get_rules(compiler, &((*rules)[category]));

    if (result != ERROR_SUCCESS) {
      yr_compiler_destroy(compiler);
      return Status(1, "Insufficient memory to get YARA rules");
    }
  }

  if (compiler != nullptr) {
    yr_compiler_destroy(compiler);
    compiler = nullptr;
  }

  return Status(0, "OK");
}

/**
 * This is the YARA callback. Used to store matching rules in the row which is
 * passed in as user_data.
 */
int YARACallback(int message, void* message_data, void* user_data) {
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    Row* r = (Row*)user_data;
    YR_RULE* rule = (YR_RULE*)message_data;
    if ((*r)["matches"].length() > 0) {
      (*r)["matches"] += "," + std::string(rule->identifier);
    } else {
      (*r)["matches"] = std::string(rule->identifier);
    }
    (*r)["count"] = INTEGER(std::stoi((*r)["count"]) + 1);
  }

  return CALLBACK_CONTINUE;
}

/**
 * @brief A simple ConfigParserPlugin for a "yara" dictionary key.
 *
 * A straight forward ConfigParserPlugin that requests a single "yara" key.
 * This stores a rather trivial "yara" data key. The accessor will be
 * redundant since this is so simple:
 *
 * Pseudo-code:
 *   getParser("yara")->getKey("yara");
 */
class YARAConfigParserPlugin : public ConfigParserPlugin {
 public:
  /// Request a single "yara" top level key.
  std::vector<std::string> keys() { return {"yara"}; }

  /// Store the "yara" key rather simply.
  Status update(const std::map<std::string, ConfigTree>& config) {
    data_.add_child("yara", config.at("yara"));
    return Status(0, "OK");
  }
};

/// Call the simple YARA ConfigParserPlugin "yara".
REGISTER(YARAConfigParserPlugin, "config_parser", "yara");

/**
 * @brief Track YARA matches to files.
 */
class YARAEventSubscriber : public FileEventSubscriber {
 public:
  Status init();

 private:
  std::map<std::string, YR_RULES*> rules;

  /**
   * @brief This exports a single Callback for FSEventsEventPublisher events.
   *
   * @param ec The Callback type receives an EventContextRef substruct
   * for the FSEventsEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Status
   */
  Status Callback(const FileEventContextRef& ec, const void* user_data);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 * called.
 *
 * This registers YARAEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(YARAEventSubscriber, "event_subscriber", "yara_matches");

Status YARAEventSubscriber::init() {
  Status status;

  int result = yr_initialize();
  if (result != ERROR_SUCCESS) {
    LOG(WARNING) << "Unable to initialize YARA (" << result << ")";
    return Status(1, "Unable to initialize YARA");
  }

  ConfigDataInstance config;
  const auto& yara_config = config.getParsedData("yara");
  const auto& file_map = config.files();

  // yara_config has a key of the category and a vector of rule files to load.
  // file_map has a key of the category and a vector of files to watch. Use
  // yara_config to get the category and subscribe to each file in file_map
  // with that category. Then load each YARA rule file from yara_config.
  for (const auto& element : yara_config.get_child("yara")) {
    // Subscribe to each file for the given key (category).
    if (file_map.count(element.first) == 0) {
      continue;
    }

    for (const auto& file : file_map.at(element.first)) {
      VLOG(1) << "Added YARA listener to: " << file;
      auto mc = createSubscriptionContext();
      mc->path = file;
      mc->mask = FILE_CHANGE_MASK;
      mc->recursive = true;
      subscribe(&YARAEventSubscriber::Callback, mc, (void*)(&element.first));
    }

    // Attempt to compile the rules for this category.
    status = handleRuleFiles(element.first, element.second, &rules);
    if (!status.ok()) {
      VLOG(1) << "YARA rule compile error: " << status.getMessage();
      return status;
    }
  }
  return Status(0, "OK");
}

Status YARAEventSubscriber::Callback(const FileEventContextRef& ec,
                                     const void* user_data) {
  if (user_data == nullptr) {
    return Status(1, "No YARA category string provided");
  }

  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  r["category"] = *(std::string*)user_data;

  // Only FSEvents transactions updates (inotify is a no-op).
  r["transaction_id"] = INTEGER(ec->transaction_id);

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");

  int result = yr_rules_scan_file(rules[r.at("category")],
                                  ec->path.c_str(),
                                  SCAN_FLAGS_FAST_MODE,
                                  YARACallback,
                                  (void*)&r,
                                  0);

  if (result != ERROR_SUCCESS) {
    return Status(1, "YARA error: " + std::to_string(result));
  }

  if (ec->action != "") {
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
