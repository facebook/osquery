/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <map>
#include <memory>
#include <vector>

#include <osquery/core.h>
#include <osquery/query.h>
#include <osquery/registry.h>
#include <osquery/status.h>

#include "osquery/core/json.h"

namespace osquery {

class Config;
class Pack;
class Schedule;
class ConfigParserPlugin;
class ConfigRefreshRunner;

/// The name of the executing query within the single-threaded schedule.
extern const std::string kExecutingQuery;

/**
 * @brief The programmatic representation of osquery's configuration
 *
 * @code{.cpp}
 *   auto c = Config::get();
 *   // use methods in osquery::Config on `c`
 * @endcode
 */
class Config : private boost::noncopyable {
 private:
  Config();

 public:
  /// Singleton accessor.
  static Config& get();

  /**
   * @brief Update the internal config data.
   *
   * @param config A map of domain or namespace to config data.
   * @return If the config changes were applied.
   */
  Status update(const std::map<std::string, std::string>& config);

  /**
   * @brief Record performance (monitoring) information about a scheduled query.
   *
   * The daemon and query scheduler will optionally record process metadata
   * before and after executing each query. This can be compared and reported
   * on an interval or within the osquery_schedule table.
   *
   * The config consumes and calculates the optional performance differentials.
   * It would also be possible to store this in the RocksDB backing store or
   * report directly to a LoggerPlugin sink. The Config is the most appropriate
   * as the metrics are transient to the process running the schedule and apply
   * to the updates/changes reflected in the schedule, from the config.
   *
   * @param name The unique name of the scheduled item
   * @param delay Number of seconds (wall time) taken by the query
   * @param size Number of characters generated by query
   * @param r0 the process row before the query
   * @param r1 the process row after the query
   */
  void recordQueryPerformance(const std::string& name,
                              size_t delay,
                              size_t size,
                              const Row& r0,
                              const Row& r1);

  /**
   * @brief Record a query 'initialization', meaning the query will run.
   *
   * Recording initializations if queries helps to identify when queries do not
   * complete. The Config::recordQueryPerformance method will clear a dirty
   * status set by this method. This status is saved in the backing database
   * store. On process start, or worker state, if any dirty bit is set then
   * it is assumed that the current start is a result of a previous abort.
   *
   * @param name THe unique name of the scheduled item
   */
  void recordQueryStart(const std::string& name);

  /**
   * @brief Calculate the hash of the osquery config
   *
   * @return The SHA1 hash of the osquery config
   */
  Status genHash(std::string& hash) const;

  /// Retrieve the hash of a named source.
  std::string getHash(const std::string& source) const;

  /**
   * @brief Hash a source's config data
   *
   * @param source is the place where the config content came from
   * @param content is the content of the config data for a given source
   * @return false if the source did not change, otherwise true
   */
  bool hashSource(const std::string& source, const std::string& content);

  /// Whether or not the last loaded config was valid.
  bool isValid() const {
    return valid_;
  }

  /// Get start time of config.
  static size_t getStartTime();

  /// Set the start time if the config.
  static void setStartTime(size_t st);

  /**
   * @brief Add a pack to the osquery schedule
   */
  void addPack(const std::string& name,
               const std::string& source,
               const rapidjson::Value& obj);

  /**
   * @brief Remove a pack from the osquery schedule
   */
  void removePack(const std::string& pack);

  /**
   * @brief Iterate through all packs
   */
  void packs(std::function<void(std::shared_ptr<Pack>& pack)> predicate);

  /**
   * @brief Add a file
   *
   * @param source source of config file
   * @param category is the category which the file exists in
   * @param path is the file path to add
   */
  void addFile(const std::string& source,
               const std::string& category,
               const std::string& path);

  /// Remove files by source.
  void removeFiles(const std::string& source);

  /**
   * @brief Map a function across the set of scheduled queries
   *
   * @param predicate is a function which accepts two parameters, the name of
   * the query and the ScheduledQuery struct of the queries data. predicate
   * will be called on each currently scheduled query.
   *
   * @param blacklisted [optional] return blacklisted queries if true.
   *
   * @code{.cpp}
   *   std::map<std::string, ScheduledQuery> queries;
   *   Config::get().scheduledQueries(
   *      ([&queries](std::string name, const ScheduledQuery& query) {
   *        queries[name] = query;
   *      }));
   * @endcode
   */
  void scheduledQueries(
      std::function<void(std::string name, const ScheduledQuery& query)>
          predicate,
      bool blacklisted = false) const;

  /**
   * @brief Map a function across the set of configured files
   *
   * @param predicate is a function which accepts two parameters, the name of
   * the file category and a vector of files in that category. predicate will be
   * called on each pair in files_
   *
   * @code{.cpp}
   *   std::map<std::string, std::vector<std::string>> file_map;
   *   Config::get().files(
   *      ([&file_map](const std::string& category,
   *                   const std::vector<std::string>& files) {
   *        file_map[category] = files;
   *      }));
   * @endcode
   */
  void files(std::function<void(const std::string& category,
                                const std::vector<std::string>& files)>
                 predicate) const;

  /**
   * @brief Get the performance stats for a specific query, by name
   *
   * @param name is the name of the query which you'd like to retrieve
   * @param predicate is a function which accepts a const reference to a
   * QueryPerformance struct. predicate will be called on name's related
   * QueryPerformance struct, if it exists.
   *
   * @code{.cpp}
   *   Config::get().getPerformanceStats(
   *     "my_awesome_query",
   *     [](const QueryPerformance& query) {
   *       // use "query" here
   *     });
   * @endcode
   */
  void getPerformanceStats(
      const std::string& name,
      std::function<void(const QueryPerformance& query)> predicate) const;

  /**
   * @brief Helper to access config parsers via the registry
   *
   * This may return a nullptr if an exception is thrown attempting to retrieve
   * the requested config parser.
   *
   * @param parser is the string name of the parser that you want
   *
   * @return a shared pointer to the config parser plugin
   */
  static const std::shared_ptr<ConfigParserPlugin> getParser(
      const std::string& parser);

 protected:
  /**
   * @brief Call the genConfig method of the config retriever plugin.
   *
   * This may perform a resource load such as TCP request or filesystem read.
   * If a non-zero value is passed to --config_refresh, this starts a thread
   * that periodically calls genConfig to reload config state
   */
  Status refresh();

  /// Update the refresh rate.
  void setRefresh(size_t refresh, size_t mod = 0);

  /// Inspect the refresh rate.
  size_t getRefresh() const;

  /**
   * @brief Check if a config plugin is registered and load configs.
   *
   * Calls refresh after confirming a config plugin is registered
   */
  Status load();

  /// A step method for Config::update.
  Status updateSource(const std::string& source, const std::string& json);

  /**
   * @brief Generate pack content from a resource handled by the Plugin.
   *
   * Configuration content may set pack values to JSON strings instead of an
   * embedded dictionary representing the pack content. When a string is
   * encountered the config assumes this is a 'resource' handled by the Plugin.
   *
   * The value, or target, is sent to the ConfigPlugin via a registry request.
   * The plugin response is assumed, and used, as the pack content.
   *
   * @param name A pack name provided and handled by the ConfigPlugin.
   * @param source The config content source identifier.
   * @param target A resource (path, URL, etc) handled by the ConfigPlugin.
   * @return status On success the response will be JSON parsed.
   */
  Status genPack(const std::string& name,
                 const std::string& source,
                 const std::string& target);

  /**
   * @brief Apply each ConfigParser to an input JSON document.
   *
   * This iterates each discovered ConfigParser Plugin and the plugin's keys
   * to match keys within the input JSON document. If a key matches then the
   * associated value is passed to the parser.
   *
   * Use this utility method for both the top-level configuration JSON and
   * the content of each configuration pack. There is an optional black list
   * parameter to differentiate pack content.
   *
   * @param source The input configuration source name.
   * @param obj The input configuration JSON.
   * @param pack True if the JSON was built from pack data, otherwise false.
   */
  void applyParsers(const std::string& source,
                    const rapidjson::Value& obj,
                    bool pack = false);

  /**
   * @brief When config sources are updated the config will 'purge'.
   *
   * The general 'purge' action applies to searching for outdated query results,
   * timestamps, saved intervals, etc. This event only occurs before a source
   * is updated. Since updating the configuration may have expected side effects
   * such as changing watched files or overwriting (modifying) pack content,
   * this 'purge' action is assumed to be destructive and potentially expensive.
   */
  void purge();

  /**
   * @brief Reset the configuration state, reserved for testing only.
   */
  void reset();

 protected:
  /// Schedule of packs and their queries.
  std::shared_ptr<Schedule> schedule_;

  /// A set of performance stats for each query in the schedule.
  std::map<std::string, QueryPerformance> performance_;

  /// A set of named categories filled with filesystem globbing paths.
  using FileCategories = std::map<std::string, std::vector<std::string>>;
  std::map<std::string, FileCategories> files_;

  /// A set of hashes for each source of the config.
  std::map<std::string, std::string> hash_;

  /// Check if the config received valid/parsable content from a config plugin.
  bool valid_{false};

  /**
   * @brief Check if the configuration has attempted a load.
   *
   * Check if the config is updating sources in response to an async update
   * or the initialization load step.
   */
  bool loaded_{false};

  /// Try if the configuration has started an auto-refresh thread.
  bool started_thread_{false};

 private:
  /// Hold a reference to the refresh runner to update the acceleration.
  std::shared_ptr<ConfigRefreshRunner> refresh_runner_{nullptr};

 private:
  friend class Initializer;

 private:
  friend class ConfigTests;
  friend class ConfigRefreshRunner;
  friend class FilePathsConfigParserPluginTests;
  friend class FileEventsTableTests;
  friend class DecoratorsConfigParserPluginTests;
  friend class SchedulerTests;
  FRIEND_TEST(ConfigTests, test_config_refresh);
  FRIEND_TEST(ConfigTests, test_get_scheduled_queries);
  FRIEND_TEST(ConfigTests, test_nonblacklist_query);
  FRIEND_TEST(OptionsConfigParserPluginTests, test_get_option);
  FRIEND_TEST(ViewsConfigParserPluginTests, test_add_view);
  FRIEND_TEST(ViewsConfigParserPluginTests, test_swap_view);
  FRIEND_TEST(ViewsConfigParserPluginTests, test_update_view);
  FRIEND_TEST(OptionsConfigParserPluginTests, test_unknown_option);
  FRIEND_TEST(EventsConfigParserPluginTests, test_get_event);
  FRIEND_TEST(PacksTests, test_discovery_cache);
  FRIEND_TEST(PacksTests, test_multi_pack);
  FRIEND_TEST(SchedulerTests, test_monitor);
  FRIEND_TEST(SchedulerTests, test_config_results_purge);
  FRIEND_TEST(EventsTests, test_event_subscriber_configure);
  FRIEND_TEST(TLSConfigTests, test_retrieve_config);
  FRIEND_TEST(TLSConfigTests, test_runner_and_scheduler);
};

/**
 * @brief Superclass for the pluggable config component.
 *
 * In order to make the distribution of configurations to hosts running
 * osquery, we take advantage of a plugin interface which allows you to
 * integrate osquery with your internal configuration distribution mechanisms.
 * You may use ZooKeeper, files on disk, a custom solution, etc. In order to
 * use your specific configuration distribution system, one simply needs to
 * create a custom subclass of ConfigPlugin. That subclass should implement
 * the ConfigPlugin::genConfig method.
 *
 * Consider the following example:
 *
 * @code{.cpp}
 *   class TestConfigPlugin : public ConfigPlugin {
 *    public:
 *     virtual Status genConfig(std::map<std::string, std::string>& config) {
 *       config["my_source"] = "{}";
 *       return Status(0, "OK");
 *     }
 *   };
 *
 *   REGISTER(TestConfigPlugin, "config", "test");
 *  @endcode
 */
class ConfigPlugin : public Plugin {
 public:
  /**
   * @brief Virtual method which should implemented custom config retrieval
   *
   * ConfigPlugin::genConfig should be implemented by a subclasses of
   * ConfigPlugin which needs to retrieve config data in a custom way.
   *
   * @param config The output ConfigSourceMap, a map of JSON to source names.
   *
   * @return A failure status will prevent the source map from merging.
   */
  virtual Status genConfig(std::map<std::string, std::string>& config) = 0;

  /**
   * @brief Virtual method which could implement custom query pack retrieval
   *
   * The default config syntax for query packs is like the following:
   *
   * @code
   *   {
   *     "packs": {
   *       "foo": {
   *         "version": "1.5.0",
   *         "platform:" "any",
   *         "queries": {
   *           // ...
   *         }
   *       }
   *     }
   *   }
   * @endcode
   *
   * Alternatively, you can define packs like the following as well:
   *
   * @code
   *   {
   *     "packs": {
   *       "foo": "/var/osquery/packs/foo.json",
   *       "bar": "/var/osquery/packs/bar.json"
   *     }
   *   }
   * @endcode
   *
   * If you defined the "value" of your pack as a string instead of an inline
   * data structure, then osquery will pass the responsibility of retrieving
   * the pack to the active config plugin. In the above example, it seems
   * obvious that the value is a local file path. Alternatively, if the
   * filesystem config plugin wasn't being used, the string could be a remote
   * URL, etc.
   *
   * genPack is not a pure virtual, so you don't have to define it if you don't
   * want to use the shortened query pack syntax. The default implementation
   * returns a failed status.
   *
   * @param name is the name of the query pack
   * @param value is the string based value that was provided with the pack
   * @param pack should be populated with the string JSON pack content
   *
   * @return a Status instance indicating the success or failure of the call
   */
  virtual Status genPack(const std::string& name,
                         const std::string& value,
                         std::string& pack);

  /// Main entrypoint for config plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

/**
 * @brief A pluggable configuration parser.
 *
 * An osquery config instance is populated from JSON using a ConfigPlugin.
 * That plugin may update the config data asynchronously and read from
 * several sources, as is the case with "filesystem" and reading multiple files.
 *
 * A ConfigParserPlugin will receive the merged configuration at osquery start
 * and the updated (still merged) config if any ConfigPlugin updates the
 * instance asynchronously. Each parser specifies a set of top-level JSON
 * keys to receive. The config instance will auto-merge the key values
 * from multiple sources.
 *
 * The keys must contain either dictionaries or lists.
 *
 * If a top-level key is a dictionary, each source with the top-level key
 * will have its own dictionary keys merged and replaced based on the lexical
 * order of sources. For the "filesystem" config plugin this is the lexical
 * sorting of filenames. If the top-level key is a list, each source with the
 * top-level key will have its contents appended.
 *
 * Each config parser plugin will live alongside the config instance for the
 * life of the osquery process. The parser may perform actions at config load
 * and config update "time" as well as keep its own data members and be
 * accessible through the Config class API.
 */
class ConfigParserPlugin : public Plugin {
 public:
  using ParserConfig = std::map<std::string, JSON>;

 public:
  /**
   * @brief Return a list of top-level config keys to receive in updates.
   *
   * The ConfigParserPlugin::update method will receive a map of these keys
   * with a JSON-parsed document of configuration data.
   *
   * @return A list of string top-level JSON keys.
   */
  virtual std::vector<std::string> keys() const = 0;

  /**
   * @brief Receive a merged JSON document for each top-level config key.
   *
   * Called when the Config instance is initially loaded with data from the
   * active config plugin and when it is updated via an async ConfigPlugin
   * update. Every config parser will receive a map of merged data for each key
   * they requested in keys().
   *
   * @param source source of the config data
   * @param config A JSON-parsed document map.
   * @return Failure if the parser should no longer receive updates.
   */
  virtual Status update(const std::string& source,
                        const ParserConfig& config) = 0;

  /// Allow parsers to perform some setup before the configuration is loaded.
  Status setUp() override;

  Status call(const PluginRequest& /*request*/,
              PluginResponse& /*response*/) override {
    return Status(0);
  }

  /**
   * @brief Accessor for parser-manipulated data.
   *
   * Parsers should be used generically, for places within the code base that
   * request a parser (check for its existence), should only use this
   * ConfigParserPlugin::getData accessor.
   *
   * More complex parsers that require dynamic casting are not recommended.
   */
  const JSON& getData() const {
    return data_;
  }

 protected:
  /// Allow the config to request parser state resets.
  virtual void reset();

 protected:
  /// Allow the config parser to keep some global state.
  JSON data_;

 private:
  friend class Config;
};

/**
 * @brief JSON parsers may accept comments.
 *
 * For semi-compatibility with existing configurations we will attempt to strip
 * hash and C++ style comments. It is OK for the config update to be latent
 * as it is a single event. But some configuration plugins may update running
 * configurations.
 *
 * @param json A mutable input/output string that will contain stripped JSON.
 */
void stripConfigComments(std::string& json);
} // namespace osquery
