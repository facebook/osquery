/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <thread>

#include <osquery/core/flags.h>
#include <osquery/events/linux/bpf/setrlimit.h>
#include <osquery/events/linux/bpf/usertracer.h>
#include <osquery/events/linux/bpf/usertracermanager.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/time.h>

#include <boost/algorithm/string.hpp>

namespace osquery {

namespace {

FLAG(bool, enable_bpf_user_tracers, false, "Enables the BPF user tracers");

FLAG(string, bpf_user_tracer_list, "", "A list of user tracers to load");
} // namespace

REGISTER(UserTracerManager, "event_publisher", "UserTracerManager");

struct UserTracerManager::PrivateData final {
  TracerStateList tracer_state_list;
};

Status UserTracerManager::setUp() {
  // Always return success here, even when the publisher is disabled. If
  // we don't, the publisher will get locked into the ENDING state with no
  // chance of correctly handling new configuration changes

  if (!FLAGS_enable_bpf_user_tracers) {
    LOG(INFO) << "Publisher UserTracerManager is disabled by configuration";
  }

  return Status::success();
}

void UserTracerManager::configure() {
  Configuration new_config;
  if (FLAGS_enable_bpf_user_tracers) {
    new_config = loadConfiguration();
  }

  applyConfiguration(d->tracer_state_list, new_config);
}

void UserTracerManager::tearDown() {}

Status UserTracerManager::run() {
  while (!isEnding()) {
    if (!FLAGS_enable_bpf_user_tracers || d->tracer_state_list.empty()) {
      // If we are not supposed to be running, sleep. This prevents
      // the EventFactory class from recording each return as a restart.
      //
      // Remember that we are trying to keep the publisher working across
      // configuration changes (see UserTracerManager::setUp for more info)

      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      continue;
    }

    for (const auto& tracer_state : d->tracer_state_list) {
      tracer_state.tracer->processEvents();
    }
  }

  return Status::success();
}

UserTracerManager::UserTracerManager() : d(new PrivateData) {}

UserTracerManager::~UserTracerManager() {
  tearDown();
}

UserTracerManager::Configuration UserTracerManager::loadConfiguration() {
  Configuration config;

  std::vector<std::string> path_list;
  boost::split(path_list, FLAGS_bpf_user_tracer_list, boost::is_any_of(","));

  for (const auto& path : path_list) {
    std::string tracer_config = {};

    auto status = readFile(path, tracer_config, 0);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to load the user tracer configuration: " << path;
      continue;
    }

    config.insert({path, std::move(tracer_config)});
  }

  return config;
}

void UserTracerManager::applyConfiguration(TracerStateList& tracer_state_list,
                                           const Configuration& new_config) {
  // Remove all the tracers that are either outdated or no longer present
  // in the configuration
  for (auto it = tracer_state_list.begin(); it != tracer_state_list.end();) {
    const auto& tracer_state = *it;

    bool remove{false};
    auto config_it = new_config.find(tracer_state.config_path);
    if (config_it == new_config.end()) {
      remove = true;

    } else {
      const auto& config = config_it->second;
      remove = tracer_state.config_contents != config;
    }

    if (!remove) {
      ++it;
      continue;
    }

    auto table_name = tracer_state.tracer->name();
    it = tracer_state_list.erase(it);
  }

  // Create the tracers that are not already running
  auto registry = RegistryFactory::get().registry("table");

  for (const auto& config_p : new_config) {
    const auto& config_path = config_p.first;
    const auto& config_contents = config_p.second;

    auto tracer_state_it =
        std::find_if(tracer_state_list.begin(),
                     tracer_state_list.end(),

                     [&config_path](const TracerState& tracer_state) -> bool {
                       return (tracer_state.config_path == config_path);
                     });

    if (tracer_state_it != tracer_state_list.end()) {
      continue;
    }

    TracerState tracer_state;
    tracer_state.config_path = config_path;
    tracer_state.config_contents = config_contents;

    auto tracer_exp = UserTracer::create(tracer_state.config_contents);
    if (tracer_exp.isError()) {
      LOG(ERROR) << "Failed to create the user tracer: "
                 << tracer_exp.getError().getMessage();
      continue;
    }

    tracer_state.tracer = tracer_exp.get();
    auto registry = RegistryFactory::get().registry("table");
    registry->add(tracer_state.tracer->name(), tracer_state.tracer, false);

    LOG(INFO) << "Loaded a new user tracer '" << tracer_state.tracer->name()
              << "' from '" << tracer_state.config_path << "'";

    tracer_state_list.push_back(std::move(tracer_state));
  }
}

} // namespace osquery
