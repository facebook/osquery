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

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/events/linux/bpf/setrlimit.h>
#include <osquery/events/linux/bpf/usertracer.h>
#include <osquery/events/linux/bpf/usertracermanager.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/mutex.h>
#include <osquery/utils/system/time.h>

#include <boost/algorithm/string.hpp>

namespace osquery {

namespace {

FLAG(bool, enable_bpf_user_tracers, false, "Enables the BPF user tracers");

} // namespace

REGISTER(UserTracerManager, "event_publisher", "UserTracerManager");

struct UserTracerManager::PrivateData final {
  Mutex tracer_instance_list_mutex;
  TracerInstanceList tracer_instance_list;
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
  WriteLock lock(d->tracer_instance_list_mutex);

  TracerConfigurationList new_config;
  if (FLAGS_enable_bpf_user_tracers) {
    new_config = loadConfiguration();
  }

  applyConfiguration(d->tracer_instance_list, new_config);
}

void UserTracerManager::tearDown() {}

Status UserTracerManager::run() {
  while (!isEnding()) {
    if (!FLAGS_enable_bpf_user_tracers || d->tracer_instance_list.empty()) {
      // If we are not supposed to be running, sleep. This prevents
      // the EventFactory class from recording each return as a restart.
      //
      // Remember that we are trying to keep the publisher working across
      // configuration changes (see UserTracerManager::setUp for more info)

      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      continue;
    }

    TracerInstanceList tracer_instance_list;

    {
      WriteLock lock(d->tracer_instance_list_mutex);
      tracer_instance_list = d->tracer_instance_list;
    }

    for (const auto& tracer_instance : tracer_instance_list) {
      tracer_instance.tracer->processEvents();
    }
  }

  return Status::success();
}

UserTracerManager::UserTracerManager() : d(new PrivateData) {}

UserTracerManager::~UserTracerManager() {
  tearDown();
}

TracerConfigurationList UserTracerManager::loadConfiguration() {
  auto config_plugin_ptr = Config::getParser("user_tracers");
  if (config_plugin_ptr == nullptr) {
    LOG(ERROR) << "The internal 'user_tracers' config plugin was not found!";
    return {};
  }

  const auto& config_plugin =
      *static_cast<const UserTracersConfigPlugin*>(config_plugin_ptr.get());

  return config_plugin.getConfigList();
}

void UserTracerManager::applyConfiguration(
    TracerInstanceList& tracer_instance_list,
    const TracerConfigurationList& new_config) {
  // Remove all the tracers that are either outdated or no longer present
  // in the configuration
  auto registry = RegistryFactory::get().registry("table");

  for (auto it = tracer_instance_list.begin();
       it != tracer_instance_list.end();) {
    const auto& tracer_instance = *it;

    auto config_it = std::find_if(
        new_config.begin(),
        new_config.end(),

        [&tracer_instance](const TracerConfiguration& config) -> bool {
          return areConfigsEqual(tracer_instance.config, config);
        });

    if (config_it == new_config.end()) {
      LOG(INFO) << "Removing the following user tracer: "
                << tracer_instance.tracer->name();

      Registry::call(
          "sql",
          "sql",
          {{"action", "detach"}, {"table", tracer_instance.tracer->name()}});
      registry->remove(tracer_instance.tracer->name());

      it = tracer_instance_list.erase(it);

    } else {
      ++it;
    }
  }

  // Create the tracers that are not already running
  for (const auto& config : new_config) {
    auto tracer_inst_it =
        std::find_if(tracer_instance_list.begin(),
                     tracer_instance_list.end(),

                     [&config](const TracerInstance& tracer_inst) -> bool {
                       return areConfigsEqual(config, tracer_inst.config);
                     });

    if (tracer_inst_it != tracer_instance_list.end()) {
      continue;
    }

    auto tracer_exp = UserTracer::create(config);
    if (tracer_exp.isError()) {
      LOG(ERROR) << "Failed to create the user tracer: "
                 << tracer_exp.getError().getMessage();

      continue;
    }

    TracerInstance tracer_instance;
    tracer_instance.config = config;
    tracer_instance.tracer = tracer_exp.take();

    registry->add(tracer_instance.tracer->name(), tracer_instance.tracer);
    Registry::call(
        "sql",
        "sql",
        {{"action", "attach"}, {"table", tracer_instance.tracer->name()}});

    LOG(INFO) << "A new user tracer was loaded: "
              << tracer_instance.tracer->name();

    tracer_instance_list.push_back(std::move(tracer_instance));
  }
}

UserTracerManager::ParameterListIndex
UserTracerManager::createParameterListIndex(
    const tob::ebpfpub::IFunctionTracer::ParameterList& parameter_list) {
  ParameterListIndex index;

  for (const auto& param : parameter_list) {
    index.insert({param.name, param});
  }

  return index;
}

bool UserTracerManager::areConfigsEqual(const TracerConfiguration& lhs,
                                        const TracerConfiguration& rhs) {
  if (lhs.table_name != rhs.table_name) {
    return false;
  }

  if (lhs.opt_image_path.has_value() != rhs.opt_image_path.has_value()) {
    return false;
  }

  if (lhs.opt_image_path.has_value()) {
    if (lhs.opt_image_path.value() != rhs.opt_image_path.value()) {
      return false;
    }
  }

  if (lhs.function_name != rhs.function_name) {
    return false;
  }

  if (lhs.parameter_list.size() != rhs.parameter_list.size()) {
    return false;
  }

  auto rhs_param_index = createParameterListIndex(rhs.parameter_list);

  for (const auto& lhs_param : lhs.parameter_list) {
    auto rhs_param_it = rhs_param_index.find(lhs_param.name);
    if (rhs_param_it == rhs_param_index.end()) {
      return false;
    }

    const auto& rhs_param = rhs_param_it->second;
    if (lhs_param.mode != rhs_param.mode) {
      return false;
    }

    if (lhs_param.type != rhs_param.type) {
      return false;
    }

    if (lhs_param.opt_size_var.has_value() !=
        rhs_param.opt_size_var.has_value()) {
      return false;
    }

    if (lhs_param.opt_size_var.has_value() &&
        (lhs_param.opt_size_var.value() != rhs_param.opt_size_var.value())) {
      return false;
    }
  }

  return true;
}

} // namespace osquery
