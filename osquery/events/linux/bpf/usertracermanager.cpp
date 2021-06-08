/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

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
  std::vector<osquery::UserTracer::Ptr> user_tracer_list;
};

Status UserTracerManager::setUp() {
  if (!FLAGS_enable_bpf_user_tracers) {
    return Status::failure("Publisher disabled via configuration");
  }

  std::vector<std::string> path_list;
  boost::split(path_list, FLAGS_bpf_user_tracer_list, boost::is_any_of(","));

  for (const auto& path : path_list) {
    std::string tracer_config = {};

    auto status = readFile(path, tracer_config, 0);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to load the user tracer configuration: " << path;
      continue;
    }

    auto tracer_exp = UserTracer::create(tracer_config);
    if (tracer_exp.isError()) {
      LOG(ERROR) << "Failed to create the user tracer: "
                 << tracer_exp.getError().getMessage();
      continue;

    } else {
      auto tracer = tracer_exp.get();

      auto registry = RegistryFactory::get().registry("table");
      registry->add(tracer->name(), tracer, false);
      d->user_tracer_list.push_back(tracer);

      LOG(INFO) << "Loaded a new user tracer '" << tracer->name() << "' from '"
                << path << "'";
    }
  }

  return Status::success();
}

void UserTracerManager::configure() {
  if (!FLAGS_enable_bpf_user_tracers) {
    return;
  }
}

void UserTracerManager::tearDown() {
  if (!FLAGS_enable_bpf_user_tracers) {
    return;
  }
}

Status UserTracerManager::run() {
  if (!FLAGS_enable_bpf_user_tracers) {
    return Status::failure("Publisher disabled via configuration");
  }

  while (!isEnding()) {
    for (const auto& tracer : d->user_tracer_list) {
      tracer->processEvents();
    }
  }

  return Status::success();
}

UserTracerManager::UserTracerManager() : d(new PrivateData) {}

UserTracerManager::~UserTracerManager() {
  tearDown();
}
} // namespace osquery
