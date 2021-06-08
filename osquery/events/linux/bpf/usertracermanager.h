/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventpublisher.h>
#include <osquery/events/linux/bpf/isystemstatetracker.h>

#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <unordered_map>
#include <vector>

namespace osquery {

struct UserTracerSC final : public SubscriptionContext {
 private:
  friend class UserTracerManager;
};

struct UserTracerEC final : public EventContext {};

class UserTracerManager final
    : public EventPublisher<UserTracerSC, UserTracerEC> {
 public:
  UserTracerManager();
  virtual ~UserTracerManager() override;

  virtual Status setUp() override;
  virtual void configure() override;
  virtual Status run() override;
  virtual void tearDown() override;

 private:
  DECLARE_PUBLISHER("UserTracerManager");

  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  using Configuration = std::unordered_map<std::string, std::string>;

  struct TracerState final {
    std::string config_path;
    std::string config_contents;
    osquery::UserTracer::Ptr tracer;
  };

  using TracerStateList = std::vector<TracerState>;

  static Configuration loadConfiguration();

  static void applyConfiguration(TracerStateList& tracer_state_list,
                                 const Configuration& new_config);
};

} // namespace osquery
