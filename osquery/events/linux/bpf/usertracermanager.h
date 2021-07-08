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
#include <osquery/events/linux/bpf/usertracersconfigplugin.h>

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
  struct TracerInstance final {
    TracerConfiguration config;
    osquery::UserTracer::Ptr tracer;
  };

  using TracerInstanceList = std::vector<TracerInstance>;

  static TracerConfigurationList loadConfiguration();

  static void applyConfiguration(TracerInstanceList& tracer_state_list,
                                 const TracerConfigurationList& new_config);

  using ParameterListIndex =
      std::unordered_map<std::string,
                         const tob::ebpfpub::IFunctionTracer::Parameter&>;

  static ParameterListIndex createParameterListIndex(
      const tob::ebpfpub::IFunctionTracer::ParameterList& parameter_list);

  static bool areConfigsEqual(const TracerConfiguration& lhs,
                              const TracerConfiguration& rhs);
};

} // namespace osquery
