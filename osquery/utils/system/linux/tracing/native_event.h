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

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/tracing/types.h>

#include <string>

namespace osquery {
namespace tracing {

/**
 * Wrapper for the native linux system events, see
 * "/sys/kernel/debug/tracing/events/"
 */
class NativeEvent final {
 public:
  ~NativeEvent();

  NativeEvent(NativeEvent&& other);
  NativeEvent& operator=(NativeEvent&& other);

  NativeEvent(NativeEvent const&) = delete;
  NativeEvent& operator=(NativeEvent const&) = delete;

  enum class Error {
    Unknown = 1,
    System = 2,
  };

  /**
   * Enable event type with path @event_path and receive the id
   */
  static Expected<NativeEvent, NativeEvent::Error> load(std::string event_path);

  SystemEventId id() const;

 private:
  explicit NativeEvent(std::string event_path);

  bool isEnabled() const;
  ExpectedSuccess<Error> enable(bool do_enable);

 private:
  SystemEventId id_ = -1;
  std::string event_path_;
};

} // namespace tracing
} // namespace osquery
