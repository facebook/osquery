/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <chrono>

#include <osquery/dispatcher/query_profiler.h>

namespace osquery {
void launchQueryWithProfiling(const std::string& name,
                              std::function<Status()> launchQuery) {
  const auto start_time_point = std::chrono::steady_clock::now();
  const auto status = launchQuery();
  const auto monitoring_path_prefix =
      (boost::format("scheduler.executing_query.%s.%s") % name %
       (status.ok() ? "success" : "failure"))
          .str();
  const auto query_duration =
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - start_time_point);
  if (Killswitch::get().isExecutingQueryMonitorEnabled()) {
    monitoring::record(monitoring_path_prefix + ".time.real.milis",
                       query_duration.count(),
                       monitoring::PreAggregationType::Min);
  }
}
} // namespace osquery
