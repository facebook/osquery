/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <ctime>

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/io/detail/quoted_manip.hpp>

#include <osquery/carver/carver.h>
#include <osquery/config/config.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/query.h>
#include <osquery/core/shutdown.h>
#include <osquery/database/database.h>
#include <osquery/events/eventfactory.h>
#include <osquery/logger/data_logger.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/process/process.h>
#include <osquery/profiler/code_profiler.h>

#include <osquery/utils/system/time.h>

#include "osquery/dispatcher/scheduler.h"
#include "osquery/sql/sqlite_util.h"
#include "plugins/config/parsers/decorators.h"

namespace osquery {

FLAG(uint64,
     schedule_timeout,
     0,
     "Limit the schedule to a duration in seconds, 0 for no limit");

FLAG(uint64, schedule_max_drift, 60, "Max time drift in seconds");

FLAG(uint64,
     schedule_reload,
     3600,
     "Interval in seconds to reload database arenas");

FLAG(uint64, schedule_epoch, 0, "Epoch for scheduled queries");

FLAG(bool,
     schedule_lognames,
     false,
     "Log the running scheduled query name at INFO level");

HIDDEN_FLAG(bool,
            events_enforce_denylist,
            false,
            "Enforce denylist for event-based queries");

HIDDEN_FLAG(bool,
            schedule_reload_sql,
            false,
            "Reload the SQL implementation during schedule reload");

/// Used to bypass (optimize-out) the set-differential of query results.
DECLARE_bool(events_optimize);
DECLARE_bool(enable_numeric_monitoring);
DECLARE_bool(verbose);

SQLInternal monitor(const std::string& name, const ScheduledQuery& query) {
  if (FLAGS_enable_numeric_monitoring) {
    CodeProfiler profiler(
        {(boost::format("scheduler.pack.%s") % query.pack_name).str(),
         (boost::format("scheduler.global.query.%s.%s") % query.pack_name %
          query.name)
             .str(),
         (boost::format("scheduler.assigned.query.%s.%s.%s") % query.oncall %
          query.pack_name % query.name)
             .str(),
         (boost::format("scheduler.owners.%s") % query.oncall).str(),
         (boost::format("scheduler.query.%s.%s.%s") %
          monitoring::hostIdentifierKeys().scheme % query.pack_name %
          query.name)
             .str()});
    return SQLInternal(query.query, true);
  } else {
    // Snapshot the performance and times for the worker before running.
    auto pid = std::to_string(PlatformProcess::getCurrentPid());
    auto r0 = SQL::selectFrom({"resident_size", "user_time", "system_time"},
                              "processes",
                              "pid",
                              EQUALS,
                              pid);
    auto t0 = getUnixTime();
    Config::get().recordQueryStart(name);
    SQLInternal sql(query.query, true);
    // Snapshot the performance after, and compare.
    auto t1 = getUnixTime();
    auto r1 = SQL::selectFrom({"resident_size", "user_time", "system_time"},
                              "processes",
                              "pid",
                              EQUALS,
                              pid);
    if (r0.size() > 0 && r1.size() > 0) {
      // Always called while processes table is working.
      Config::get().recordQueryPerformance(name, t1 - t0, r0[0], r1[0]);
    }
    return sql;
  }
}

Status launchQuery(const std::string& name, const ScheduledQuery& query) {
  // Execute the scheduled query and create a named query object.
  if (FLAGS_verbose) {
    VLOG(1) << "Executing scheduled query " << name << ": " << query.query;
  } else if (FLAGS_schedule_lognames) {
    LOG(INFO) << "Executing scheduled query " << name;
  }
  runDecorators(DECORATE_ALWAYS);

  auto sql = monitor(name, query);
  if (!sql.getStatus().ok()) {
    LOG(ERROR) << "Error executing scheduled query " << name << ": "
               << sql.getStatus().toString();
    return Status::failure("Error executing scheduled query");
  }

  // Fill in a host identifier fields based on configuration or availability.
  std::string ident = getHostIdentifier();

  // A query log item contains an optional set of differential results or
  // a copy of the most-recent execution alongside some query metadata.
  QueryLogItem item;
  item.name = name;
  item.identifier = ident;
  item.time = osquery::getUnixTime();
  item.epoch = FLAGS_schedule_epoch;
  item.calendar_time = osquery::getAsciiTime();
  getDecorations(item.decorations);

  if (query.isSnapshotQuery()) {
    // This is a snapshot query, emit results with a differential or state.
    item.snapshot_results = std::move(sql.rowsTyped());
    logSnapshotQuery(item);
    return Status::success();
  }

  // Create a database-backed set of query results.
  auto dbQuery = Query(name, query);
  // Comparisons and stores must include escaped data.
  sql.escapeResults();
  Status status;
  DiffResults& diff_results = item.results;
  // Add this execution's set of results to the database-tracked named query.
  // We can then ask for a differential from the last time this named query
  // was executed by exact matching each row.
  if (!FLAGS_events_optimize || !sql.eventBased()) {
    status = dbQuery.addNewResults(
        std::move(sql.rowsTyped()), item.epoch, item.counter, diff_results);
  } else {
    status = dbQuery.addNewEvents(
        std::move(sql.rowsTyped()), item.epoch, item.counter, diff_results);
  }

  if (!status.ok()) {
    std::string message = "Error adding new results to database for query " +
                          name + ": " + status.what();
    // If the database is not available then the daemon cannot continue.
    requestShutdown(EXIT_CATASTROPHIC, message);
  }

  if (!query.reportRemovedRows()) {
    diff_results.removed.clear();
  }

  if (diff_results.hasNoResults()) {
    // No diff results or events to emit.
    return status;
  }

  VLOG(1) << "Found results for query: " << name;

  status = logQueryLogItem(item);
  if (!status.ok()) {
    // If log directory is not available, then the daemon shouldn't continue.
    std::string message = "Error logging the results of query: " + name + ": " +
                          status.toString();
    requestShutdown(EXIT_CATASTROPHIC, message);
  }
  return status;
}

void SchedulerRunner::calculateTimeDriftAndMaybePause(
    std::chrono::milliseconds loop_step_duration) {
  if (loop_step_duration + time_drift_ < interval_) {
    pause(interval_ - loop_step_duration - time_drift_);
    time_drift_ = std::chrono::milliseconds::zero();
  } else {
    time_drift_ += loop_step_duration - interval_;
    if (time_drift_ > max_time_drift_) {
      // giving up
      time_drift_ = std::chrono::milliseconds::zero();
    }
  }
}

void SchedulerRunner::maybeRunDecorators(uint64_t time_step) {
  // Configuration decorators run on 60 second intervals only.
  if ((time_step % 60) == 0) {
    runDecorators(DECORATE_INTERVAL, time_step);
  }
}

void SchedulerRunner::maybeScheduleCarves(uint64_t time_step) {
  if ((time_step % 60) == 0) {
    scheduleCarves();
  }
}

void SchedulerRunner::maybeReloadSchedule(uint64_t time_step) {
  if (FLAGS_schedule_reload > 0 && (time_step % FLAGS_schedule_reload) == 0) {
    if (FLAGS_schedule_reload_sql) {
      SQLiteDBManager::resetPrimary();
    }
    resetDatabase();
  }
}

void SchedulerRunner::maybeFlushLogs(uint64_t time_step) {
  // GLog is not re-entrant, so logs must be flushed in a dedicated thread.
  if ((time_step % 3) == 0) {
    relayStatusLogs(LoggerRelayMode::Async);
  }
}

bool enforceDenylist(const std::string& query) {
  // The only exception for a denylisted query to still run is when this flag
  // is false (the default).
  if (FLAGS_events_enforce_denylist) {
    return true;
  }

  auto tables = QueryPlanner(query).tables();
  if (tables.empty()) {
    return true;
  }

  // Check if the query only operates on event subscribers.
  // If it does, skip the denylist enforcement.
  std::set<std::string> table_set(tables.begin(), tables.end());
  auto event_tables = EventFactory::subscriberNames();

  std::set<std::string> overlap;
  std::set_intersection(table_set.begin(),
                        table_set.end(),
                        event_tables.begin(),
                        event_tables.end(),
                        std::inserter(overlap, overlap.begin()));
  return overlap.size() != table_set.size();
}
void SchedulerRunner::start() {
  // Start the counter at the second.
  auto i = osquery::getUnixTime();
  // Timeout is the number of seconds from starting.
  auto end = (timeout_ == 0) ? 0 : timeout_ + i;

  for (; (end == 0) || (i <= end); ++i) {
    auto start_time_point = std::chrono::steady_clock::now();
    Config::get().scheduledQueries(
        ([&i](const std::string& name, const ScheduledQuery& query) {
          if (query.splayed_interval > 0 && i % query.splayed_interval == 0) {
            if (query.denylisted && enforceDenylist(query.query)) {
              return;
            }

            TablePlugin::kCacheInterval = query.splayed_interval;
            TablePlugin::kCacheStep = i;
            const auto status = launchQuery(name, query);
            monitoring::record(
                (boost::format("scheduler.query.%s.%s.status.%s") %
                 query.pack_name % query.name %
                 (status.ok() ? "success" : "failure"))
                    .str(),
                1,
                monitoring::PreAggregationType::Sum,
                true);
          }
        }),
        true);

    maybeRunDecorators(i);
    maybeReloadSchedule(i);
    maybeFlushLogs(i);
    maybeScheduleCarves(i);

    auto loop_step_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time_point);
    calculateTimeDriftAndMaybePause(loop_step_duration);
    if (interrupted()) {
      break;
    }
  }

  // Scheduler ended.
  if (!interrupted() && request_shutdown_on_expiration) {
    LOG(INFO) << "The scheduler ended after " << timeout_ << " seconds";
    requestShutdown();
  }
}

std::chrono::milliseconds SchedulerRunner::getCurrentTimeDrift() const
    noexcept {
  return time_drift_;
}

void startScheduler() {
  startScheduler(static_cast<unsigned long int>(FLAGS_schedule_timeout), 1);
}

void startScheduler(unsigned long int timeout, size_t interval) {
  Dispatcher::addService(std::make_shared<SchedulerRunner>(
      timeout, interval, std::chrono::seconds{FLAGS_schedule_max_drift}));
}
} // namespace osquery
