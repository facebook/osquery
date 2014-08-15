// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/query.h"

#include <algorithm>

using osquery::Status;

namespace osquery {
namespace db {

const std::string kQueryNameNotFoundError = "query name not found in database";

/////////////////////////////////////////////////////////////////////////////
// Getters and setters
/////////////////////////////////////////////////////////////////////////////

std::string Query::getQuery() { return query_.query; }

std::string Query::getColumnFamilyName() { return query_.name; }

int Query::getInterval() { return query_.interval; }

/////////////////////////////////////////////////////////////////////////////
// Data access methods
/////////////////////////////////////////////////////////////////////////////

Status Query::getHistoricalQueryResults(HistoricalQueryResults &hQR) {
  return getHistoricalQueryResults(hQR, DBHandle::getInstance());
}

Status Query::getHistoricalQueryResults(HistoricalQueryResults &hQR,
                                        std::shared_ptr<DBHandle> db) {
  if (isQueryNameInDatabase()) {
    std::string raw;
    auto get_status = db->Get(kQueries, query_.name, raw);
    if (get_status.ok()) {
      auto deserialize_status = deserializeHistoricalQueryResultsJSON(raw, hQR);
      if (!deserialize_status.ok()) {
        return deserialize_status;
      }
    } else {
      return get_status;
    }
  } else {
    return Status(1, kQueryNameNotFoundError);
  }
  return Status(0, "OK");
}

std::vector<std::string> Query::getStoredQueryNames() {
  return getStoredQueryNames(DBHandle::getInstance());
}

std::vector<std::string>
Query::getStoredQueryNames(std::shared_ptr<DBHandle> db) {
  std::vector<std::string> results;
  db->Scan(kQueries, results);
  return results;
}

bool Query::isQueryNameInDatabase() {
  return isQueryNameInDatabase(DBHandle::getInstance());
}

bool Query::isQueryNameInDatabase(std::shared_ptr<DBHandle> db) {
  auto names = Query::getStoredQueryNames(db);
  return std::find(names.begin(), names.end(), query_.name) != names.end();
}

Status Query::getExecutions(std::deque<int> &results) {
  return getExecutions(results, DBHandle::getInstance());
}

Status Query::getExecutions(std::deque<int> &results,
                            std::shared_ptr<DBHandle> db) {
  HistoricalQueryResults hQR;
  auto s = getHistoricalQueryResults(hQR, db);
  if (s.ok()) {
    results = hQR.executions;
  }
  return s;
}

Status Query::addNewResults(const osquery::db::QueryData &qd, int unix_time) {
  return addNewResults(qd, unix_time, DBHandle::getInstance());
}

Status Query::addNewResults(const QueryData &qd, int unix_time,
                            std::shared_ptr<DBHandle> db) {
  DiffResults dr;
  return addNewResults(qd, dr, false, unix_time, db);
}

osquery::Status Query::addNewResults(const osquery::db::QueryData &qd,
                                     osquery::db::DiffResults &dr,
                                     int unix_time) {
  return addNewResults(qd, dr, true, unix_time, DBHandle::getInstance());
}

osquery::Status Query::addNewResults(const osquery::db::QueryData &qd,
                                     osquery::db::DiffResults &dr,
                                     bool calculate_diff, int unix_time,
                                     std::shared_ptr<DBHandle> db) {
  HistoricalQueryResults hQR;
  auto hqr_status = getHistoricalQueryResults(hQR, db);
  if (!hqr_status.ok() && hqr_status.toString() != kQueryNameNotFoundError) {
    return hqr_status;
  }
  if (calculate_diff) {
    dr = diff(hQR.mostRecentResults.second, qd);
  }
  hQR.pastResults[hQR.mostRecentResults.first] = dr;
  hQR.mostRecentResults.first = unix_time;
  hQR.mostRecentResults.second = qd;
  hQR.executions.push_front(unix_time);
  std::string json;
  auto serialize_status = serializeHistoricalQueryResultsJSON(hQR, json);
  if (!serialize_status.ok()) {
    return serialize_status;
  }
  auto put_status = db->Put(kQueries, query_.name, json);
  if (!put_status.ok()) {
    return put_status;
  }
  return Status(0, "OK");
}

osquery::Status Query::getCurrentResults(osquery::db::QueryData &qd) {
  return getCurrentResults(qd, DBHandle::getInstance());
}

Status Query::getCurrentResults(QueryData &qd, std::shared_ptr<DBHandle> db) {
  HistoricalQueryResults hQR;
  auto s = getHistoricalQueryResults(hQR, db);
  if (s.ok()) {
    qd = hQR.mostRecentResults.second;
  }
  return s;
}
}
}
