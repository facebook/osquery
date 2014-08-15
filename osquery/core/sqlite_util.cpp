// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/core/sqlite_util.h"

#include <iostream>
#include <map>
#include <string>

#include <glog/logging.h>
#include <sqlite3.h>

#include "osquery/database.h"
#include "osquery/tables/base.h"
#include "osquery/tables/registry.h"

using namespace osquery::db;
using namespace osquery::tables;

namespace osquery {
namespace core {

sqlite3 *createDB() {
  sqlite3 *db = nullptr;
  sqlite3_open(":memory:", &db);
  osquery::tables::attachVirtualTables(db);
  return db;
}

QueryData aggregateQuery(const std::string &q, int &error_return) {
  return aggregateQuery(q, error_return, createDB());
}

QueryData aggregateQuery(const std::string &q, int &error_return, sqlite3 *db) {
  QueryData d;
  char *err = nullptr;
  sqlite3_exec(db, q.c_str(), query_data_callback, &d, &err);
  if (err != nullptr) {
    LOG(ERROR) << "Error launching query: " << err;
    error_return = 1;
    sqlite3_free(err);
  } else {
    error_return = 0;
  }

  return d;
}

int query_data_callback(void *argument, int argc, char *argv[],
                        char *column[]) {
  if (argument == nullptr) {
    LOG(ERROR) << "query_data_callback received nullptr as data argument";
    return SQLITE_MISUSE;
  }
  QueryData *qData = (QueryData *)argument;
  Row r;
  for (int i = 0; i < argc; i++) {
    r[column[i]] = argv[i];
  }
  (*qData).push_back(r);
  return 0;
}
}
}
