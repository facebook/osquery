// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_CORE_H
#define OSQUERY_CORE_H

#include <string>
#include <vector>

#include "osquery/database.h"
#include "osquery/sqlite3.h"

namespace osquery { namespace core {

// the callback for populating a std::vector<row> set of results. "argument"
// should be a non-const reference to a std::vector<row>
int callback(void *argument, int argc, char *argv[], char *column[]);

// aggregateQuery accepts a const reference to an std::string and returns a
// resultset of type QueryData.
osquery::db::QueryData
aggregateQuery(const std::string& q, int& error_return);
osquery::db::QueryData
aggregateQuery(const std::string& q, int& error_return, sqlite3* db);

// Attach all active virtual tables to an active SQLite database connection
void sqlite3_attach_vtables(sqlite3 *db);

// Return a fully configured sqlite3 database object
sqlite3* createDB();

// Split a given string based on whitespace
std::vector<std::string> split(const std::string& s);
std::vector<std::string> split(const std::string& s,
  const std::string& regexp);

// Join a given string based on a given deliminator.
std::string join(const std::vector<std::string>& v, const std::string& delim);

// trim the surrounding whitespace from a string
std::string &ltrim(std::string &s);
std::string &rtrim(std::string &s);
std::string &trim(std::string &s);

}}

#endif /* OSQUERY_CORE_H */
