/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/carver/carver.h"
#include "osquery/core/json.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

DECLARE_bool(disable_carver);

/// Database prefix used to directly access and manipulate our carver entries
const std::string kCarverDBPrefix = "carving.";

void enumerateCarves(QueryData& results) {
  std::vector<std::string> carves;
  auto s = scanDatabaseKeys(kQueries, carves, kCarverDBPrefix);

  for (const auto& carveGuid : carves) {
    std::string carve;
    s = getDatabaseValue(kQueries, carveGuid, carve);
    if(!s.ok()) {
      VLOG(1) << "Failed to retreive carve GUID";
      continue;
    }

    pt::ptree tree;
    try {
      std::stringstream ss(carve);
      pt::read_json(ss, tree);
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Failed to parse carving entries: " << e.what();
      return;
    }

    Row r;
    r["time"] = BIGINT(tree.get<int>("time"));
    r["size"] = INTEGER(tree.get<int>("size"));
    r["sha256"] = SQL_TEXT(tree.get<std::string>("sha256"));
    r["carve_guid"] = SQL_TEXT(tree.get<std::string>("carve_guid"));
    r["status"] = SQL_TEXT(tree.get<std::string>("status"));
    r["carve"] = INTEGER(0);
    r["path"] = SQL_TEXT(tree.get<std::string>("path"));
    results.push_back(r);
  }
}

QueryData genCarves(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  if (context.constraints["carve"].exists(EQUALS) && paths.size() > 0) {
    auto guid = boost::uuids::to_string(boost::uuids::random_generator()());

    pt::ptree tree;
    tree.put("carve_guid", guid);
    tree.put("time", time(nullptr));
    tree.put("status", "STARTING");
    tree.put("sha256", "");
    tree.put("size", -1);
    if(paths.size() > 1) {
      tree.put("path", boost::algorithm::join(paths, ","));
    } else {
      tree.put("path", *(paths.begin()));
    }

    std::ostringstream os;
    pt::write_json(os, tree, false);
    auto s = setDatabaseValue(kQueries, kCarverDBPrefix + guid, os.str());
    if(!s.ok()){
      LOG(WARNING) << "Error inserting new carve entry into the database: " << s.getMessage();
    }

    Dispatcher::addService(std::make_shared<Carver>(paths, guid));
  }
  enumerateCarves(results);

  return results;
}
}
}
