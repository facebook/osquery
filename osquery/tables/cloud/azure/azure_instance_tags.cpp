/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/azure/azure_util.h>

namespace osquery {
namespace tables {
namespace pt = boost::property_tree;

QueryData genAzureTags(QueryContext& context) {
  QueryData results;
  pt::ptree tree;

  Status s = fetchAzureMetadata(tree);

  if (!s.ok()) {
    TLOG << "Couldn't fetch metadata: " << s.what();
  }

  auto tags_str = tree_get(tree, "tags");
  auto vm_id = tree_get(tree, "vmId");
  std::vector<std::string> tags;

  boost::split(tags, tags_str, boost::is_any_of(";"));

  for (auto& tag : tags) {
    Row r;

    auto colon = tag.find_first_of(':');

    // This shouldn't ever happen, but it doesn't hurt to be safe.
    if (colon == std::string::npos) {
      continue;
    }

    auto key = tag.substr(0, colon);
    auto value = tag.substr(colon + 1);

    r["vm_id"] = vm_id;
    r["key"] = key;
    r["value"] = value;
    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery
