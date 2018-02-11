/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/remote/bro/bro_utils.h"

namespace pt = boost::property_tree;

namespace osquery {

Status createSubscriptionRequest(const BrokerRequestType& rType,
                                 const broker::message& msg,
                                 const std::string& incoming_topic,
                                 SubscriptionRequest& sr) {
  // Check number of fields
  unsigned long numFields;
  if (rType == EXECUTE) {
    numFields = 6;
  } else if (rType == SUBSCRIBE || rType == UNSUBSCRIBE) {
    numFields = 7;
  } else {
    return Status(1,
                  "Unknown Subscription Request Type '" +
                      kBrokerRequestTypeNames.at(rType) + "'");
  }

  if (msg.size() != numFields) {
    return Status(1,
                  std::to_string(msg.size()) + " instead of " +
                      std::to_string(numFields) + " fields in '" +
                      kBrokerRequestTypeNames.at(rType) + "' message '" +
                      broker::to_string(msg[0]));
  }

  // Query String
  if (!broker::is<std::string>(msg[1])) {
    return Status(1, "SQL query is not a string");
  }
  sr.query = *broker::get<std::string>(msg[2]);

  // Response Event Name
  if (!broker::is<std::string>(msg[1])) {
    return Status(1, "Response Event Name is not a string");
  }
  sr.response_event = *broker::get<std::string>(msg[1]);

  // Cookie
  auto cookie = broker::to_string(msg[3]);
  sr.cookie = cookie;

  // Response Topic
  if (!broker::is<std::string>(msg[4])) {
    return Status(1, "Response Topic Name is not a string");
  }
  if (broker::to_string(msg[4]).empty()) {
    sr.response_topic = incoming_topic;
    LOG(WARNING) << "No response topic given for event '" << sr.response_event
                 << "' reporting back to "
                    "incoming topic '"
                 << incoming_topic << "'";
  } else {
    sr.response_topic = *broker::get<std::string>(msg[4]);
  }

  // Update Type
  std::string update_type = broker::to_string(msg[5]);
  if (update_type == "ADDED") {
    sr.added = true;
    sr.removed = false;
    sr.snapshot = false;
  } else if (update_type == "REMOVED") {
    sr.added = false;
    sr.removed = true;
    sr.snapshot = false;
  } else if (update_type == "BOTH") {
    sr.added = true;
    sr.removed = true;
    sr.snapshot = false;
  } else if (update_type == "SNAPSHOT") {
    sr.added = false;
    sr.removed = false;
    sr.snapshot = true;
  } else {
    return Status(1, "Unknown update type");
  }

  // If one-time query
  if (rType == EXECUTE) {
    if (sr.added || sr.removed || !sr.snapshot) {
      LOG(WARNING) << "Only possible to query SNAPSHOT for one-time queries";
    }
    return Status(0, "OK");
  }
  // SUBSCRIBE or UNSUBSCRIBE
  if (sr.snapshot) {
    LOG(WARNING)
        << "Only possible to query ADD and/or REMOVE for scheduled queries";
  }

  // Interval
  if (!broker::is<uint64_t>(msg[6])) {
    return Status(1, "Interval is not a number");
  }
  sr.interval = *broker::get<uint64_t>(msg[6]);

  return Status(0, "OK");
}

Status parseBrokerGroups(const std::string& json_groups,
                         std::vector<std::string>& groups) {
  pt::ptree groups_tree;
  try {
    auto clone = "{\"groups\":" + json_groups + "}";
    stripConfigComments(clone);
    std::stringstream json_stream;
    json_stream << clone;
    pt::read_json(json_stream, groups_tree);

    if (groups_tree.count("groups") >= 1) {
      auto& pt_groups = groups_tree.get_child("groups");
      for (const auto& ptg : pt_groups) {
        std::string ptg_value = pt_groups.get<std::string>(ptg.first, "");
        if (!ptg_value.empty()) {
          groups.push_back(ptg_value);
        }
      }
    }
  } catch (const pt::json_parser::json_parser_error& /* e */) {
    return Status(1, "Error parsing the bro groups");
  }
  return Status(0, "OK");
}
} // namespace osquery
