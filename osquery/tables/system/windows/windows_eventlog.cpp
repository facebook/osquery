/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <Windows.h>
#include <winevt.h>

#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/events/windows/windowseventlogparser.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kEventLogXmlPrefix = "<QueryList><Query Id=\"0\">";
const std::string kEventLogXmlSuffix = "</Query></QueryList>";

const int kNumEventsBlock = 1024;

void parseWelXml(QueryContext& context,
                 std::wstring& xml_event,
                 RowYield& yield) {
  auto row = make_table_row();
  pt::ptree propTree;
  WELEvent windows_event;
  auto status = parseWindowsEventLogXML(propTree, xml_event);
  status = parseWindowsEventLogPTree(windows_event, propTree);

  row["time"] = INTEGER(windows_event.osquery_time);
  row["datetime"] = SQL_TEXT(windows_event.datetime);
  row["channel"] = SQL_TEXT(windows_event.source);
  row["provider_name"] = SQL_TEXT(windows_event.provider_name);
  row["provider_guid"] = SQL_TEXT(windows_event.provider_guid);
  row["eventid"] = INTEGER(windows_event.event_id);
  row["task"] = INTEGER(windows_event.task_id);
  row["level"] = INTEGER(windows_event.level);
  row["pid"] = INTEGER(windows_event.pid);
  row["tid"] = INTEGER(windows_event.tid);

  row["keywords"] = SQL_TEXT(windows_event.keywords);
  row["data"] = SQL_TEXT(windows_event.data);

  if (context.hasConstraint("time_range", EQUALS)) {
    auto time_range = context.constraints["time_range"].getAll(EQUALS);
    row["time_range"] = SQL_TEXT(*time_range.begin());
  } else {
    row["time_range"] = SQL_TEXT("");
  }

  if (context.hasConstraint("timestamp", EQUALS)) {
    auto timestamp = context.constraints["timestamp"].getAll(EQUALS);
    row["timestamp"] = SQL_TEXT(*timestamp.begin());
  }

  if (context.hasConstraint("xpath", EQUALS)) {
    auto xpaths = context.constraints["xpath"].getAll(EQUALS);
    row["xpath"] = SQL_TEXT(*xpaths.begin());
  }

  yield(std::move(row));
}

void parseQueryResults(QueryContext& context,
                       EVT_HANDLE queryResults,
                       RowYield& yield) {
  std::vector<EVT_HANDLE> events(kNumEventsBlock);
  unsigned long numEvents = 0;

  // Retrieve the events one block at a time
  auto ret = EvtNext(
      queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);
  while (ret != FALSE) {
    for (unsigned long i = 0; i < numEvents; i++) {
      unsigned long renderedBuffSize = 0;
      unsigned long renderedBuffUsed = 0;
      unsigned long propCount = 0;
      if (!EvtRender(nullptr,
                     events[i],
                     EvtRenderEventXml,
                     renderedBuffSize,
                     nullptr,
                     &renderedBuffUsed,
                     &propCount)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
          LOG(WARNING) << "Failed to allocated memory to render event "
                       << GetLastError();
          continue;
        }
      }

      std::vector<wchar_t> renderedContent(renderedBuffUsed);
      renderedBuffSize = renderedBuffUsed;
      if (!EvtRender(nullptr,
                     events[i],
                     EvtRenderEventXml,
                     renderedBuffSize,
                     renderedContent.data(),
                     &renderedBuffUsed,
                     &propCount)) {
        LOG(WARNING) << "Failed to render windows event with "
                     << GetLastError();
        continue;
      }

      std::wstringstream xml_event;
      xml_event << renderedContent.data();
      parseWelXml(context, xml_event.str(), yield);
      EvtClose(events[i]);
    }

    ret = EvtNext(
        queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);
  }
  if (ERROR_NO_MORE_ITEMS != GetLastError()) {
    // No need to close the handler after error; The query
    // EvtClose will also close all the event handler
    VLOG(1) << "EvtNext failed with error " << GetLastError();
  }
}

void genXfilterFromConstraints(QueryContext& context, std::string& xfilter) {
  std::vector<std::string> xfilterList;

  auto eids = context.constraints["eventid"].getAll(EQUALS);
  if (!eids.empty()) {
    xfilterList.emplace_back(
        "(EventID=" + osquery::join(eids, ") or (EventID=") + ")");
  }

  auto pids = context.constraints["pid"].getAll(EQUALS);
  if (!pids.empty()) {
    xfilterList.emplace_back(
        "(Execution[@ProcessID=" +
        osquery::join(pids, "]) or (Execution[@ProcessID=") + "])");
  }

  auto times = context.constraints["time_range"].getAll(EQUALS);
  auto timestamps = context.constraints["timestamp"].getAll(EQUALS);
  if (!times.empty()) {
    auto datetime = *times.begin();
    auto time_vec = osquery::split(datetime, ";");

    if (time_vec.size() == 1) {
      auto _start = time_vec.front();
      xfilterList.emplace_back("TimeCreated[@SystemTime&gt;='" + _start + "']");
    } else if (time_vec.size() == 2) {
      auto _start = time_vec.front();
      auto _end = time_vec.at(1);
      xfilterList.emplace_back("TimeCreated[@SystemTime&gt;='" + _start +
                               "' and @SystemTime&lt;='" + _end + "']");
    }
  } else if (!timestamps.empty()) {
    auto time_diff = *timestamps.begin();
    xfilterList.emplace_back(
        "TimeCreated[timediff(@SystemTime) &lt;= " + time_diff + "]");
  }

  xfilter = xfilterList.empty()
                ? "*"
                : "*[System[" + osquery::join(xfilterList, " and ") + "]]";
}

void genWindowsEventLog(RowYield& yield, QueryContext& context) {
  std::set<std::pair<std::string, std::string>> xpath_set;

  // Check if the `xpath` constraint is available. The `xpath` has
  // priority over `channel` and it will lookup and filter the events
  // based on `xpath` if passed.
  if (context.hasConstraint("xpath", EQUALS)) {
    auto xpaths = context.constraints["xpath"].getAll(EQUALS);
    auto xpath = *xpaths.begin();
    pt::ptree propTree;
    std::stringstream ss;
    ss << xpath;
    pt::read_xml(ss, propTree);
    auto channel = propTree.get("QueryList.Query.Select.<xmlattr>.Path", "");
    if (!channel.empty()) {
      xpath_set.insert(std::make_pair(channel, xpath));
    } else {
      LOG(WARNING) << "Invalid xpath format - " << xpath;
    }
  } else if (context.hasConstraint("channel", EQUALS)) {
    auto channels = context.constraints["channel"].getAll(EQUALS);
    std::string xfilter("");
    genXfilterFromConstraints(context, xfilter);
    std::string welSearchQuery = kEventLogXmlPrefix;

    for (const auto& channel : channels) {
      welSearchQuery += "<Select Path=\"" + channel + "\">";
      welSearchQuery += xfilter;
      welSearchQuery += "</Select>" + kEventLogXmlSuffix;
      xpath_set.insert(std::make_pair(channel, welSearchQuery));
    }
  } else {
    LOG(WARNING) << "must specify the event log channel or xpath for lookup!";
    return;
  }

  for (const auto& path : xpath_set) {
    auto queryResults =
        EvtQuery(nullptr,
                 stringToWstring(path.first).c_str(),
                 stringToWstring(path.second).c_str(),
                 EvtQueryChannelPath | EvtQueryReverseDirection);

    if (queryResults == nullptr) {
      LOG(WARNING) << "Failed to search event log for query with "
                   << GetLastError();
      return;
    }

    parseQueryResults(context, queryResults, yield);
    EvtClose(queryResults);
  }
}

}; // namespace tables
}; // namespace osquery
