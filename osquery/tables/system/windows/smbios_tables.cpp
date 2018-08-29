/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iomanip>
#include <sstream>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

std::string to_iso8601_datetime(const FILETIME& ft) {
  SYSTEMTIME date = {0};

  if (FileTimeToSystemTime(&ft, &date) == FALSE) {
    // NOTE(andy): Failure to convert to SYSTEMTIME yields empty response
    return "";
  }

  std::ostringstream iso_date;
  iso_date << std::setfill('0');
  iso_date << std::setw(4) << date.wYear << "-" << std::setw(2) << 
    date.wMonth << "-" << std::setw(2) << date.wDay << "T" << std::setw(2) << 
    date.wHour << ":" << std::setw(2) << date.wMinute << ":" << std::setw(2) << 
    date.wSecond << "." << std::setw(3) << date.wMilliseconds;

  TIME_ZONE_INFORMATION tz = {0};
  if (GetTimeZoneInformationForYear(date.wYear, nullptr, &tz) == FALSE) {
    // NOTE(andy): On error getting timezone information, return an empty 
    //             string
    return "";
  }

  // NOTE(andy): Calculate time zone portion of date time
  LONG tMin = std::abs(tz.Bias);
  LONG wHours = tMin / 60;
  LONG wMinute = tMin - (wHours * 60);

  iso_date << ((tz.Bias > 0) ? "-" : "+") << std::setw(2) << wHours << ":" <<
    std::setw(2) << wMinute;
  return iso_date.str();
}

QueryData genPlatformInfo(QueryContext& context) {
  QueryData results;

  std::string query =
      "select Manufacturer, SMBIOSBIOSVersion, ReleaseDate, "
      "SystemBiosMajorVersion, SystemBiosMinorVersion from Win32_BIOS";
  WmiRequest request(query);
  if (!request.getStatus().ok()) {
    return results;
  }
  std::vector<WmiResultItem>& wmiResults = request.results();
  if (wmiResults.size() != 1) {
    return results;
  }
  Row r;
  std::string sPlaceholder;
  wmiResults[0].GetString("Manufacturer", r["vendor"]);
  wmiResults[0].GetString("SMBIOSBIOSVersion", r["version"]);
  unsigned char majorRevision = 0x0;
  wmiResults[0].GetUChar("SystemBiosMajorVersion", majorRevision);
  unsigned char minorRevision = 0x0;
  wmiResults[0].GetUChar("SystemBiosMinorVersion", minorRevision);
  r["revision"] =
      std::to_string(majorRevision) + "." + std::to_string(minorRevision);

  FILETIME release_date = {0};
  wmiResults[0].GetDateTime("ReleaseDate", false, release_date);

  r["date"] = to_iso8601_datetime(release_date);

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
