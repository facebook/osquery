/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>
#include <sstream>

#include <stdlib.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/wmi.h"

namespace osquery {
namespace tables {


QueryData genShares(QueryContext& context) {
  QueryData results_data;
  std::stringstream ss;
  ss << "SELECT * FROM Win32_Share";

  WmiRequest request(ss.str());
  if (request.getStatus().ok()) {
	std::vector<WmiResultItem>& results = request.results();
	for (const auto& result : results) {
		Row r;
		Status s;
		long lPlaceHolder;
		bool bPlaceHolder;
		std::string sPlaceHolder;

		s = result.GetString("Description", sPlaceHolder);
		r["description"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("InstallDate", sPlaceHolder);
		r["install_date"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("Status", sPlaceHolder);
		r["status"] = SQL_TEXT(sPlaceHolder);
		s = result.GetBool("AllowMaximum", bPlaceHolder);
		r["allow_maximum"] = INTEGER(bPlaceHolder);
		s = result.GetLong("MaximumAllowed", lPlaceHolder);
		r["maximum_allowed"] = INTEGER(lPlaceHolder);
		s = result.GetString("Name", sPlaceHolder);
		r["name"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("Path", sPlaceHolder);
		r["path"] = SQL_TEXT(sPlaceHolder);
		s = result.GetLong("Type", lPlaceHolder);
		r["type"] = INTEGER(lPlaceHolder);
		results_data.push_back(r);
	}
  }
  
  return results_data;
}
}
}