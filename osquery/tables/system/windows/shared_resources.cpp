/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <string>

#include <osquery/core.h>
#include <osquery/tables.h>

#include <osquery/utils/conversions/tryto.h>
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genShares(QueryContext& context) {
  QueryData results_data;

  const WmiRequest request("SELECT * FROM Win32_Share");
  if (request.getStatus().ok()) {
    const std::vector<WmiResultItem>& results = request.results();
    for (const auto& result : results) {
      Row r;
      long lPlaceHolder;
      bool bPlaceHolder;

      result.GetString("Description", r["description"]);
      result.GetString("InstallDate", r["install_date"]);
      result.GetString("Status", r["status"]);
      result.GetBool("AllowMaximum", bPlaceHolder);
      r["allow_maximum"] = INTEGER(bPlaceHolder);
      result.GetLong("MaximumAllowed", lPlaceHolder);
      r["maximum_allowed"] = INTEGER(lPlaceHolder);
      result.GetString("Name", r["name"]);
      result.GetString("Path", r["path"]);
      result.GetLong("Type", lPlaceHolder);
      r["type"] = INTEGER(lPlaceHolder);
      results_data.push_back(r);
    }
  }

  return results_data;
}
}
}
