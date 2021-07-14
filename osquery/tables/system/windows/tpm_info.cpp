/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

QueryData genTpmInfo(QueryContext& context) {
  QueryData resultsdata;
  std::string wmiclass{"SELECT * FROM Win32_Tpm"};

  BSTR wminamespace = ::SysAllocString(L"root\\cimv2\\Security\\MicrosoftTpm");
  if (wminamespace == nullptr) {
    return {};
  }
  const WmiRequest request(wmiclass, wminamespace);
  ::SysFreeString(wminamespace);

  if (request.getStatus().ok()) {
    const auto& results = request.results();
    for (const auto& result : results) {
      Row r;

      auto isBool = false;
      long ManufacturerID;

      result.GetBool("IsActivated_InitialValue", isBool);
      r["activated"] = INTEGER(isBool);
      result.GetBool("IsEnabled_InitialValue", isBool);
      r["enabled"] = INTEGER(isBool);
      result.GetBool("IsOwned_InitialValue", isBool);
      r["owned"] = INTEGER(isBool);
      (result.GetLong("ManufacturerId", ManufacturerID))
          ? r["manufacturer_id"] = INTEGER(ManufacturerID)
          : r["manufacturer_id"] = "-1";
      result.GetString("ManufacturerIdTxt", r["manufacturer_name"]);
      result.GetString("ManufacturerVersion", r["manufacturer_version"]);
      result.GetString("ManufacturerVersionInfo", r["product_name"]);
      result.GetString("PhysicalPresenceVersionInfo",
                       r["physical_presence_version"]);
      result.GetString("SpecVersion", r["spec_version"]);
      resultsdata.push_back(r);
    }
  }
  return resultsdata;
}
} // namespace tables
} // namespace osquery
