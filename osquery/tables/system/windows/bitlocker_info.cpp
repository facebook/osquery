/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genBitlockerInfo(QueryContext& context) {
  Row r;
  QueryData results;

  WmiRequest wmiSystemReq(
      "SELECT * FROM Win32_EncryptableVolume",
      (BSTR)L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (wmiResults.empty()) {
    LOG(WARNING) << "Error retreiving information from WMI.";
    return results;
  }
  for (const auto& data : wmiResults) {
    long status = 0;
    long emethod;
    std::string emethod_str;
    data.GetString("DeviceID", r["device_id"]);
    data.GetString("DriveLetter", r["drive_letter"]);
    data.GetString("PersistentVolumeID", r["persistent_volume_id"]);
    data.GetLong("ConversionStatus", status);
    r["conversion_status"] = INTEGER(status);
    data.GetLong("ProtectionStatus", status);
    r["protection_status"] = INTEGER(status);
    data.GetLong("EncryptionMethod", emethod);
    switch (emethod) {
    case 0:
      emethod_str = "None";
      break;
    case 1:
      emethod_str = "AES_128_WITH_DIFFUSER";
      break;
    case 2:
      emethod_str = "AES_256_WITH_DIFFUSER";
      break;
    case 3:
      emethod_str = "AES_128";
      break;
    case 4:
      emethod_str = "AES_256";
      break;
    case 5:
      emethod_str = "HARDWARE_ENCRYPTION";
      break;
    case 6:
      emethod_str = "XTS_AES_128";
      break;
    case 7:
      emethod_str = "XTS_AES_256";
      break;
    default:
      emethod_str = "UNKNOWN";
      break;
    }
    r["encryption_method"] = emethod_str;
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery