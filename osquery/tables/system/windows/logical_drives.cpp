/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genLogicalDrives(QueryContext& context) {
  QueryData results;

  const WmiRequest wmiLogicalDiskReq(
      "select DeviceID, Description, FreeSpace, Size, FileSystem from "
      "Win32_LogicalDisk");
  const std::vector<WmiResultItem>& wmiResults = wmiLogicalDiskReq.results();
  for (unsigned int i = 0; i < wmiResults.size(); ++i) {
    Row r;
    std::string driveType;
    std::string deviceId;
    wmiResults[i].GetString("Description", driveType);
    wmiResults[i].GetString("DeviceID", deviceId);
    wmiResults[i].GetString("FreeSpace", r["free_space"]);
    wmiResults[i].GetString("Size", r["size"]);
    wmiResults[i].GetString("FileSystem", r["file_system"]);

    r["type"] = driveType;
    r["device_id"] = deviceId;
    r["boot_partition"] = INTEGER(0);

    std::string assocQuery =
        std::string("Associators of {Win32_LogicalDisk.DeviceID='") + deviceId +
        "'} where AssocClass=Win32_LogicalDiskToPartition";

    const WmiRequest wmiLogicalDiskToPartitionReq(assocQuery);
    const std::vector<WmiResultItem>& wmiLogicalDiskToPartitionResults =
        wmiLogicalDiskToPartitionReq.results();

    if (wmiLogicalDiskToPartitionResults.empty()) {
      results.push_back(r);
      continue;
    }
    std::string partitionDeviceId;
    wmiLogicalDiskToPartitionResults[0].GetString("DeviceID",
                                                  partitionDeviceId);

    std::string partitionQuery =
        std::string(
            "SELECT BootPartition FROM Win32_DiskPartition WHERE DeviceID='") +
        partitionDeviceId + '\'';
    const WmiRequest wmiPartitionReq(partitionQuery);
    const std::vector<WmiResultItem>& wmiPartitionResults =
        wmiPartitionReq.results();

    if (wmiPartitionResults.empty()) {
      results.push_back(r);
      continue;
    }
    bool bootPartition = false;
    wmiPartitionResults[0].GetBool("BootPartition", bootPartition);
    r["boot_partition"] = bootPartition ? INTEGER(1) : INTEGER(0);
    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
