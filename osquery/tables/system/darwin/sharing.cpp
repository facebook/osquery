/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/sql/sqlite_util.h"
#include "osquery/tables/system/darwin/sharing.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kInternetSharingPath =
    "/Library/Preferences/SystemConfiguration/com.apple.nat.plist";

const std::string kRemoteAppleManagementPath =
    "/Library/Application Support/Apple/Remote "
    "Desktop/RemoteManagement.launchd";

const std::string kRemoteBluetoothSharingPath = "/Library/Preferences/ByHost/";

const std::string kRemoteBluetoothSharingPattern = "com.apple.Bluetooth.%";

bool remoteAppleManagementPlistExists() {
  auto remoteAppleManagementFileInfo =
      SQL::selectAllFrom("file", "path", EQUALS, kRemoteAppleManagementPath);
  if (remoteAppleManagementFileInfo.empty()) {
    return false;
  }
  return true;
}

int getScreenSharingStatus() {
  Boolean loaded = false, persistence = false;
  if (remoteAppleManagementPlistExists()) {
    return 0;
  }
  loaded = SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.apple.screensharing"), &persistence);
  return (!(loaded ^ persistence));
}

int getRemoteManagementStatus() {
  return remoteAppleManagementPlistExists() ? 1 : 0;
}

int getFileSharingStatus() {
  Boolean fileServerStatus = false, fileServerPersistence = false;
  Boolean smbStatus = false, smbPersistence = false;

  smbStatus = SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.apple.smbd"), &smbPersistence);
  fileServerStatus = SMJobIsEnabled(kSMDomainSystemLaunchd,
                                    CFSTR("com.apple.AppleFileServer"),
                                    &fileServerPersistence);
  return (!(smbStatus ^ smbPersistence)) |
         (!(fileServerStatus ^ fileServerPersistence));
}

int getRemoteLoginStatus() {
  Boolean loaded = false, persistence = false;
  loaded = SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.openssh.sshd"), &persistence);
  return (!(loaded ^ persistence));
}

int getRemoteAppleEventStatus() {
  Boolean loaded = false, persistence = false;
  loaded = SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.apple.AEServer"), &persistence);
  return (!(loaded ^ persistence));
}

int getPrinterSharingStatus() {
  http_t* cups = nullptr;
  int num_settings = 0;
  cups_option_t* settings = nullptr;
  const char* value = nullptr;

  cups = httpConnect2(cupsServer(),
                      ippPort(),
                      nullptr,
                      AF_INET,
                      cupsEncryption(),
                      1,
                      30000,
                      nullptr);
  if (cups != nullptr) {
    int ret = cupsAdminGetServerSettings(cups, &num_settings, &settings);
    if (ret != 0) {
      value = cupsGetOption("_share_printers", num_settings, settings);
      cupsFreeOptions(num_settings, settings);
    } else {
      VLOG(1) << "ERROR: Unable to get CUPS server settings: "
              << cupsLastErrorString();
    }
    httpClose(cups);
  }
  if (value != nullptr) {
    return *value == '1' ? 1 : 0;
  }
  return 0;
}

int getInterNetSharingStatus() {
  auto internetSharingStatus =
      SQL::selectAllFrom("plist", "path", EQUALS, kInternetSharingPath);
  if (internetSharingStatus.empty()) {
    return 0;
  }
  for (const auto& row : internetSharingStatus) {
    if (row.find("key") == row.end() || row.find("subkey") == row.end() ||
        row.find("value") == row.end()) {
      continue;
    }
    if (row.at("key") == "NAT" && row.at("subkey") == "Enabled" &&
        row.at("value") == INTEGER(1)) {
      return 1;
    }
  }
  return 0;
}

int getBluetoothSharingStatus() {
  auto users = SQL::selectAllFrom("users");
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      auto dir = fs::path(row.at("directory")) / kRemoteBluetoothSharingPath;
      if (!pathExists(dir).ok()) {
        continue;
      }
      std::vector<std::string> paths;
      if (!resolveFilePattern(dir / kRemoteBluetoothSharingPattern, paths)
               .ok()) {
        continue;
      }

      for (const auto& bluetoothSharing_path : paths) {
        auto bluetoothSharingStatus =
            SQL::selectAllFrom("plist", "path", EQUALS, bluetoothSharing_path);
        if (bluetoothSharingStatus.empty()) {
          continue;
        }
        for (const auto& r : bluetoothSharingStatus) {
          if (r.find("key") == row.end() || row.find("value") == r.end()) {
            continue;
          }
          if (r.at("key") == "PrefKeyServicesEnabled" &&
              r.at("value") == INTEGER(1)) {
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

QueryData genSharing(QueryContext& context) {
  Row r;
  r["screen_sharing"] = INTEGER(getScreenSharingStatus());
  r["file_sharing"] = INTEGER(getFileSharingStatus());
  r["printer_sharing"] = INTEGER(getPrinterSharingStatus());
  r["remote_login"] = INTEGER(getRemoteLoginStatus());
  r["remote_management"] = INTEGER(getRemoteManagementStatus());
  r["remote_apple_events"] = INTEGER(getRemoteAppleEventStatus());
  r["internet_sharing"] = INTEGER(getInterNetSharingStatus());
  r["bluetooth_sharing"] = INTEGER(getBluetoothSharingStatus());
  return {r};
}

} // namespace tables
} // namespace osquery
