/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/system.h>

#include <Wtsapi32.h>
#include <winsock2.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/process/windows/process_ops.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>

const std::map<int, std::string> kSessionStates = {
    {WTSActive, "active"},
    {WTSDisconnected, "disconnected"},
    {WTSConnected, "connected"},
    {WTSConnectQuery, "connectquery"},
    {WTSShadow, "shadow"},
    {WTSIdle, "idle"},
    {WTSListen, "listen"},
    {WTSReset, "reset"},
    {WTSDown, "down"},
    {WTSInit, "init"}};

namespace osquery {
namespace tables {

QueryData genLoggedInUsers(QueryContext& context) {
  QueryData results;

  PWTS_SESSION_INFO_1 pSessionInfo;
  unsigned long count;
  /*
   * As per the MSDN:
   * This parameter is reserved. Always set this parameter to one.
   */
  unsigned long level = 1;
  auto res = WTSEnumerateSessionsEx(
      WTS_CURRENT_SERVER_HANDLE, &level, 0, &pSessionInfo, &count);

  if (res == 0) {
    return results;
  }

  for (size_t i = 0; i < count; i++) {
    Row r;

    LPWSTR sessionInfo = nullptr;
    DWORD bytesRet = 0;
    res = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                     pSessionInfo[i].SessionId,
                                     WTSSessionInfo,
                                     &sessionInfo,
                                     &bytesRet);
    if (res == 0 || sessionInfo == nullptr) {
      VLOG(1) << "Error querying WTS session information (" << GetLastError()
              << ")";
      continue;
    }
    const auto wtsSession = reinterpret_cast<WTSINFOW*>(sessionInfo);
    r["user"] = SQL_TEXT(wstringToString(wtsSession->UserName));
    r["type"] = SQL_TEXT(kSessionStates.at(pSessionInfo[i].State));
    r["tty"] = pSessionInfo[i].pSessionName == nullptr
                   ? ""
                   : pSessionInfo[i].pSessionName;

    FILETIME utcTime = {0};
    unsigned long long unixTime = 0;
    utcTime.dwLowDateTime = wtsSession->ConnectTime.LowPart;
    utcTime.dwHighDateTime = wtsSession->ConnectTime.HighPart;
    if (utcTime.dwLowDateTime != 0 || utcTime.dwHighDateTime != 0) {
      unixTime = filetimeToUnixtime(utcTime);
    }
    r["time"] = INTEGER(unixTime);

    char* clientInfo = nullptr;
    bytesRet = 0;
    res = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
                                     pSessionInfo[i].SessionId,
                                     WTSClientInfo,
                                     &clientInfo,
                                     &bytesRet);
    if (res == 0 || clientInfo == nullptr) {
      VLOG(1) << "Error querying WTS session information (" << GetLastError()
              << ")";
      results.push_back(r);
      WTSFreeMemory(sessionInfo);
      continue;
    }

    auto wtsClient = reinterpret_cast<WTSCLIENTA*>(clientInfo);
    if (wtsClient->ClientAddressFamily == AF_INET) {
      r["host"] = std::to_string(wtsClient->ClientAddress[0]) + "." +
                  std::to_string(wtsClient->ClientAddress[1]) + "." +
                  std::to_string(wtsClient->ClientAddress[2]) + "." +
                  std::to_string(wtsClient->ClientAddress[3]);
    } else if (wtsClient->ClientAddressFamily == AF_INET6) {
      // TODO: IPv6 addresses are given as an array of byte values.
      auto addr = reinterpret_cast<const char*>(wtsClient->ClientAddress);
      r["host"] = std::string(addr, CLIENTADDRESS_LENGTH);
    }

    r["pid"] = INTEGER(-1);

    if (clientInfo != nullptr) {
      WTSFreeMemory(clientInfo);
      clientInfo = nullptr;
      wtsClient = nullptr;
    }

    const auto sidBuf =
        getSidFromUsername(wtsSession->UserName);

    if (sessionInfo != nullptr) {
      WTSFreeMemory(sessionInfo);
      sessionInfo = nullptr;
    }

    if (sidBuf == nullptr) {
      VLOG(1) << "Error converting username to SID";
      results.push_back(r);
      continue;
    }

    const auto sidStr = psidToString(reinterpret_cast<SID*>(sidBuf.get()));
    r["sid"] = SQL_TEXT(sidStr);

    const auto hivePath = "HKEY_USERS\\" + sidStr;
    r["registry_hive"] = SQL_TEXT(hivePath);

    results.push_back(r);
  }

  if (pSessionInfo != nullptr) {
    WTSFreeMemory(pSessionInfo);
    pSessionInfo = nullptr;
  }

  return results;
}
} // namespace tables
} // namespace osquery
