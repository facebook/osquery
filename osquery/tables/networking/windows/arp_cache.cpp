/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <boost/range/algorithm/find.hpp>
#include <osquery/tables.h>
#include <string>

#include "boost/algorithm/string/replace.hpp"
#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/networking/windows/interfaces.h"

namespace osquery {
namespace tables {

const std::map<unsigned short, const std::string> mapOfAddressFamily = {
    {2, "IPv4"}, {23, "IPv6"},
};

const std::map<unsigned char, const std::string> mapOfStore = {
    {0, "Persistent"}, {1, "Active"},
};

const std::map<unsigned char, const std::string> mapOfState = {
    {0, "Unreachable"},
    {1, "Incomplete"},
    {2, "Probe"},
    {3, "Delay"},
    {4, "Stale"},
    {5, "Reachable"},
    {6, "Permanent"},
    {7, "TBD"},
};

QueryData genArpCache(QueryContext& context) {
  Row r;
  QueryData results;
  QueryData interfaces = genInterfaceDetails(context);
  WmiRequest wmiSystemReq("select * from MSFT_NetNeighbor",
                          L"ROOT\\StandardCimv2");
  std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  std::map<long, std::string> mapOfInterfaces = {
      {1, ""}, // loopback
  };
  unsigned short usiPlaceHolder;
  unsigned char cPlaceHolder;
  unsigned int uiPlaceHolder;
  std::string strPlaceHolder;

  for (auto& iface : interfaces) {
    long interfaceIndex = atol(iface["interface"].c_str());
    std::string macAddress = iface["mac"];
    mapOfInterfaces.insert(
        std::pair<long, std::string>(interfaceIndex, macAddress));
  }
  for (const auto& item : wmiResults) {
    item.GetUnsignedShort("AddressFamily", usiPlaceHolder);
    r["address_family"] = SQL_TEXT(mapOfAddressFamily.at(usiPlaceHolder));
    item.GetUChar("Store", cPlaceHolder);
    r["store"] = SQL_TEXT(mapOfStore.at(cPlaceHolder));
    item.GetUChar("State", cPlaceHolder);
    r["state"] = SQL_TEXT(mapOfState.at(cPlaceHolder));
    item.GetUnsignedInt32("InterfaceIndex", uiPlaceHolder);
    r["interface"] = SQL_TEXT(mapOfInterfaces.at(uiPlaceHolder));
    item.GetString("IPAddress", r["ip_address"]);
    item.GetString("InterfaceAlias", r["interface_alias"]);
    item.GetString("LinkLayerAddress", strPlaceHolder);
    r["link_layer_address"] =
        SQL_TEXT(boost::replace_all_copy(strPlaceHolder, "-", ":"));

    results.push_back(r);
  }

  return results;
}

QueryData genCrossPlatformArpCache(QueryContext& context) {
  Row r;
  QueryData results;
  QueryData winArpCache = genArpCache(context);

  for (const auto& item : winArpCache) {
    if (item.at("link_layer_address") == "" ||
        item.at("link_layer_address") == "00:00:00:00:00:00") {
      continue;
    }
    if (item.at("address_family") == "IPv4") {
      r["address"] = item.at("ip_address");
      r["mac"] = item.at("link_layer_address");
      r["interface"] = item.at("interface");
      r["permanent"] = SQL_TEXT("0");
      if (item.at("state") == "Permanent") {
        r["permanent"] = SQL_TEXT("1");
      }
      results.push_back(r);
    }
  }

  return results;
}
}
}
