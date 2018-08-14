/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
// Small hack to make the header compatible with C++
#define prf_ra in6_prflags::prf_ra
#include <netinet6/nd6.h>
#undef prf_ra

#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/tables/networking/posix/interfaces.h>

namespace osquery {
namespace tables {

namespace {
const std:unordered_:map<std::string, int> kIpv6SysctlObjects = {
    {"forwarding", IPV6CTL_FORWARDING},
    {"redirect", IPV6CTL_SENDREDIRECTS},
    {"hlim", IPV6CTL_DEFHLIM},
    {"rtadv", IPV6CTL_ACCEPT_RTADV},
};

int getSysIpv6Config(const std::string& attr) {
  int value;
  size_t size = sizeof(value);
  auto sysctlObject = kIpv6SysctlObjects.find(attr);
  if (sysctlObject == kIpv6SysctlObjects.end()) {
    VLOG(1) << "No such sysctl object identifier: \"" << attr << "\"";
    return -1;
  }
  int mib[] = {CTL_NET, PF_INET6, IPPROTO_IPV6, sysctlObject->second};
  return !sysctl(mib, 4, &value, &size, nullptr, 0) ? value : -1;
}
} // namespace

void genIpv6FromIntf(const std::string& iface, QueryData& results) {
  Row r;
  int ifaceHlim = 0;

  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd >= 0) {
    struct in6_ndireq nd;
    memcpy(nd.ifname, iface.c_str(), sizeof(nd.ifname));
    if (ioctl(fd, SIOCGIFINFO_IN6, &nd) >= 0) {
      ifaceHlim = nd.ndi.chlim;
    } else {
      VLOG(1) << "Error getting information from intf: " << iface;
    }
    close(fd);
  } else {
    VLOG(1) << "Cannot open inet6 socket";
  }

  r["interface"] = iface;
  r["hlim"] = INTEGER(ifaceHlim ? ifaceHlim : getSysIpv6Config("hlim"));
  // Darwin does not support some of the configurations at the interface level
  for (const auto& attr : {"forwarding", "redirect", "rtadv"}) {
    r[attr] = INTEGER(getSysIpv6Config(attr));
  }
  results.emplace_back(std::move(r));
}

QueryData genInterfaceIpv6(QueryContext& context) {
  QueryData results;
  for (const auto& iface : genInterfaceDetails(context)) {
    genIpv6FromIntf(iface.at("interface"), results);
  }
  return results;
}
} // namespace tables
} // namespace osquery
