/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <netinet/in.h>

#include <resolv.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/posix/utils.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

QueryData genDNSResolversImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // libresolv will populate a global structure with resolver information.
  if (res_init() == -1) {
    return {};
  }

  // The global structure is called "_res" and is of the semi-opaque type
  // struct __res_state from the same resolv.h. An application many communicate
  // with the resolver discovery, but we are interested in the default state.
  struct __res_state& rr = _res;
  if (rr.nscount > 0) {
    for (size_t i = 0; i < static_cast<size_t>(_res.nscount); i++) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "nameserver";
      r["address"] = ipAsString((const struct sockaddr*)&_res.nsaddr_list[i]);
      r["netmask"] = "32";
      // Options applies to every resolver.
      r["options"] = BIGINT(_res.options);
      r["pid_with_namespace"] = "0";
      results.push_back(r);
    }
  }

  if (_res.nsort > 0) {
    for (size_t i = 0; i < static_cast<size_t>(_res.nsort); i++) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "sortlist";
      r["address"] =
          ipAsString((const struct sockaddr*)&_res.sort_list[i].addr);
      r["netmask"] = INTEGER(_res.sort_list[i].mask);
      r["options"] = BIGINT(_res.options);
      r["pid_with_namespace"] = "0";
      results.push_back(r);
    }
  }

  for (size_t i = 0; i < MAXDNSRCH; i++) {
    if (_res.dnsrch[i] != nullptr) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "search";
      r["address"] = std::string(_res.dnsrch[0]);
      r["options"] = BIGINT(_res.options);
      r["pid_with_namespace"] = "0";
      results.push_back(r);
    }
  }

  res_close();
  return results;
}

QueryData genDNSResolvers(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "dns_resovlers", genDNSResolversImpl);
  } else {
    GLOGLogger logger;
    return genDNSResolversImpl(context, logger);
  }
}
}
}
