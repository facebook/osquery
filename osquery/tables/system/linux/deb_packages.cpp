/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// see README.api of libdpkg-dev
#define LIBDPKG_VOLATILE_API

#include <boost/algorithm/string.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/tables/system/linux/deb_package_helpers.h"

namespace osquery {
namespace tables {

void extractDebPackageInfo(const struct pkginfo *pkg, QueryData &results) {
  Row r;

  struct varbuf vb;
  varbuf_init(&vb, 20);

  // Iterate over the desired fieldinfos, calling their fwritefunctions
  // to extract the package's information.
  for (const struct fieldinfo& fip : kfieldinfos) {
    fip.wcall(&vb, pkg, &pkg->installed, fw_printheader, &fip);

    std::string line = vb.string();
    if (!line.empty()) {
      size_t separator_position = line.find(':');

      std::string key = line.substr(0, separator_position);
      std::string value = line.substr(separator_position + 1, line.length());
      auto it = kFieldMappings.find(key);
      if (it != kFieldMappings.end()) {
        boost::algorithm::trim(value);
        r[it->second] = std::move(value);
      }
    }
    varbuf_reset(&vb);
  }
  varbuf_destroy(&vb);

  results.push_back(r);
}

QueryData genDebPackages(QueryContext &context) {
  QueryData results;

  if (!osquery::isDirectory(kDPKGPath)) {
    TLOG << "Cannot find DPKG database: " << kDPKGPath;
    return results;
  }

  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  struct pkg_array packages;
  dpkg_setup(&packages);

  const auto* pk = packages.pkgs;
  for (const auto& pkg : boost::make_iterator_range(pk, pk + packages.n_pkgs)) {
    // Casted to int to allow the older enums that were embeded in the packages
    // struct to be compared
    if (static_cast<int>(pkg->status) ==
        static_cast<int>(PKG_STAT_NOTINSTALLED)) {
      continue;
    }

    extractDebPackageInfo(pkg, results);
  }

  dpkg_teardown(&packages);
  return results;
}
}
}
