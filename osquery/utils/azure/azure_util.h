/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <boost/property_tree/ptree.hpp>
#include <osquery/utils/status/status.h>

namespace pt = boost::property_tree;

namespace osquery {

std::string tree_get(pt::ptree& tree, const std::string key);

Status fetchAzureMetadata(pt::ptree& tree);

} // namespace osquery
