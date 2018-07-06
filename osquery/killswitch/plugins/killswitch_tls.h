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

#include "osquery/killswitch/plugins/killswitch_json.h"

namespace osquery {

class TLSKillswitchPlugin;

class TLSKillswitchPlugin
    : public KillswitchJSON,
      public std::enable_shared_from_this<TLSKillswitchPlugin> {
 public:
  Status setUp() override;

 protected:
  virtual Expected<std::string, KillswitchJSON::GetJSONError> getJSON()
      override;
  /// Calculate the URL once and cache the result.
  std::string uri_;
};
} // namespace osquery
