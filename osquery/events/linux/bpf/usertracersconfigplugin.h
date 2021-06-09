/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <osquery/config/config.h>

#include <ebpfpub/ifunctiontracer.h>

namespace osquery {

struct TracerConfiguration final {
  std::string table_name;
  std::optional<std::string> opt_image_path;
  std::string function_name;
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list;
};

using TracerConfigurationList = std::vector<TracerConfiguration>;

class UserTracersConfigPlugin : public ConfigParserPlugin {
 public:
  virtual std::vector<std::string> keys() const override;
  virtual Status update(const std::string& source,
                        const ParserConfig& config) override;

  const TracerConfigurationList& getConfigList() const;

  static Status parseConfiguration(TracerConfigurationList& config_list,
                                   const rapidjson::Document& config_section);

  static Status parseTracerConfiguration(
      TracerConfiguration& config, const rapidjson::Value& tracer_config_entry);

 private:
  TracerConfigurationList config_list_;
};

} // namespace osquery
