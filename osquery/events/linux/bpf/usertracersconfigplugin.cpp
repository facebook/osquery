/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/usertracersconfigplugin.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

namespace {

const std::string kConfigKey{"user_tracers"};
const std::vector<std::string> kConfigKeyList = {kConfigKey};

} // namespace

REGISTER(UserTracersConfigPlugin, "config_parser", "user_tracers");

std::vector<std::string> UserTracersConfigPlugin::keys() const {
  return kConfigKeyList;
}

Status UserTracersConfigPlugin::update(const std::string& source,
                                       const ParserConfig& config) {
  if (config.count(kConfigKey) == 0U) {
    return Status::failure("The " + kConfigKey +
                           " configuration key is missing");
  }

  const auto& json_config = config.at(kConfigKey).doc();

  TracerConfigurationList new_config_list;
  auto status = parseConfiguration(new_config_list, json_config);
  if (!status.ok()) {
    return status;
  }

  config_list_ = std::move(new_config_list);
  return Status::success();
}

const TracerConfigurationList& UserTracersConfigPlugin::getConfigList() const {
  return config_list_;
}

Status UserTracersConfigPlugin::parseConfiguration(
    TracerConfigurationList& config_list,
    const rapidjson::Document& config_section) {
  config_list.clear();

  if (!config_section.IsArray()) {
    return Status::failure("The " + kConfigKey +
                           " configuration key is not an array");
  }

  const auto& tracer_array = config_section.GetArray();
  std::size_t entry_index{};

  bool failed{false};
  std::unordered_set<std::string> table_name_list;

  for (const auto& tracer : tracer_array) {
    ++entry_index;

    TracerConfiguration tracer_config;
    auto status = parseTracerConfiguration(tracer_config, tracer);
    if (!status.ok()) {
      failed = true;
      LOG(ERROR) << "UserTracersConfigPlugin: Error found in entry #"
                 << entry_index << ": " << status.getMessage();

      continue;
    }

    if (table_name_list.count(tracer_config.table_name) > 0) {
      failed = true;
      LOG(ERROR) << "UserTracersConfigPlugin: Duplicated table name found: "
                 << tracer_config.table_name;

      continue;
    }

    table_name_list.insert(tracer_config.table_name);
    config_list.push_back(std::move(tracer_config));
  }

  if (failed) {
    return Status::failure(
        "One or more invalid configuration entries were found");
  }

  return Status::success();
}

Status UserTracersConfigPlugin::parseTracerConfiguration(
    TracerConfiguration& config, const rapidjson::Value& tracer_config_entry) {
  config = {};

  if (!tracer_config_entry.IsObject()) {
    return Status::failure("Not a JSON object");
  }

  // Table name
  const auto& tracer_config_obj = tracer_config_entry.GetObject();
  if (!tracer_config_obj.HasMember("table_name") ||
      !tracer_config_obj["table_name"].IsString()) {
    return Status::failure(
        "The 'table_name' value is missing or is not a string");
  }

  config.table_name = tracer_config_obj["table_name"].GetString();

  // Binary path, only present for uprobes
  if (tracer_config_obj.HasMember("path")) {
    if (!tracer_config_obj["path"].IsString()) {
      return Status::failure("The 'path' value is not a string");
    }

    config.opt_image_path = tracer_config_obj["path"].GetString();
  }

  // Function (uprobe) or syscall name (kprobe, tracepoint)
  if (!tracer_config_obj.HasMember("function_name") ||
      !tracer_config_obj["function_name"].IsString()) {
    return Status::failure(
        "The 'function_name' value is missing or is not a string");
  }

  config.function_name = tracer_config_obj["function_name"].GetString();

  // Parameter list
  if (!tracer_config_obj.HasMember("parameter_list") ||
      !tracer_config_obj["parameter_list"].IsArray()) {
    return Status::failure(
        "The 'parameter_list' value is missing or is not an array");
  }

  const auto& param_list_array = tracer_config_obj["parameter_list"].GetArray();
  std::size_t param_index{};

  for (const auto& param_obj : param_list_array) {
    ++param_index;

    tob::ebpfpub::IFunctionTracer::Parameter parameter{};

    if (!param_obj.IsObject()) {
      return Status::failure("Parameter #" + std::to_string(param_index) +
                             " is not an object");
    }

    // Parameter name
    if (!param_obj.HasMember("name") || !param_obj["name"].IsString()) {
      return Status::failure("The 'name' value for parameter #" +
                             std::to_string(param_index) +
                             " is missing or is not a string");
    }

    parameter.name = param_obj["name"].GetString();

    // Parameter type
    if (!param_obj.HasMember("type") || !param_obj["type"].IsString()) {
      return Status::failure("The 'type' value for parameter #" +
                             std::to_string(param_index) +
                             " is missing or is not a string");
    }

    std::string param_type{param_obj["type"].GetString()};

    bool needs_value_size{false};
    if (param_type == "Integer") {
      parameter.type = tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer;
      needs_value_size = true;

    } else if (param_type == "IntegerPtr") {
      parameter.type =
          tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr;

      needs_value_size = true;

    } else if (param_type == "Buffer") {
      parameter.type = tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer;
      needs_value_size = true;

    } else if (param_type == "String") {
      parameter.type = tob::ebpfpub::IFunctionTracer::Parameter::Type::String;

    } else if (param_type == "Argv") {
      parameter.type = tob::ebpfpub::IFunctionTracer::Parameter::Type::Argv;

    } else {
      return Status::failure("Parameter #" + std::to_string(param_index) +
                             " contains an invalid type");
    }

    if (needs_value_size != param_obj.HasMember("size")) {
      auto error_message =
          "The 'size' value for parameter #" + std::to_string(param_index);
      if (needs_value_size) {
        error_message += " is missing";
      } else {
        error_message += " is not required";
      }

      return Status::failure(error_message);
    }

    // Parameter size, only required for certain types
    if (needs_value_size) {
      if (!param_obj.HasMember("size") || !param_obj["size"].IsUint64()) {
        return Status::failure("The 'size' value for parameter #" +
                               std::to_string(param_index) +
                               " is missing or is not an integer");
      }

      parameter.opt_size_var = param_obj["size"].GetUint64();
    }

    // Parameter mode
    if (!param_obj.HasMember("mode") || !param_obj["mode"].IsString()) {
      return Status::failure("The 'mode' value for parameter #" +
                             std::to_string(param_index) +
                             " is missing or is not a string");
    }

    std::string param_mode{param_obj["mode"].GetString()};
    if (param_mode == "In") {
      parameter.mode = tob::ebpfpub::IFunctionTracer::Parameter::Mode::In;

    } else if (param_mode == "Out") {
      parameter.mode = tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out;

    } else if (param_mode == "InOut") {
      parameter.mode = tob::ebpfpub::IFunctionTracer::Parameter::Mode::InOut;

    } else {
      return Status::failure("Parameter #" + std::to_string(param_index) +
                             " contains an invalid mode");
    }

    config.parameter_list.push_back(std::move(parameter));
  }

  return Status::success();
}

} // namespace osquery
