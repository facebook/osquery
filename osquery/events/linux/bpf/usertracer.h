/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/expected/expected.h>

#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <map>
#include <memory>

namespace osquery {

class UserTracer final : public TablePlugin {
 public:
  enum class ErrorCode {
    MemoryAllocationFailure,
    InvalidJSONConfiguration,
    InvalidConfigurationSyntax,
    InvalidSchema,
    BufferStorageError,
    PerfEventArrayError,
    PerfEventReaderError,
    FunctionTracerError,
  };

  using Ptr = std::shared_ptr<UserTracer>;
  static Expected<Ptr, ErrorCode> create(const std::string& configuration);

  ~UserTracer();

  const std::string& name() const;
  void processEvents();

  UserTracer(const UserTracer&) = delete;
  UserTracer& operator=(const UserTracer&) = delete;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  UserTracer(const std::string& configuration);

  virtual TableColumns columns() const override;
  virtual TableRows generate(QueryContext& context) override;

 public:
  struct Configuration final {
    std::string table_name;
    std::optional<std::string> opt_image_path;
    std::string function_name;
    tob::ebpfpub::IFunctionTracer::ParameterList parameter_list;
  };

  static Expected<Configuration, ErrorCode> parseConfiguration(
      const std::string& configuration);

  static Expected<TableColumns, ErrorCode> generateTableSchema(
      const Configuration& configuration);

  static bool getFieldValue(
      osquery::DynamicTableRowHolder& row,
      const tob::ebpfpub::IFunctionTracer::Event::Field& field,
      const std::string& column_name);

  using EventQueue =
      std::map<std::uint64_t, tob::ebpfpub::IFunctionTracer::Event>;

  static TableRows parseEvents(const EventQueue& event_queue);
};

} // namespace osquery
