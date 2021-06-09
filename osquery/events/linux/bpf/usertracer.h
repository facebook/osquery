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
#include <osquery/events/linux/bpf/usertracersconfigplugin.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/expected/expected.h>

#include <ebpfpub/iperfeventreader.h>

#include <map>
#include <memory>
#include <optional>

namespace osquery {

class UserTracer final : public TablePlugin {
 public:
  enum class ErrorCode {
    MemoryAllocationFailure,
    BufferStorageError,
    PerfEventArrayError,
    PerfEventReaderError,
    FunctionTracerError,
  };

  using Ptr = std::shared_ptr<UserTracer>;
  static Expected<Ptr, ErrorCode> create(
      const TracerConfiguration& configuration);

  virtual ~UserTracer() override;

  const std::string& name() const;
  void processEvents();

  UserTracer(const UserTracer&) = delete;
  UserTracer& operator=(const UserTracer&) = delete;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  UserTracer(TracerConfiguration configuration);

  virtual TableColumns columns() const override;
  virtual TableRows generate(QueryContext& context) override;

 public:
  static Expected<TableColumns, ErrorCode> generateTableSchema(
      const TracerConfiguration& configuration);

  static bool getFieldValue(
      osquery::DynamicTableRowHolder& row,
      const tob::ebpfpub::IFunctionTracer::Event::Field& field,
      const std::string& column_name);

  using EventQueue =
      std::map<std::uint64_t, tob::ebpfpub::IFunctionTracer::Event>;

  static TableRows parseEvents(const EventQueue& event_queue);

  template <typename KeyType, typename ValueType>
  static void limitMapSize(std::map<KeyType, ValueType>& map,
                           std::size_t max_elem_count) {
    if (map.size() <= max_elem_count) {
      return;
    }

    auto it = std::next(map.begin(), map.size() - max_elem_count);
    map.erase(map.begin(), it);
  }
};

} // namespace osquery
