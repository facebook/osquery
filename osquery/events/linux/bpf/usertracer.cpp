/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/linux/bpf/usertracer.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/mutex.h>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/ifunctiontracer.h>
#include <tob/ebpf/perfeventarray.h>

namespace osquery {

namespace {
#ifdef __aarch64__
static const std::string kKprobeSyscallPrefix{"__arm64_sys_"};

#elif __amd64__
static const std::string kKprobeSyscallPrefix{"__x64_sys_"};

#else
#error Unsupported architecture
#endif

} // namespace

FLAG(uint64,
     bpf_max_user_tracer_rows,
     1024ULL,
     "The maximum number of rows to store in memory");

struct UserTracer::PrivateData final {
  TracerConfiguration configuration;
  TableColumns table_schema;

  tob::ebpfpub::IBufferStorage::Ref buffer_storage;
  tob::ebpf::PerfEventArray::Ref perf_event_array;
  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;

  Mutex event_queue_mutex;
  EventQueue event_queue;
};

Expected<UserTracer::Ptr, UserTracer::ErrorCode> UserTracer::create(
    const TracerConfiguration& configuration) {
  try {
    return Ptr(new UserTracer(std::move(configuration)));

  } catch (const std::bad_alloc&) {
    return createError(ErrorCode::MemoryAllocationFailure);

  } catch (const ErrorCode& error_code) {
    return createError(error_code);
  }
}

UserTracer::~UserTracer() {}

const std::string& UserTracer::name() const {
  return d->configuration.table_name;
}

void UserTracer::processEvents() {
  tob::ebpfpub::IPerfEventReader::ErrorCounters error_counters{};

  d->perf_event_reader->exec(
      std::chrono::seconds(1U),

      [&](const tob::ebpfpub::IFunctionTracer::EventList& event_list,
          const tob::ebpfpub::IPerfEventReader::ErrorCounters&
              new_error_counters) {
        error_counters.invalid_event += new_error_counters.invalid_event;
        error_counters.lost_events += new_error_counters.lost_events;

        error_counters.invalid_probe_output +=
            new_error_counters.invalid_probe_output;

        error_counters.invalid_event_data +=
            new_error_counters.invalid_event_data;

        WriteLock lock(d->event_queue_mutex);

        for (auto& event : event_list) {
          auto rel_timestamp = event.header.timestamp;
          d->event_queue.insert({rel_timestamp, std::move(event)});
        }

        limitMapSize(d->event_queue, FLAGS_bpf_max_user_tracer_rows);
      });
}

UserTracer::UserTracer(TracerConfiguration configuration) : d(new PrivateData) {
  d->configuration = std::move(configuration);

  auto table_schema_exp = generateTableSchema(d->configuration);
  if (table_schema_exp.isError()) {
    auto error = table_schema_exp.takeError();
    LOG(ERROR) << error.getMessage();

    throw error.getErrorCode();
  }

  d->table_schema = table_schema_exp.take();

  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(1024, 4096);
  if (!buffer_storage_exp.succeeded()) {
    LOG(ERROR) << "Failed to create the buffer storage: "
               << buffer_storage_exp.error().message();

    throw ErrorCode::BufferStorageError;
  }

  d->buffer_storage = buffer_storage_exp.takeValue();

  auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(12);
  if (!perf_event_array_exp.succeeded()) {
    LOG(ERROR) << "Failed to create the perf event array: "
               << perf_event_array_exp.error().message();

    throw ErrorCode::PerfEventArrayError;
  }

  d->perf_event_array = perf_event_array_exp.takeValue();

  auto perf_event_reader_exp =
      tob::ebpfpub::IPerfEventReader::create(*d->perf_event_array.get());

  if (!perf_event_reader_exp.succeeded()) {
    LOG(ERROR) << "Failed to create the perf event reader: "
               << perf_event_reader_exp.error().message();

    throw ErrorCode::PerfEventReaderError;
  }

  d->perf_event_reader = perf_event_reader_exp.takeValue();

  tob::StringErrorOr<tob::ebpfpub::IFunctionTracer::Ref> function_tracer_exp;

  if (d->configuration.opt_image_path.has_value()) {
    const auto& image_path = d->configuration.opt_image_path.value();

    function_tracer_exp = tob::ebpfpub::IFunctionTracer::createFromUprobe(
        d->configuration.function_name,
        image_path,
        d->configuration.parameter_list,
        *d->buffer_storage.get(),
        *d->perf_event_array.get(),
        1024);

  } else {
    function_tracer_exp = tob::ebpfpub::IFunctionTracer::createFromKprobe(
        kKprobeSyscallPrefix + d->configuration.function_name,
        d->configuration.parameter_list,
        *d->buffer_storage.get(),
        *d->perf_event_array.get(),
        1024);
  }

  if (!function_tracer_exp.succeeded()) {
    LOG(ERROR) << "Failed to create the function tracer: "
               << function_tracer_exp.error().message();

    throw ErrorCode::FunctionTracerError;
  }

  auto function_tracer = function_tracer_exp.takeValue();
  d->perf_event_reader->insert(std::move(function_tracer));
}

TableColumns UserTracer::columns() const {
  return d->table_schema;
}

TableRows UserTracer::generate(QueryContext& context) {
  std::map<std::uint64_t, tob::ebpfpub::IFunctionTracer::Event> event_queue;

  {
    WriteLock lock(d->event_queue_mutex);

    event_queue = std::move(d->event_queue);
    d->event_queue.clear();
  }

  return parseEvents(event_queue);
}

Expected<TableColumns, UserTracer::ErrorCode> UserTracer::generateTableSchema(
    const TracerConfiguration& configuration) {
  TableColumns column_list = {
      std::make_tuple("timestamp", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("tid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("pid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("uid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("gid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("cid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("exit_code", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("probe_error", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("duration", INTEGER_TYPE, ColumnOptions::DEFAULT),
  };

  for (const auto& parameter : configuration.parameter_list) {
    ColumnType column_type{};

    switch (parameter.type) {
    case tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer:
    case tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr:
      column_type = INTEGER_TYPE;
      break;

    case tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer:
    case tob::ebpfpub::IFunctionTracer::Parameter::Type::String:
    case tob::ebpfpub::IFunctionTracer::Parameter::Type::Argv:
      column_type = TEXT_TYPE;
      break;
    }

    // Remap the special ebpfpub "EXIT_CODE" name to "return_value" since we
    // already have the raw exit code in the schema
    auto parameter_name = parameter.name;
    if (parameter_name == "EXIT_CODE") {
      parameter_name = "return_value";
    }

    if (parameter.mode ==
        tob::ebpfpub::IFunctionTracer::Parameter::Mode::InOut) {
      column_list.push_back(std::make_tuple(
          parameter_name + "_in", column_type, ColumnOptions::DEFAULT));

      column_list.push_back(std::make_tuple(
          parameter_name + "_out", column_type, ColumnOptions::DEFAULT));

    } else {
      column_list.push_back(
          std::make_tuple(parameter_name, column_type, ColumnOptions::DEFAULT));
    }
  }

  return column_list;
}

bool UserTracer::getFieldValue(
    osquery::DynamicTableRowHolder& row,
    const tob::ebpfpub::IFunctionTracer::Event::Field& field,
    const std::string& column_name) {
  if (std::holds_alternative<std::uint64_t>(field.data_var)) {
    row[column_name] = INTEGER(std::get<std::uint64_t>(field.data_var));
    return true;

  } else if (std::holds_alternative<std::vector<std::uint8_t>>(
                 field.data_var)) {
    std::stringstream output;
    output.width(2U);
    output.fill('0');

    const auto& buffer = std::get<std::vector<std::uint8_t>>(field.data_var);

    for (auto byte : buffer) {
      output << static_cast<int>(byte);
    }

    row[column_name] = SQL_TEXT(output.str());
    return true;

  } else if (std::holds_alternative<std::string>(field.data_var)) {
    row[column_name] = SQL_TEXT(std::get<std::string>(field.data_var));
    return true;

  } else if (std::holds_alternative<std::vector<std::string>>(field.data_var)) {
    const auto& string_list =
        std::get<std::vector<std::string>>(field.data_var);

    std::string output;
    for (const auto& str : string_list) {
      if (!output.empty()) {
        output += ", ";
      }

      output += str;
    }

    row[column_name] = SQL_TEXT(output);
    return true;
  }

  return false;
}

TableRows UserTracer::parseEvents(const EventQueue& event_queue) {
  TableRows output;

  for (const auto& event_queue_p : event_queue) {
    const auto& event = event_queue_p.second;

    auto row = make_table_row();
    row["timestamp"] = SQL_TEXT(std::to_string(event.header.timestamp));
    row["tid"] = INTEGER(event.header.thread_id);
    row["pid"] = INTEGER(event.header.process_id);
    row["uid"] = INTEGER(event.header.user_id);
    row["gid"] = INTEGER(event.header.group_id);
    row["cid"] = INTEGER(event.header.cgroup_id);
    row["exit_code"] = SQL_TEXT(std::to_string(event.header.exit_code));
    row["probe_error"] = INTEGER(event.header.probe_error);
    row["duration"] = INTEGER(event.header.duration);

    for (const auto& field_p : event.in_field_map) {
      auto column_name = field_p.first;
      if (event.out_field_map.count(column_name) > 0U) {
        column_name += "_in";
      }

      const auto& field = field_p.second;
      if (!getFieldValue(row, field, column_name)) {
        LOG(ERROR) << "Invalid data variant";
      }
    }

    for (const auto& field_p : event.out_field_map) {
      auto column_name = field_p.first;
      if (event.in_field_map.count(column_name) > 0U) {
        column_name += "_out";
      }

      if (column_name == "EXIT_CODE") {
        column_name = "return_value";
      }

      const auto& field = field_p.second;
      if (!getFieldValue(row, field, column_name)) {
        LOG(ERROR) << "Invalid data variant";
      }
    }

    output.push_back(std::move(row));
  }

  return output;
}

} // namespace osquery
