/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <array>

#include <osquery/core/flags.h>
#include <osquery/events/linux/apparmor_events.h>
#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/events/linux/selinux_events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {

// External flags; they are used to determine whether we should run or not
DECLARE_bool(disable_audit);
DECLARE_bool(audit_allow_fim_events);
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);
DECLARE_bool(audit_allow_user_events);
DECLARE_bool(audit_allow_selinux_events);
DECLARE_bool(audit_allow_kill_process_events);
DECLARE_bool(audit_allow_apparmor_events);
DECLARE_bool(audit_allow_seccomp_events);

REGISTER(AuditEventPublisher, "event_publisher", "auditeventpublisher");

namespace {

const std::string kAppArmorEventMarker{"apparmor"};

bool IsPublisherEnabled() noexcept {
  if (FLAGS_disable_audit) {
    return false;
  }

  return (FLAGS_audit_allow_fim_events || FLAGS_audit_allow_process_events ||
          FLAGS_audit_allow_sockets || FLAGS_audit_allow_user_events ||
          FLAGS_audit_allow_selinux_events ||
          FLAGS_audit_allow_kill_process_events ||
          FLAGS_audit_allow_apparmor_events ||
          FLAGS_audit_allow_seccomp_events);
}
} // namespace

std::string AuditEventPublisher::executable_path_;

Status AuditEventPublisher::setUp() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Publisher disabled via configuration");
  }

  if (executable_path_.empty()) {
    char buffer[PATH_MAX] = {};
    assert(readlink("/proc/self/exe", buffer, sizeof(buffer)) != -1);
    executable_path_ = buffer;
  }

  return Status::success();
}

void AuditEventPublisher::configure() {
  if (!IsPublisherEnabled()) {
    audit_netlink_.reset();

  } else if (audit_netlink_ == nullptr) {
    audit_netlink_ = std::make_unique<AuditdNetlink>();
  }
}

void AuditEventPublisher::tearDown() {}

Status AuditEventPublisher::run() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Publisher disabled via configuration");
  }

  auto audit_event_record_queue = audit_netlink_->getEvents();

  auto event_context = createEventContext();

  // This is a simple estimate based on the process_file_events_tests.cpp
  // records
  auto event_count_estimate = audit_event_record_queue.size() / 4U;
  event_context->audit_events.reserve(event_count_estimate);

  ProcessEvents(event_context, audit_event_record_queue, audit_trace_context_);
  if (!event_context->audit_events.empty()) {
    fire(event_context);
  }

  return Status::success();
}

void AuditEventPublisher::ProcessEvents(
    AuditEventContextRef event_context,
    const std::vector<AuditEventRecord>& record_list,
    AuditTraceContext& trace_context) noexcept {
  static const auto& selinux_event_set = kSELinuxEventList;

  // Assemble each record into a AuditEvent object; multi-record events
  // are complete when we receive the terminator (AUDIT_EOE)
  for (const auto& audit_event_record : record_list) {
    auto audit_event_it = trace_context.find(audit_event_record.audit_id);

    // We have two entry points here; the first one is for user messages, while
    // the second one is for syscalls
    if (audit_event_record.type >= AUDIT_FIRST_USER_MSG &&
        audit_event_record.type <= AUDIT_LAST_USER_MSG) {
      UserAuditEventData data = {};
      data.user_event_id = static_cast<std::uint64_t>(audit_event_record.type);

      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::UserEvent;
      audit_event.record_list.push_back(std::move(audit_event_record));
      audit_event.data = data;

      event_context->audit_events.push_back(audit_event);

      // SELinux or AppArmor events
    } else if (selinux_event_set.find(audit_event_record.type) !=
               selinux_event_set.end()) {
      if (audit_event_record.fields.find(kAppArmorEventMarker) ==
          audit_event_record.fields.end()) {
        // Pure SELinux Event

        AuditEvent audit_event;
        audit_event.type = AuditEvent::Type::SELinux;
        audit_event.record_list.push_back(audit_event_record);

        event_context->audit_events.push_back(audit_event);
      } else {
        // We've got an AppArmor event
        AppArmorAuditEventData data;

        for (auto& field : data.fields) {
          switch (field.second.which()) {
          case 0: {
            // string field
            std::string value = "";
            field.second =
                StripQuotes(GetStringFieldFromMap(
                                value, audit_event_record.fields, field.first)
                                ? value
                                : "");
            break;
          }
          case 1: {
            // int field
            std::uint64_t value = 0;
            field.second = GetIntegerFieldFromMap(
                               value, audit_event_record.fields, field.first)
                               ? value
                               : 0;
            break;
          }
          }
        }

        if (boost::get<std::string>(data.fields["apparmor"]).empty()) {
          VLOG(1) << "AUDIT_APPARMOR record is malformed";
          continue;
        }

        AuditEvent audit_event;
        audit_event.type = AuditEvent::Type::AppArmor;
        audit_event.record_list.push_back(audit_event_record);
        audit_event.data = data;
        event_context->audit_events.push_back(audit_event);
      }

      // Seccomp events
    } else if (audit_event_record.type == AUDIT_SECCOMP) {
      SeccompAuditEventData data;

      parseSeccompEvent(audit_event_record, data);

      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::Seccomp;
      audit_event.data = data;
      audit_event.record_list.push_back(audit_event_record);
      event_context->audit_events.push_back(audit_event);

    } else if (audit_event_record.type == AUDIT_SYSCALL) {
      if (audit_event_it != trace_context.end()) {
        VLOG(1) << "Received a duplicated event.";
        trace_context.erase(audit_event_it);
      }

      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::Syscall;

      // Estimate based on the process_file_events_tests.cpp records
      audit_event.record_list.reserve(4U);

      SyscallAuditEventData data;

      std::string raw_executable_path;
      if (!GetStringFieldFromMap(
              raw_executable_path, audit_event_record.fields, "exe")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
                   "executable path field is either missing or not valid.";

        continue;
      }

      data.executable_path = DecodeAuditPathValues(raw_executable_path);

      // Do not process events originated by the osquery watchdog or daemon
      if (executable_path_ == data.executable_path) {
        continue;
      }

      if (!GetIntegerFieldFromMap(
              data.syscall_number, audit_event_record.fields, "syscall")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
                   "syscall field "
                   "is either missing or not valid.";

        continue;
      }

      std::string syscall_status;
      GetStringFieldFromMap(
          syscall_status, audit_event_record.fields, "success", "yes");

      // By discarding this event, we will also automatically discard any other
      // attached record
      if (syscall_status != "yes") {
        continue;
      }

      std::uint64_t process_id;
      if (!GetIntegerFieldFromMap(
              process_id, audit_event_record.fields, "pid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The process id "
                   "field is either missing or not valid.";

        continue;
      }

      std::uint64_t parent_process_id;
      if (!GetIntegerFieldFromMap(
              parent_process_id, audit_event_record.fields, "ppid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The parent "
                   "process id field is either missing or not valid.";

        continue;
      }

      data.process_id = static_cast<pid_t>(process_id);
      data.parent_process_id = static_cast<pid_t>(parent_process_id);
      audit_event.data = data;

      std::uint64_t process_uid;
      if (!GetIntegerFieldFromMap(
              process_uid, audit_event_record.fields, "uid")) {
        VLOG(1) << "Missing or invalid uid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_auid;
      if (!GetIntegerFieldFromMap(
              process_auid, audit_event_record.fields, "auid")) {
        VLOG(1) << "Missing or invalid auid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_euid;
      if (!GetIntegerFieldFromMap(
              process_euid, audit_event_record.fields, "euid")) {
        VLOG(1) << "Missing or invalid euid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_fsuid;
      if (!GetIntegerFieldFromMap(
              process_fsuid, audit_event_record.fields, "fsuid")) {
        VLOG(1) << "Missing or invalid fsuid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_suid;
      if (!GetIntegerFieldFromMap(
              process_suid, audit_event_record.fields, "suid")) {
        VLOG(1) << "Missing or invalid suid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_gid;
      if (!GetIntegerFieldFromMap(
              process_gid, audit_event_record.fields, "gid")) {
        VLOG(1) << "Missing or invalid gid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_egid;
      if (!GetIntegerFieldFromMap(
              process_egid, audit_event_record.fields, "egid")) {
        VLOG(1) << "Missing or invalid egid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_fsgid;
      if (!GetIntegerFieldFromMap(
              process_fsgid, audit_event_record.fields, "fsgid")) {
        VLOG(1) << "Missing or invalid fsgid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_sgid;
      if (!GetIntegerFieldFromMap(
              process_sgid, audit_event_record.fields, "sgid")) {
        VLOG(1) << "Missing or invalid sgid field in AUDIT_SYSCALL";

        continue;
      }

      data.process_uid = static_cast<uid_t>(process_uid);
      data.process_auid = static_cast<uid_t>(process_auid);
      data.process_euid = static_cast<uid_t>(process_euid);
      data.process_fsuid = static_cast<uid_t>(process_fsuid);
      data.process_suid = static_cast<uid_t>(process_suid);
      data.process_gid = static_cast<gid_t>(process_gid);
      data.process_egid = static_cast<gid_t>(process_egid);
      data.process_fsgid = static_cast<gid_t>(process_fsgid);
      data.process_sgid = static_cast<gid_t>(process_sgid);

      audit_event.record_list.push_back(audit_event_record);
      trace_context[audit_event_record.audit_id] = std::move(audit_event);

      // This is the terminator for multi-record audit events
    } else if (audit_event_record.type == AUDIT_EOE) {
      if (audit_event_it == trace_context.end()) {
        continue;
      }

      auto completed_audit_event = audit_event_it->second;
      trace_context.erase(audit_event_it);

      event_context->audit_events.push_back(std::move(completed_audit_event));

    } else {
      if (audit_event_it == trace_context.end()) {
        continue;
      }

      audit_event_it->second.record_list.push_back(audit_event_record);
    }
  }

  // Drop events that are older than 5 minutes; it means that we have failed to
  // receive the end of record and will never complete them correctly

  std::time_t current_time;
  std::time(&current_time);

  std::unordered_map<std::string, std::time_t> timestamp_cache;

  // The first part of the audit id is a timestamp: 1501323932.710:7670542
  for (auto event_it = trace_context.begin();
       event_it != trace_context.end();) {
    const auto& audit_event_id = event_it->first;
    std::time_t event_timestamp;

    auto timestamp_it = timestamp_cache.find(audit_event_id);
    if (timestamp_it == timestamp_cache.end()) {
      std::string string_timestamp = audit_event_id.substr(0, 10);

      event_timestamp = tryTo<long long>(string_timestamp).takeOr(0ll);

      timestamp_cache[audit_event_id] = event_timestamp;

    } else {
      event_timestamp = timestamp_it->second;
    }

    if (current_time - event_timestamp >= 300) {
      event_it = trace_context.erase(event_it);
    } else {
      event_it++;
    }
  }
}

const AuditEventRecord* GetEventRecord(const AuditEvent& event,
                                       int record_type) noexcept {
  auto it = std::find_if(event.record_list.begin(),
                         event.record_list.end(),
                         [record_type](const AuditEventRecord& record) -> bool {
                           return (record.type == record_type);
                         });

  if (it == event.record_list.end()) {
    return nullptr;
  }

  return &(*it);
};

bool GetStringFieldFromMap(std::string& value,
                           const std::map<std::string, std::string>& fields,
                           const std::string& name,
                           const std::string& default_value) noexcept {
  auto it = fields.find(name);
  if (it == fields.end()) {
    value = default_value;
    return false;
  }

  value = it->second;
  return true;
}

bool GetIntegerFieldFromMap(std::uint64_t& value,
                            const std::map<std::string, std::string>& field_map,
                            const std::string& field_name,
                            std::size_t base,
                            std::uint64_t default_value) noexcept {
  std::string string_value;
  if (!GetStringFieldFromMap(string_value, field_map, field_name, "")) {
    value = default_value;
    return false;
  }
  auto exp = tryTo<std::uint64_t>(string_value, base);
  value = exp.takeOr(std::move(default_value));
  return exp.isValue();
}

void CopyFieldFromMap(Row& row,
                      const std::map<std::string, std::string>& fields,
                      const std::string& name,
                      const std::string& default_value) noexcept {
  GetStringFieldFromMap(row[name], fields, name, default_value);
}

std::string StripQuotes(const std::string& value) noexcept {
  if (value.length() >= 3 && value[0] == '\"' &&
      value[value.length() - 1] == '\"') {
    return value.substr(1, value.length() - 2);
  } else {
    return value;
  }
}

void parseSeccompEvent(const AuditEventRecord& record,
                       SeccompAuditEventData& data) noexcept {
  // Fill SeccompAuditEventData structure with data from audit_event_record
  for (auto& field : data.fields) {
    switch (field.second.which()) {
    case 0: {
      // string field
      std::string value = "";
      field.second =
          GetStringFieldFromMap(value, record.fields, field.first) ? value : "";
      break;
    }
    case 1: {
      // int field
      std::uint64_t value = 0;
      int base = 10;
      if (field.first == "arch" || field.first == "code") {
        base = 16;
      }
      field.second =
          GetIntegerFieldFromMap(value, record.fields, field.first, base)
              ? value
              : 0;
      break;
    }
    }
  }
}

} // namespace osquery
