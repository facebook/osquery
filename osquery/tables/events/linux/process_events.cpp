/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <asm/unistd_64.h>

#include <osquery/events/linux/process_events.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
#include <osquery/tables/events/linux/process_events.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
namespace {
const std::unordered_map<int, std::string> kSyscallNameMap = {
    {__NR_execve, "execve"},
    {__NR_execveat, "execveat"},
    {__NR_fork, "fork"},
    {__NR_vfork, "vfork"},
    {__NR_clone, "clone"}};
}

FLAG(bool,
     audit_allow_process_events,
     true,
     "Allow the audit publisher to install process event monitoring rules");

FLAG(bool,
     audit_allow_fork_process_events,
     false,
     "Allow the audit publisher to install process event monitoring rules to "
     "capture fork/vfork/clone system calls");

REGISTER(AuditProcessEventSubscriber, "event_subscriber", "process_events");

Status AuditProcessEventSubscriber::init() {
  if (!FLAGS_audit_allow_process_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&AuditProcessEventSubscriber::Callback, sc);

  return Status::success();
}

Status AuditProcessEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  for (auto& row : emitted_row_list) {
    auto qd = SQL::selectAllFrom("file", "path", EQUALS, row.at("path"));
    row["btime"] = "0";

    if (qd.size() == 1) {
      row["ctime"] = qd.front().at("ctime");
      row["atime"] = qd.front().at("atime");
      row["mtime"] = qd.front().at("mtime");

    } else {
      VLOG(1) << "Failed to acquire the ctime/atime/mtime values for path "
              << row.at("path");

      row["ctime"] = "0";
      row["atime"] = "0";
      row["mtime"] = "0";
    }
  }

  addBatch(emitted_row_list);
  return Status::success();
}

Status AuditProcessEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  // clang-format off
  /*
    execve (59)
    1300 audit(1502125323.756:6): arch=c000003e syscall=59 success=yes exit=0 a0=23eb8e0 a1=23ebbc0 a2=23c9860 a3=7ffe18d32ed0 items=2 ppid=6882 pid=7841 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=2 comm="sh" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
    1309 audit(1502125323.756:6): argc=1 a0="sh"
    1307 audit(1502125323.756:6):  cwd="/home/alessandro"
    1302 audit(1502125323.756:6): item=0 name="/usr/bin/sh" inode=18867 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:shell_exec_t:s0 objtype=NORMAL
    1302 audit(1502125323.756:6): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=33604032 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL
    1320 audit(1502125323.756:6):

    execveat (322)
    1300, audit(1565728125.289:26): arch=c000003e syscall=322 success=yes exit=0 a0=3 a1=5627914857d5 a2=0 a3=0 items=2 ppid=31922 pid=29003 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts2 ses=4294967295 comm="fork" exe="/home/alessandro/fork" key=(null)
    1309, audit(1565728125.289:26): argc=0 a0="/dev/fd/3/fork"
    1307, audit(1565728125.289:26): cwd="/home/alessandro"
    1302, audit(1565728125.289:26): item=0 name="fork" inode=1440185 dev=00:32 mode=0100775 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
    1302, audit(1565728125.289:26): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=6763 dev=00:19 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
    1327, audit(1565728125.289:26): proctitle="./execveat"
    1320, audit(1565728125.289:26):

    fork (57), clone (56), vfork (58)
    1300 audit(1565629510.716:246170): arch=c000003e syscall=57 success=yes exit=13733 a0=7fff45d30a68 a1=7fff45d30a78 a2=55a2507aa680 a3=7f92b823cd80 items=0 ppid=9680 pid=13732 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=4294967295 comm="fork" exe="/home/alessandro/fork" key=(null)
    1327 audit(1565629510.716:246170): proctitle="./fork"
    1320 audit(1565629510.716:246170):
  */
  // clang-format on

  emitted_row_list.clear();
  emitted_row_list.reserve(event_list.size());

  for (const auto& event : event_list) {
    // Make sure this is a syscall event that we are interested in
    if (event.type != AuditEvent::Type::Syscall) {
      continue;
    }

    const auto& event_data = boost::get<SyscallAuditEventData>(event.data);
    if (kExecProcessEventsSyscalls.count(event_data.syscall_number) == 0U &&
        kForkProcessEventsSyscalls.count(event_data.syscall_number) == 0U) {
      continue;
    }

    // Acquire the base syscall record, which is common to all the different
    // events we are handling here
    const AuditEventRecord* syscall_event_record =
        GetEventRecord(event, AUDIT_SYSCALL);

    if (syscall_event_record == nullptr) {
      VLOG(1) << "Malformed AUDIT_SYSCALL event";
      continue;
    }

    // Skip threads created with the CLONE_THREAD flag of the clone() system
    // call
    bool is_thread = false;
    auto status = IsThreadClone(
        is_thread, event_data.syscall_number, *syscall_event_record);
    if (!status.ok()) {
      VLOG(1) << "Malformed AUDIT_SYSCALL event: " << status.getMessage();
      continue;
    }

    if (is_thread) {
      continue;
    }

    // Generate basic row contents
    Row row = {};
    row["uptime"] = std::to_string(getUptime());

    CopyFieldFromMap(row, syscall_event_record->fields, "auid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "pid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "uid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "euid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "gid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "egid", "0");

    if (!GetSyscallName(row["syscall"], event_data.syscall_number)) {
      row["syscall"] = std::to_string(event_data.syscall_number);

      VLOG(1) << "Failed to locate the system call name";
    }

    std::uint64_t parent_process_id;
    GetIntegerFieldFromMap(
        parent_process_id, syscall_event_record->fields, "ppid");
    row["parent"] = std::to_string(parent_process_id);

    std::string field_value;
    GetStringFieldFromMap(field_value, syscall_event_record->fields, "exe", "");
    row["path"] = DecodeAuditPathValues(field_value);

    // Unused fields
    row["overflows"] = "";
    row["env"] = "";
    row["env_size"] = "0";
    row["env_count"] = "0";

    // Handle syscall-specific data
    if (kExecProcessEventsSyscalls.count(event_data.syscall_number) > 0U) {
      auto status = ProcessExecveEventData(row, event);
      if (!status) {
        VLOG(1) << "Failed to parse the event: " << status.getMessage();
        continue;
      }

    } else {
      row["owner_uid"] = "0";
      row["owner_gid"] = "0";
    }

    emitted_row_list.push_back(row);
  }

  return Status::success();
}

Status AuditProcessEventSubscriber::ProcessExecveEventData(
    Row& row, const AuditEvent& event) noexcept {
  // Get the initial working directory of the process
  const AuditEventRecord* cwd_event_record = GetEventRecord(event, AUDIT_CWD);
  if (cwd_event_record == nullptr) {
    return Status::failure("Malformed AUDIT_CWD event");
  }

  CopyFieldFromMap(row, cwd_event_record->fields, "cwd", "");

  // Save the command line parameters
  const AuditEventRecord* execve_event_record =
      GetEventRecord(event, AUDIT_EXECVE);

  if (execve_event_record == nullptr) {
    return Status::failure("Malformed AUDIT_EXECVE event");
  }

  row["cmdline"] = "";

  for (const auto& arg : execve_event_record->fields) {
    if (arg.first == "argc") {
      continue;
    }

    if (row.at("cmdline").size() > 0) {
      row["cmdline"] += " ";
    }

    row["cmdline"] += DecodeAuditPathValues(arg.second);
  }

  row["cmdline_size"] = std::to_string(row.at("cmdline").size());

  // Get the remaining data from the first AUDIT_PATH record
  const AuditEventRecord* first_path_event_record =
      GetEventRecord(event, AUDIT_PATH);

  if (first_path_event_record == nullptr) {
    return Status::failure("Malformed AUDIT_PATH event");
  }

  CopyFieldFromMap(row, first_path_event_record->fields, "mode", "");

  GetStringFieldFromMap(
      row["owner_uid"], first_path_event_record->fields, "ouid", "0");

  GetStringFieldFromMap(
      row["owner_gid"], first_path_event_record->fields, "ogid", "0");

  return Status::success();
}

Status AuditProcessEventSubscriber::IsThreadClone(
    bool& is_thread_clone,
    int syscall_nr,
    const AuditEventRecord& syscall_record) noexcept {
  is_thread_clone = false;

  if (syscall_record.type != AUDIT_SYSCALL) {
    return Status::failure("Invalid record type");
  }

  if (syscall_nr != __NR_clone) {
    return Status::success();
  }

  std::uint64_t clone_flags;
  GetIntegerFieldFromMap(clone_flags, syscall_record.fields, "a0", 16U);

  is_thread_clone = (clone_flags & CLONE_THREAD) != 0U;
  return Status::success();
}

bool AuditProcessEventSubscriber::GetSyscallName(std::string& name,
                                                 int syscall_nr) noexcept {
  name.clear();

  auto it = kSyscallNameMap.find(syscall_nr);
  if (it == kSyscallNameMap.end()) {
    return false;
  }

  name = it->second;
  return true;
}

const std::unordered_map<int, std::string>&
AuditProcessEventSubscriber::GetSyscallNameMap() noexcept {
  return kSyscallNameMap;
}
} // namespace osquery
