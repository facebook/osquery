/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <libaudit.h>

#include <atomic>
#include <condition_variable>
#include <future>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include <boost/algorithm/hex.hpp>

#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

/// Netlink status, used by AuditNetlink::acquireHandle()
enum class NetlinkStatus { ActiveMutable, ActiveImmutable, Disabled, Error };

/// Contains an audit_rule_data structure
using AuditRuleDataObject = std::vector<std::uint8_t>;

/// A single, prepared audit event record.
struct AuditEventRecord final {
  /// Record type (i.e.: AUDIT_SYSCALL, AUDIT_PATH, ...)
  int type;

  /// Event time.
  unsigned long int time;

  /// Audit event id that owns this record. Remember: PRIMARY KEY(id, timestamp)
  std::string audit_id;

  /// The field list for this record. Valid for everything except SELinux and
  /// AppArmor records
  std::map<std::string, std::string> fields;

  /// The raw message, only valid for SELinux and AppArmor records (because they
  /// have broken syntax)
  std::string raw_data;
};

static_assert(std::is_move_constructible<AuditEventRecord>::value,
              "not move constructible");

// This structure is used to share data between the reading and processing
// services
struct AuditdContext final {
  /// Unprocessed audit records
  std::vector<audit_reply> unprocessed_records;
  static_assert(
      std::is_move_constructible<decltype(unprocessed_records)>::value,
      "not move constructible");

  /// Mutex for the list of unprocessed records
  std::mutex unprocessed_records_mutex;

  /// Processed events condition variable
  std::condition_variable unprocessed_records_cv;

  /// This queue contains processed events
  std::vector<AuditEventRecord> processed_events;

  /// Processed events queue mutex.
  std::mutex processed_events_mutex;

  /// Used to wake up the thread that processes the raw audit records
  std::condition_variable processed_records_cv;

  /// When set to true, the audit handle is (re)acquired
  std::atomic_bool acquire_handle{true};
};

using AuditdContextRef = std::shared_ptr<AuditdContext>;

/// This is the service responsible for reading data from the audit netlink
class AuditdNetlinkReader final : public InternalRunnable {
 public:
  explicit AuditdNetlinkReader(AuditdContextRef context);

 protected:
  virtual void start() override;
  virtual void stop() override;

 private:
  /// Reads as many audit event records as possible before returning.
  bool acquireMessages() noexcept;

  /// Configures the audit service and applies required rules
  bool configureAuditService() noexcept;

  /// Clears out the audit configuration
  bool clearAuditConfiguration() noexcept;

  /// Deletes the given audit rule
  bool deleteAuditRule(const AuditRuleDataObject& rule_object);

  /// Removes the rules that we have applied
  void restoreAuditServiceConfiguration() noexcept;

  /// (Re)acquire the netlink handle.
  NetlinkStatus acquireHandle() noexcept;

 private:
  /// Shared data
  AuditdContextRef auditd_context_;

  /// Read buffer used when receiving events from the netlink
  std::vector<audit_reply> read_buffer_;

  /// The set of rules we applied (and that we'll uninstall when exiting)
  std::vector<audit_rule_data> installed_rule_list_;

  /// The syscalls we are listening for
  std::set<int> monitored_syscall_list_;

  /// Netlink handle.
  int audit_netlink_handle_{-1};
};

/// This service parses the raw audit records
class AuditdNetlinkParser final : public InternalRunnable {
 public:
  explicit AuditdNetlinkParser(AuditdContextRef context);
  virtual void start() override;

  /// Parses an audit_reply structure into an AuditEventRecord object
  static bool ParseAuditReply(const audit_reply& reply,
                              AuditEventRecord& event_record) noexcept;

  /// Adjusts the internal pointers of the audit_reply object
  static void AdjustAuditReply(audit_reply& reply) noexcept;

 private:
  /// Shared data
  AuditdContextRef auditd_context_;
};

/// This class provides access to the audit netlink data
class AuditdNetlink final : private boost::noncopyable {
 public:
  AuditdNetlink();
  virtual ~AuditdNetlink();

  /// Prepares the raw audit event records stored in the given context.
  std::vector<AuditEventRecord> getEvents() noexcept;

 private:
  /// Netlink reader service
  std::shared_ptr<AuditdNetlinkReader> reader_service_;

  /// Netlink parser service
  std::shared_ptr<AuditdNetlinkParser> parser_service_;

  /// Shared data
  AuditdContextRef auditd_context_;
};

/// Handle quote and hex-encoded audit field content.
inline std::string DecodeAuditPathValues(const std::string& s) {
  if (s.size() > 1 && s[0] == '"') {
    return s.substr(1, s.size() - 2);
  }

  try {
    return boost::algorithm::unhex(s);
  } catch (const boost::algorithm::hex_decode_error& e) {
    return s;
  }
}
} // namespace osquery
