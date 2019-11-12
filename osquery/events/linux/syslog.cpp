/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <fcntl.h>
#include <grp.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <istream>
#include <string>

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/tokenizer.hpp>
#include <osquery/registry_factory.h>

#include <osquery/filesystem/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/events/linux/syslog.h"

namespace fs = boost::filesystem;

namespace osquery {

FLAG(bool, enable_syslog, false, "Enable the syslog ingestion event publisher");

FLAG(string,
     syslog_pipe_path,
     "/var/osquery/syslog_pipe",
     "Path to the named pipe used for forwarding rsyslog events");

FLAG(uint64,
     syslog_rate_limit,
     100,
     "Maximum number of logs to ingest per run (~200ms between runs)");

REGISTER(SyslogEventPublisher, "event_publisher", "syslog");

// rsyslog needs read/write access, osquery process needs read access
const mode_t kPipeMode = 0460;
const std::string kPipeGroupName = "syslog";
const char* kTimeFormat = "%Y-%m-%dT%H:%M:%S";
const std::vector<std::string> kCsvFields = {
    "time", "host", "severity", "facility", "tag", "message"};
const size_t kErrorThreshold = 10;
static const size_t MAX_LINE_LEN = 16384;

Status SyslogEventPublisher::setUp() {
  if (!FLAGS_enable_syslog) {
    return Status(1, "Publisher disabled via configuration");
  }

  // The pipe file should exist as part of install / config. We create
  // pipe file here if it doesn't exist, but won't receive events until:
  // - the /etc/rsyslog.d/90-osquery.conf file is in place
  // - syslog service is restarted

  Status s;
  if (!pathExists(FLAGS_syslog_pipe_path)) {
    VLOG(1) << "Pipe does not exist: creating pipe " << FLAGS_syslog_pipe_path;
    s = createPipe(FLAGS_syslog_pipe_path);
    if (!s.ok()) {
      LOG(WARNING) << RLOG(1964)
                   << "Problems encountered creating pipe: " << s.getMessage();
    }
  }

  fs::file_status file_status = fs::status(FLAGS_syslog_pipe_path);
  if (file_status.type() != fs::fifo_file) {
    return Status(1, "Not a FIFO file: " + FLAGS_syslog_pipe_path);
  }

  // Try to acquire a lock on the pipe, to make sure we're the only osquery
  // related process reading from it.
  s = lockPipe(FLAGS_syslog_pipe_path);
  if (!s.ok()) {
    return s;
  }

  // The reader buffers bytes read from nonblocking file

  auto spPipe = std::make_unique<NonblockingFileImpl>(FLAGS_syslog_pipe_path);
  if (!spPipe->isValid()) {
    return Status(1,
                  "Error opening pipe for reading: " + FLAGS_syslog_pipe_path);
  }
  VLOG(1) << "Successfully opened pipe for syslog ingestion: "
          << FLAGS_syslog_pipe_path;

  spReader_ =
      std::make_unique<FgetsBuffer>(std::move(spPipe), MAX_LINE_LEN, false);

  return Status::success();
}

Status SyslogEventPublisher::createPipe(const std::string& path) {
  if (mkfifo(FLAGS_syslog_pipe_path.c_str(), kPipeMode) != 0) {
    return Status(1, "Error in mkfifo: " + std::string(strerror(errno)));
  }

  // Explicitly set the permissions since the umask will effect the
  // permissions created by mkfifo
  if (chmod(FLAGS_syslog_pipe_path.c_str(), kPipeMode) != 0) {
    return Status(1, "Error in chmod: " + std::string(strerror(errno)));
  }

  // Try to set the group so that rsyslog will be able to write to the pipe
  struct group* group = getgrnam(kPipeGroupName.c_str());
  if (group == nullptr) {
    VLOG(1) << "No group " << kPipeGroupName
            << " found. Not changing group for the pipe.";
    return Status::success();
  }
  if (chown(FLAGS_syslog_pipe_path.c_str(), -1, group->gr_gid) == -1) {
    return Status(1,
                  "Error in chown to group " + kPipeGroupName + ": " +
                      std::string(strerror(errno)));
  }
  return Status::success();
}

Status SyslogEventPublisher::lockPipe(const std::string& path) {
  lockFd_ = open(path.c_str(), O_NONBLOCK);
  if (lockFd_ == -1) {
    return Status(
        1, "Error in open for locking pipe: " + std::string(strerror(errno)));
  }
  if (flock(lockFd_, LOCK_EX | LOCK_NB) != 0) {
    close(lockFd_);
    lockFd_ = -1;
    return Status(
        1, "Unable to acquire pipe lock: " + std::string(strerror(errno)));
  }
  return Status::success();
}

void SyslogEventPublisher::unlockPipe() {
  if (lockFd_ != -1) {
    if (flock(lockFd_, LOCK_UN) != 0) {
      LOG(WARNING) << "Error unlocking pipe: " << std::string(strerror(errno));
    }
    close(lockFd_);
    lockFd_ = -1;
  }
}

Status SyslogEventPublisher::run() {
  // This run function will be called by the event factory with ~100ms pause
  // (see InterruptableRunnable::pause()) between runs. In case something goes
  // weird and there is a huge amount of input, we limit how many logs we
  // take in per run to avoid pegging the CPU.
  for (size_t i = 0; i < FLAGS_syslog_rate_limit; ++i) {
    std::string line;
    if (spReader_->fgets(line)) {
      return Status();
    }
    auto ec = createEventContext();
    Status status = populateEventContext(line, ec);
    if (status.ok()) {
      fire(ec);
      if (errorCount_ > 0) {
        --errorCount_;
      }
    } else {
      LOG(ERROR) << status.getMessage() << " in line: " << line;
      ++errorCount_;
      if (errorCount_ >= kErrorThreshold) {
        return Status(1, "Too many errors in syslog parsing.");
      }
    }
  }
  return Status::success();
}

void SyslogEventPublisher::tearDown() {
  unlockPipe();
}

Status SyslogEventPublisher::populateEventContext(const std::string& line,
                                                  SyslogEventContextRef& ec) {
  boost::tokenizer<RsyslogCsvSeparator> tokenizer(line);
  auto key = kCsvFields.begin();
  for (std::string value : tokenizer) {
    if (key == kCsvFields.end()) {
      return Status(1, "Received more fields than expected");
    }

    boost::trim(value);
    if (*key == "time") {
      ec->fields["datetime"] = value;
    } else if (*key == "tag" && !value.empty() && value.back() == ':') {
      // rsyslog sends "tag" with a trailing colon that we don't need
      ec->fields.emplace(*key, value.substr(0, value.size() - 1));
    } else {
      ec->fields.emplace(*key, value);
    }
    ++key;
  }

  if (key == kCsvFields.end()) {
    return Status::success();
  } else {
    return Status(1, "Received fewer fields than expected");
  }
}

bool SyslogEventPublisher::shouldFire(const SyslogSubscriptionContextRef& sc,
                                      const SyslogEventContextRef& ec) const {
  return true;
}
} // namespace osquery
