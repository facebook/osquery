/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <map>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <boost/functional/hash.hpp>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/conversions.h"
#include "osquery/core/utils.h"
#include "osquery/events/windows/ntfs_event_publisher.h"

namespace osquery {
FLAG(bool,
     enable_ntfs_event_publisher,
     false,
     "Enables the NTFS event publiser");

/// This debug flag will print the incoming events
HIDDEN_FLAG(bool,
            ntfs_event_publisher_debug,
            false,
            "Debug the NTFS event publisher");

REGISTER(NTFSEventPublisher, "event_publisher", "ntfseventspublisher");

namespace fs = boost::filesystem;

namespace {
/// This structure is used for the internal components cache
struct NodeReferenceInfo final {
  USNFileReferenceNumber parent;
  std::string name;
};
}

struct NTFSEventPublisher::PrivateData final {
  /// Each reader service instance is mapped to the drive letter it is
  /// reading from
  std::unordered_map<char, USNJournalReaderInstance> reader_service_map;

  /// This mutex protects the reader service map
  Mutex reader_service_map_mutex;

  /// This map caches volume handles and root folder reference numbers
  std::unordered_map<char, VolumeData> volume_data_map;

  /// This mutex protects the volume data map
  Mutex volume_data_map_mutex;

  /// This cache contains a mapping from ref id to file name. We can gather this
  /// data passively by just inspecting the journal records and also query the
  /// volume in case of a cache miss
  std::unordered_map<USNFileReferenceNumber, NodeReferenceInfo>
      path_components_cache;

  /// This map is used to merge the rename records (old name and new name) into
  /// a single event. It is ordered so that we can delete data starting from the
  /// oldest entries
  std::map<USNFileReferenceNumber, USNJournalEventRecord> rename_path_mapper;
};

void NTFSEventPublisher::restartJournalReaderServices(
    std::unordered_set<char>& active_drives) {
  WriteLock lock(d->reader_service_map_mutex);

  // Spawn new services
  for (const auto& drive_letter : active_drives) {
    if (d->reader_service_map.find(drive_letter) !=
        d->reader_service_map.end()) {
      continue;
    }

    auto context = std::make_shared<USNJournalReaderContext>();
    context->drive_letter = drive_letter;

    VLOG(1) << "Creating a new USNJournalReader service for drive "
            << drive_letter << ":";

    auto service = std::make_shared<USNJournalReader>(context);

    d->reader_service_map.insert(
        {drive_letter, std::make_pair(service, context)});

    Dispatcher::addService(service);
  }

  // Terminate the ones we no longer need
  for (auto service_it = d->reader_service_map.begin();
       service_it != d->reader_service_map.end();) {
    const auto& drive_letter = service_it->first;
    if (active_drives.count(drive_letter)) {
      service_it++;
      continue;
    }

    const auto& service_instance = service_it->second;
    const auto& service_context = service_instance.second;

    VLOG(1) << "Terminating the USNJournalReader service assigned to drive "
            << drive_letter << ":";

    service_context->terminate = true;
    service_it = d->reader_service_map.erase(service_it);
  }
}

std::vector<USNJournalEventRecord> NTFSEventPublisher::acquireJournalRecords() {
  ReadLock lock(d->reader_service_map_mutex);

  // We have a reader service for each volume; attempt to fetch data
  // from each one of them
  std::vector<USNJournalEventRecord> record_list;

  for (auto& reader_info : d->reader_service_map) {
    auto& reader_instance = reader_info.second;
    auto& reader_context = reader_instance.second;

    std::vector<USNJournalEventRecord> new_record_list = {};

    {
      std::unique_lock<std::mutex> lock(
          reader_context->processed_records_mutex);

      auto wait_status = reader_context->processed_records_cv.wait_for(
          lock, std::chrono::seconds(1));

      if (wait_status == std::cv_status::no_timeout) {
        new_record_list = std::move(reader_context->processed_record_list);
        reader_context->processed_record_list.clear();
      }
    }

    record_list.reserve(record_list.size() + new_record_list.size());

    std::move(new_record_list.begin(),
              new_record_list.end(),
              std::back_inserter(record_list));

    new_record_list.clear();
  }

  return record_list;
}

NTFSEventPublisherConfiguration NTFSEventPublisher::readConfiguration() {
  auto config_parser = Config::getParser("file_paths");
  const auto& json = config_parser->getData().doc();
  const auto& file_accesses = json["file_accesses"];

  NTFSEventPublisherConfiguration configuration = {};

  // We are not going to expand the paths, as we just need to get the
  // drive letter in order to restart the reader services
  Config::get().files([&configuration](
      const std::string& category, const std::vector<std::string>& path_list) {

    for (const auto& path : path_list) {
      const auto& drive_letter = static_cast<char>(::toupper(path.front()));
      configuration.insert(drive_letter);
    }
  });

  return configuration;
}

Status NTFSEventPublisher::getPathFromReferenceNumber(
    std::string& path, char drive_letter, const USNFileReferenceNumber& ref) {
  path.clear();

  // Get the root reference number
  VolumeData volume_data = {};
  auto status = getVolumeData(volume_data, drive_letter);
  if (!status.ok()) {
    return status;
  }

  // Attempt to resolve the path one node at a time
  std::vector<std::string> components = {};
  size_t path_length = 3U;

  auto current_ref = ref;
  NodeReferenceInfo* current_node_info = nullptr;

  while (current_ref != volume_data.root_ref) {
    auto it = d->path_components_cache.find(current_ref);
    if (it != d->path_components_cache.end()) {
      const auto& node_ref_info = it->second;

      components.push_back(node_ref_info.name);
      current_ref = node_ref_info.parent;

      path_length += node_ref_info.name.size() + 1;

    } else {
      NodeReferenceInfo node_ref_info = {};
      status = queryVolumeJournal(
          node_ref_info.name, node_ref_info.parent, drive_letter, current_ref);
      if (!status) {
        return status;
      }

      components.push_back(node_ref_info.name);
      current_ref = node_ref_info.parent;

      path_length += node_ref_info.name.size() + 1;
    }
  }

  path.reserve(path_length);
  path += drive_letter;
  path.append(":\\");

  for (auto it = components.rbegin(); it != components.rend(); it++) {
    const auto& node_name = *it;
    path.append(node_name);
    path.append("\\");
  }

  return Status(0);
}

Status NTFSEventPublisher::queryVolumeJournal(
    std::string& name,
    USNFileReferenceNumber& parent_ref,
    char drive_letter,
    const USNFileReferenceNumber& ref) {
  UpgradeLock lock(d->reader_service_map_mutex);

  auto it = d->reader_service_map.find(drive_letter);
  if (it == d->reader_service_map.end()) {
    return Status(1, "Service is not running");
  }

  const auto& service_instance = it->second;
  const auto& journal_reader = service_instance.first;

  return journal_reader->query(name, parent_ref, ref);
}

Status NTFSEventPublisher::getVolumeData(VolumeData& volume,
                                         char drive_letter) {
  UpgradeLock lock(d->volume_data_map_mutex);

  {
    auto it = d->volume_data_map.find(drive_letter);
    if (it != d->volume_data_map.end()) {
      volume = it->second;
      return Status(0);
    }
  }

  WriteUpgradeLock wlock(lock);

  // Get a handle to the volume
  auto volume_path = std::string("\\\\.\\") + drive_letter + ":";

  VolumeData volume_data = {};
  volume_data.volume_handle =
      ::CreateFile(volume_path.c_str(),
                   FILE_GENERIC_READ,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   nullptr,
                   OPEN_EXISTING,
                   FILE_FLAG_BACKUP_SEMANTICS,
                   nullptr);

  if (volume_data.volume_handle == INVALID_HANDLE_VALUE) {
    std::stringstream message;
    message << "Failed to open the following drive: " << volume_path
            << " due to the following error: ";

    std::string description;
    if (!getWindowsErrorDescription(description, GetLastError())) {
      description = "Unknown error";
    }

    message << description;
    return Status(1, message.str());
  }

  // Get the root folder reference number
  std::string root_folder_path;
  root_folder_path.push_back(drive_letter);
  root_folder_path.append(":\\");

  volume_data.root_folder_handle =
      ::CreateFile(root_folder_path.c_str(),
                   FILE_SHARE_READ,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   nullptr,
                   OPEN_EXISTING,
                   FILE_FLAG_BACKUP_SEMANTICS,
                   nullptr);

  if (volume_data.root_folder_handle == INVALID_HANDLE_VALUE) {
    ::CloseHandle(volume_data.volume_handle);

    std::stringstream message;
    message << "Failed to get the root folder handle for volume '"
            << drive_letter << "'. Error: ";

    std::string description;
    if (!getWindowsErrorDescription(description, GetLastError())) {
      description = "Unknown error";
    }

    message << description;
    return Status(1, message.str());
  }

  std::uint8_t buffer[2048] = {};
  DWORD bytes_read = 0U;

  if (!DeviceIoControl(volume_data.root_folder_handle,
                       FSCTL_READ_FILE_USN_DATA,
                       nullptr,
                       0,
                       buffer,
                       sizeof(buffer),
                       &bytes_read,
                       nullptr)) {
    ::CloseHandle(volume_data.volume_handle);
    ::CloseHandle(volume_data.root_folder_handle);

    std::stringstream message;
    message << "Failed to get the root reference number for volume '"
            << drive_letter << "'. Error: ";

    std::string description;
    if (!getWindowsErrorDescription(description, GetLastError())) {
      description = "Unknown error";
    }

    message << description;
    return Status(1, message.str());
  }

  auto usn_record = reinterpret_cast<USN_RECORD*>(buffer);
  if (!USNParsers::GetFileReferenceNumber(volume_data.root_ref, usn_record)) {
    ::CloseHandle(volume_data.volume_handle);
    ::CloseHandle(volume_data.root_folder_handle);

    return Status(1, "Failed to parse the root USN record");
  }

  d->volume_data_map.insert({drive_letter, volume_data});
  return Status(0);
}

void NTFSEventPublisher::releaseDriveHandleMap() {
  WriteLock lock(d->volume_data_map_mutex);

  for (const auto& p : d->volume_data_map) {
    const auto& volume_data = p.second;
    ::CloseHandle(volume_data.volume_handle);
    ::CloseHandle(volume_data.root_folder_handle);
  }

  d->volume_data_map.clear();
}

NTFSEventPublisher::NTFSEventPublisher() : d(new PrivateData) {}

NTFSEventPublisher::~NTFSEventPublisher() {
  tearDown();
}

Status NTFSEventPublisher::setUp() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return Status(1, "Publisher disabled via configuration");
  }

  return Status(0, "OK");
}

void NTFSEventPublisher::configure() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return;
  }

  auto configuration = readConfiguration();
  restartJournalReaderServices(configuration);

  releaseDriveHandleMap();
}

Status NTFSEventPublisher::run() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return Status(1, "Publisher disabled via configuration");
  }

  auto journal_records = acquireJournalRecords();
  if (journal_records.empty()) {
    return Status(0);
  }

  auto event_context = createEventContext();

  for (const auto& journal_record : journal_records) {
    // Update the path components cache
    NodeReferenceInfo node_ref_info = {};
    node_ref_info.parent = journal_record.parent_ref_number;
    node_ref_info.name = journal_record.name;

    d->path_components_cache.insert(
        {journal_record.node_ref_number, node_ref_info});

    // Track rename records so that we can merge them into a single event
    bool skip_record = false;
    USNJournalEventRecord old_name_record = {};

    switch (journal_record.type) {
    case USNJournalEventRecord::Type::DirectoryRename_OldName:
    case USNJournalEventRecord::Type::FileRename_OldName: {
      d->rename_path_mapper.insert(
          {journal_record.node_ref_number, journal_record});
      skip_record = true;
      break;
    }

    case USNJournalEventRecord::Type::DirectoryRename_NewName:
    case USNJournalEventRecord::Type::FileRename_NewName: {
      auto it = d->rename_path_mapper.find(journal_record.node_ref_number);
      if (it == d->rename_path_mapper.end()) {
        skip_record = true;
        VLOG(1) << "Failed to remap the rename records";
      }

      old_name_record = it->second;
      d->rename_path_mapper.erase(it);
    }
    }

    if (skip_record) {
      continue;
    }

    // Generate the new event
    NTFSEventRecord event = {};
    event.type = journal_record.type;
    event.timestamp = journal_record.timestamp;
    event.attributes = journal_record.attributes;

    auto status = getPathFromReferenceNumber(event.path,
                                             journal_record.drive_letter,
                                             journal_record.node_ref_number);
    if (!status.ok()) {
      VLOG(1) << status.getMessage();
      event.path = journal_record.name;
    }

    status = getPathFromReferenceNumber(event.parent_path,
                                        journal_record.drive_letter,
                                        journal_record.parent_ref_number);
    if (!status.ok()) {
      VLOG(1) << status.getMessage();
    }

    if (old_name_record.node_ref_number != 0U) {
      status = getPathFromReferenceNumber(event.old_path,
                                          old_name_record.drive_letter,
                                          old_name_record.node_ref_number);
      if (!status.ok()) {
        VLOG(1) << status.getMessage();
        event.old_path = old_name_record.name;
      }
    }

    event_context->event_list.push_back(std::move(event));

    // Update the path components cache by deleting files that are no longer
    // available
    // ...
  }

  fire(event_context);

  // Put a limit on the size of the caches we are using
  if (d->path_components_cache.size() >= 20000U) {
    auto range_start = d->path_components_cache.begin();
    auto range_end = std::next(range_start, 10000U);

    d->path_components_cache.erase(range_start, range_end);
  }

  if (d->rename_path_mapper.size() >= 2000U) {
    auto range_start = d->rename_path_mapper.begin();
    auto range_end = std::next(range_start, 1000U);

    d->rename_path_mapper.erase(range_start, range_end);
  }

  return Status(0, "OK");
}

void NTFSEventPublisher::tearDown() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return;
  }

  releaseDriveHandleMap();
}
} // namespace osquery
