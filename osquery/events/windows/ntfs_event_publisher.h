/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <unordered_set>

#include <osquery/events.h>

#include "osquery/events/windows/usn_journal_reader.h"

namespace osquery {
/// The subscription context contains the list of paths the subscriber is
/// interested in
struct NTFSEventSubscriptionContext final : public SubscriptionContext {
 private:
  friend class FileEventPublisher;
};

using NTFSEventSubscriptionContextRef =
    std::shared_ptr<NTFSEventSubscriptionContext>;

/// A single NTFS event record
struct NTFSEventRecord final {
  /// Event type
  USNJournalEventRecord::Type type;

  /// Path
  std::string path;

  /// Previous path (only valid for rename operations)
  std::string old_path;

  /// Record timestamp
  std::time_t record_timestamp{0U};

  /// Node attributes
  DWORD attributes;

  /// Update sequence number of the journal record
  USN update_sequence_number{0U};

  /// Ordinal for the file or directory referenced by this record
  USNFileReferenceNumber node_ref_number{0U};

  /// Ordinal for the directory containing the file or directory referenced
  USNFileReferenceNumber parent_ref_number{0U};

  /// Drive letter
  char drive_letter{0U};

  /// If true, this event is partial; it means that we could only get
  /// the file or folder name inside path or old_path
  bool partial{false};
};

/// This structure is used to save volume handles and reference ids
struct VolumeData final {
  /// Volume handle, used to perform journal queries
  HANDLE volume_handle;

  /// Root folder handle
  HANDLE root_folder_handle;

  /// This is the root folder reference number; we need it when walking
  /// the file reference tree
  USNFileReferenceNumber root_ref;
};

static_assert(std::is_move_constructible<NTFSEventRecord>::value,
              "not move constructible");

/// A file change event context can contain many file change descriptors,
/// depending on how much data from the journal has been processed
struct NTFSEventContext final : public EventContext {
  /// The list of events received from the USN journal
  std::vector<NTFSEventRecord> event_list;
};

using NTFSEventContextRef = std::shared_ptr<NTFSEventContext>;

/// This structure is used for the path components cache
struct NodeReferenceInfo final {
  /// Parent file reference number
  USNFileReferenceNumber parent;

  /// File or folder name
  std::string name;
};

/// The path components cache maps reference numbers to node names
using PathComponentsCache =
    std::unordered_map<USNFileReferenceNumber, NodeReferenceInfo>;

/// This structure describes a running USNJournalReader instance
struct USNJournalReaderInstance final {
  /// The reader service
  USNJournalReaderRef reader;

  /// The shared context
  USNJournalReaderContextRef context;

  /// This cache contains a mapping from ref id to file name. We can gather this
  /// data passively by just inspecting the journal records and also query the
  /// volume in case of a cache miss
  PathComponentsCache path_components_cache;

  /// This map is used to merge the rename records (old name and new name) into
  /// a single event. It is ordered so that we can delete data starting from the
  /// oldest entries
  std::map<USNFileReferenceNumber, USNJournalEventRecord> rename_path_mapper;
};

/// The NTFSEventPublisher configuration is just a list of drives we are
/// monitoring
using NTFSEventPublisherConfiguration = std::unordered_set<char>;

/// The file change publisher receives the raw events from the USNJournalReader
/// and processes them to emit file change events
class NTFSEventPublisher final
    : public EventPublisher<NTFSEventSubscriptionContext, NTFSEventContext> {
  DECLARE_PUBLISHER("ntfseventpublisher");

  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// If needed, this method spawns a new USNJournalReader service for the given
  /// volume
  void restartJournalReaderServices(std::unordered_set<char>& active_drives);

  /// Acquires new events from the reader service, firing new events to
  /// subscribers
  std::vector<USNJournalEventRecord> acquireJournalRecords();

  /// Reads the configuration, saving the list of drives that need to be
  /// monitored
  NTFSEventPublisherConfiguration readConfiguration();

  /// Attempts to resolve the reference number using the path components cache
  Status resolvePathFromComponentsCache(
      std::string& path,
      PathComponentsCache& path_components_cache,
      char drive_letter,
      const USNFileReferenceNumber& ref);

  /// Attempts to get the full path for the given file reference. If the path is
  /// located, it also updates the path components cache
  Status getPathFromReferenceNumber(std::string& path,
                                    PathComponentsCache& path_components_cache,
                                    char drive_letter,
                                    const USNFileReferenceNumber& ref);

  /// Returns a VolumeData structure containing the volume handle and the
  /// root folder reference number
  Status getVolumeData(VolumeData& volume, char drive_letter);

  /// Releases the drive handle cache
  void releaseDriveHandleMap();

 public:
  /// Constructor
  NTFSEventPublisher();

  /// Destructor
  virtual ~NTFSEventPublisher();

  /// Initializes the publisher
  Status setUp() override;

  /// Called during startup and every time the configuration is reloaded
  void configure() override;

  /// Publisher's entry point
  Status run() override;

  /// Clean up routine
  void tearDown() override;
};

/// Converts a USNFileReferenceNumber to a FILE_ID_DESCRIPTOR for the
/// OpenFileById Windows API
void GetNativeFileIdFromUSNReference(FILE_ID_DESCRIPTOR& file_id,
                                     const USNFileReferenceNumber& ref);
} // namespace osquery
