/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <array>
#include <ctime>
#include <iomanip>
#include <map>

#include <Windows.h>
#include <winioctl.h>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/utils.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/usn_journal_reader.h"

#ifndef FILE_ATTRIBUTE_RECALL_ON_OPEN
#define FILE_ATTRIBUTE_RECALL_ON_OPEN 0x00040000
#endif

#ifndef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000
#endif

namespace osquery {
/// This debug flag will print the incoming events
HIDDEN_FLAG(bool,
            usn_journal_reader_debug,
            false,
            "Debug USN journal messages");

// clang-format off
const std::unordered_map<int, std::string> kWindowsFileAttributeMap = {
    {FILE_ATTRIBUTE_ARCHIVE, "FILE_ATTRIBUTE_ARCHIVE"},
    {FILE_ATTRIBUTE_COMPRESSED, "FILE_ATTRIBUTE_COMPRESSED"},
    {FILE_ATTRIBUTE_DEVICE, "FILE_ATTRIBUTE_DEVICE"},
    {FILE_ATTRIBUTE_DIRECTORY, "FILE_ATTRIBUTE_DIRECTORY"},
    {FILE_ATTRIBUTE_ENCRYPTED, "FILE_ATTRIBUTE_ENCRYPTED"},
    {FILE_ATTRIBUTE_HIDDEN, "FILE_ATTRIBUTE_HIDDEN"},
    {FILE_ATTRIBUTE_INTEGRITY_STREAM, "FILE_ATTRIBUTE_INTEGRITY_STREAM"},
    {FILE_ATTRIBUTE_NORMAL, "FILE_ATTRIBUTE_NORMAL"},
    {FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"},
    {FILE_ATTRIBUTE_NO_SCRUB_DATA, "FILE_ATTRIBUTE_NO_SCRUB_DATA"},
    {FILE_ATTRIBUTE_OFFLINE, "FILE_ATTRIBUTE_OFFLINE"},
    {FILE_ATTRIBUTE_READONLY, "FILE_ATTRIBUTE_READONLY"},
    {FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS"},
    {FILE_ATTRIBUTE_RECALL_ON_OPEN, "FILE_ATTRIBUTE_RECALL_ON_OPEN"},
    {FILE_ATTRIBUTE_REPARSE_POINT, "FILE_ATTRIBUTE_REPARSE_POINT"},
    {FILE_ATTRIBUTE_SPARSE_FILE, "FILE_ATTRIBUTE_SPARSE_FILE"},
    {FILE_ATTRIBUTE_SYSTEM, "FILE_ATTRIBUTE_SYSTEM"},
    {FILE_ATTRIBUTE_TEMPORARY, "FILE_ATTRIBUTE_TEMPORARY"},
    {FILE_ATTRIBUTE_VIRTUAL, "FILE_ATTRIBUTE_VIRTUAL"}};
// clang-format on

// clang-format off
const std::unordered_map<USNJournalEventRecord::Type, std::string>
    kNTFSEventToStringMap = {
        {USNJournalEventRecord::Type::AttributesChange, "AttributesChange"},
        {USNJournalEventRecord::Type::ExtendedAttributesChange, "ExtendedAttributesChange"},
        {USNJournalEventRecord::Type::DirectoryCreation, "DirectoryCreation"},
        {USNJournalEventRecord::Type::FileWrite, "FileWrite"},
        {USNJournalEventRecord::Type::DirectoryOverwrite, "DirectoryOverwrite"},
        {USNJournalEventRecord::Type::FileOverwrite, "FileOverwrite"},
        {USNJournalEventRecord::Type::DirectoryTruncation, "DirectoryTruncation"},
        {USNJournalEventRecord::Type::FileTruncation, "FileTruncation"},
        {USNJournalEventRecord::Type::TransactedDirectoryChange, "TransactedDirectoryChange"},
        {USNJournalEventRecord::Type::TransactedFileChange, "TransactedFileChange"},
        {USNJournalEventRecord::Type::FileCreation, "FileCreation"},
        {USNJournalEventRecord::Type::DirectoryDeletion, "DirectoryDeletion"},
        {USNJournalEventRecord::Type::FileDeletion, "FileDeletion"},
        {USNJournalEventRecord::Type::DirectoryLinkChange, "DirectoryLinkChange"},
        {USNJournalEventRecord::Type::FileLinkChange, "FileLinkChange"},
        {USNJournalEventRecord::Type::DirectoryIndexingSettingChange, "DirectoryIndexingSettingChange"},
        {USNJournalEventRecord::Type::FileIndexingSettingChange, "FileIndexingSettingChange"},
        {USNJournalEventRecord::Type::DirectoryIntegritySettingChange, "DirectoryIntegritySettingChange"},
        {USNJournalEventRecord::Type::FileIntegritySettingChange, "FileIntegritySettingChange"},
        {USNJournalEventRecord::Type::AlternateDataStreamWrite, "AlternateDataStreamWrite"},
        {USNJournalEventRecord::Type::AlternateDataStreamOverwrite, "AlternateDataStreamOverwrite"},
        {USNJournalEventRecord::Type::AlternateDataStreamTruncation, "AlternateDataStreamTruncation"},
        {USNJournalEventRecord::Type::AlternateDataStreamChange, "AlternateDataStreamChange"},
        {USNJournalEventRecord::Type::DirectoryObjectIdChange, "DirectoryObjectIdChange"},
        {USNJournalEventRecord::Type::FileObjectIdChange, "FileObjectIdChange"},
        {USNJournalEventRecord::Type::DirectoryRename_NewName, "DirectoryRename_NewName"},
        {USNJournalEventRecord::Type::FileRename_NewName, "FileRename_NewName"},
        {USNJournalEventRecord::Type::DirectoryRename_OldName, "DirectoryRename_OldName"},
        {USNJournalEventRecord::Type::FileRename_OldName, "FileRename_OldName"},
        {USNJournalEventRecord::Type::ReparsePointChange, "ReparsePointChange"},
        {USNJournalEventRecord::Type::DirectorySecurityAttributesChange, "DirectorySecurityAttributesChange"},
        {USNJournalEventRecord::Type::FileSecurityAttributesChange, "FileSecurityAttributesChange"}};
// clang-format on

namespace {
/// Read buffer size
const size_t kUSNJournalReaderBufferSize = 4096U;

/// This variable holds the list of change events we are interested in. Order
/// is important, as it determines the priority when decompressing/splitting
/// the `reason` field of the USN journal records.
const std::vector<DWORD> kUSNChangeReasonFlagList = {
    USN_REASON_FILE_CREATE,
    USN_REASON_DATA_OVERWRITE,
    USN_REASON_DATA_TRUNCATION,
    USN_REASON_DATA_EXTEND,
    USN_REASON_FILE_DELETE,

    USN_REASON_RENAME_OLD_NAME,
    USN_REASON_RENAME_NEW_NAME,

    USN_REASON_NAMED_DATA_EXTEND,
    USN_REASON_NAMED_DATA_OVERWRITE,
    USN_REASON_NAMED_DATA_TRUNCATION,

    USN_REASON_TRANSACTED_CHANGE,
    USN_REASON_BASIC_INFO_CHANGE,
    USN_REASON_EA_CHANGE,
    USN_REASON_HARD_LINK_CHANGE,
    USN_REASON_INDEXABLE_CHANGE,
    USN_REASON_INTEGRITY_CHANGE,
    USN_REASON_STREAM_CHANGE,
    USN_REASON_OBJECT_ID_CHANGE,
    USN_REASON_REPARSE_POINT_CHANGE,
    USN_REASON_SECURITY_CHANGE};

// This map is used to convert the `reason` field of the USN record to
// our internal type. In the pair type, the first field is selected if
// the attributes indicate that the event is operating on a directory
// clang-format off
const std::unordered_map<int, std::pair<USNJournalEventRecord::Type, USNJournalEventRecord::Type>> kReasonConversionMap = {
  // USN `reason` bit                 Internal event for directories                                    Internal event for non-directories
  {USN_REASON_BASIC_INFO_CHANGE,      {USNJournalEventRecord::Type::AttributesChange,                   USNJournalEventRecord::Type::AttributesChange}},
  {USN_REASON_EA_CHANGE,              {USNJournalEventRecord::Type::AttributesChange,                   USNJournalEventRecord::Type::ExtendedAttributesChange}},
  {USN_REASON_DATA_EXTEND,            {USNJournalEventRecord::Type::DirectoryCreation,                  USNJournalEventRecord::Type::FileWrite}},
  {USN_REASON_DATA_OVERWRITE,         {USNJournalEventRecord::Type::DirectoryOverwrite,                 USNJournalEventRecord::Type::FileOverwrite}},
  {USN_REASON_DATA_TRUNCATION,        {USNJournalEventRecord::Type::DirectoryTruncation,                USNJournalEventRecord::Type::FileTruncation}},
  {USN_REASON_TRANSACTED_CHANGE,      {USNJournalEventRecord::Type::TransactedDirectoryChange,          USNJournalEventRecord::Type::TransactedFileChange}},
  {USN_REASON_FILE_CREATE,            {USNJournalEventRecord::Type::DirectoryCreation,                  USNJournalEventRecord::Type::FileCreation}},
  {USN_REASON_FILE_DELETE,            {USNJournalEventRecord::Type::DirectoryDeletion,                  USNJournalEventRecord::Type::FileDeletion}},
  {USN_REASON_HARD_LINK_CHANGE,       {USNJournalEventRecord::Type::DirectoryLinkChange,                USNJournalEventRecord::Type::FileLinkChange}},
  {USN_REASON_INDEXABLE_CHANGE,       {USNJournalEventRecord::Type::DirectoryIndexingSettingChange,     USNJournalEventRecord::Type::FileIndexingSettingChange}},
  {USN_REASON_INTEGRITY_CHANGE,       {USNJournalEventRecord::Type::DirectoryIntegritySettingChange,    USNJournalEventRecord::Type::FileIntegritySettingChange}},
  {USN_REASON_NAMED_DATA_EXTEND,      {USNJournalEventRecord::Type::AlternateDataStreamWrite,           USNJournalEventRecord::Type::AlternateDataStreamWrite}},
  {USN_REASON_NAMED_DATA_OVERWRITE,   {USNJournalEventRecord::Type::AlternateDataStreamOverwrite,       USNJournalEventRecord::Type::AlternateDataStreamOverwrite}},
  {USN_REASON_NAMED_DATA_TRUNCATION,  {USNJournalEventRecord::Type::AlternateDataStreamTruncation,      USNJournalEventRecord::Type::AlternateDataStreamTruncation}},
  {USN_REASON_STREAM_CHANGE,          {USNJournalEventRecord::Type::AlternateDataStreamChange,          USNJournalEventRecord::Type::AlternateDataStreamChange}},
  {USN_REASON_OBJECT_ID_CHANGE,       {USNJournalEventRecord::Type::DirectoryObjectIdChange,            USNJournalEventRecord::Type::FileObjectIdChange}},
  {USN_REASON_RENAME_NEW_NAME,        {USNJournalEventRecord::Type::DirectoryRename_NewName,            USNJournalEventRecord::Type::FileRename_NewName}},
  {USN_REASON_RENAME_OLD_NAME,        {USNJournalEventRecord::Type::DirectoryRename_OldName,            USNJournalEventRecord::Type::FileRename_OldName}},
  {USN_REASON_REPARSE_POINT_CHANGE,   {USNJournalEventRecord::Type::ReparsePointChange,                 USNJournalEventRecord::Type::ReparsePointChange}},
  {USN_REASON_SECURITY_CHANGE,        {USNJournalEventRecord::Type::DirectorySecurityAttributesChange,  USNJournalEventRecord::Type::FileSecurityAttributesChange}}
};
// clang-format on

/// Aggregates the flag list into a bit mask; this is used to avoid having to
/// repeat the flag list twice in two different formats
DWORD GetUSNChangeReasonFlagMask() {
  DWORD result = 0U;
  for (const auto& bit : kUSNChangeReasonFlagList) {
    result |= bit;
  }

  return result;
}
}

struct USNJournalReader::PrivateData final {
  /// Shared data between this service and the publisher
  USNJournalReaderContextRef journal_reader_context;

  /// This is the handle for the volume mounted at
  /// journal_reader_context->drive_letter
  HANDLE volume_handle{INVALID_HANDLE_VALUE};

  /// Read buffer
  std::array<std::uint8_t, kUSNJournalReaderBufferSize> read_buffer;

  /// How many bytes the service was able to read during the last acquireRecords
  /// call
  size_t bytes_received{0U};

  /// Initial sequence number; this is the USN that we saw for the first time
  /// when launching the service
  USN initial_sequence_number;

  /// Sequence number used to query the volume journal
  USN next_update_seq_number{0U};

  /// The volume journal id
  DWORDLONG journal_id{0U};

  /// The volume path (i.e.: \\.\C:)
  std::string volume_path;

  /// This map is used to deduplicate the journal records; when the maximum size
  /// is reached, the oldest entries are automatically cleared
  USNPerFileLastRecordType per_file_last_record_type_map;
};

Status USNJournalReader::initialize() {
  // Create a handle to the volume and save it
  d->volume_path =
      std::string("\\\\.\\") + d->journal_reader_context->drive_letter + ":";

  d->volume_handle =
      ::CreateFile(d->volume_path.c_str(),
                   FILE_GENERIC_READ,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   nullptr,
                   OPEN_EXISTING,
                   0,
                   nullptr);

  if (d->volume_handle == INVALID_HANDLE_VALUE) {
    std::stringstream error_message;
    error_message << "Failed to get a handle to the following volume: "
                  << d->volume_path << ". Terminating...";

    return Status(1, error_message.str());
  }

  // Acquire a valid USN that we will use to start querying the journal
  USN_JOURNAL_DATA_V2 journal_data = {};
  DWORD bytes_received = 0U;

  if (!::DeviceIoControl(d->volume_handle,
                         FSCTL_QUERY_USN_JOURNAL,
                         nullptr,
                         0,
                         &journal_data,
                         sizeof(journal_data),
                         &bytes_received,
                         nullptr) ||
      bytes_received != sizeof(journal_data)) {
    std::stringstream error_message;
    error_message << "Failed to acquire the initial journal ID and sequence "
                     "number for the following volume: "
                  << d->volume_path << ". Terminating...";

    return Status(1, error_message.str());
  }

  /// This is the next USN identifier, to be used when requesting the next
  /// updates; we keep the initial ones for queries
  d->initial_sequence_number = journal_data.NextUsn;
  d->next_update_seq_number = d->initial_sequence_number;

  // Also save the journal id
  d->journal_id = journal_data.UsnJournalID;

  return Status(0);
}

Status USNJournalReader::acquireRecords() {
  static const DWORD flag_mask = GetUSNChangeReasonFlagMask();

  // Attempt to fill the read buffer; it is important to also support at least
  // V3 records, as V2 are disabled when range tracking is activated. We are
  // skipping them for now, but we can easily enable them by changing the last
  // field in this structure (the code will automatically skip them for now)
  READ_USN_JOURNAL_DATA_V1 read_data_command = {0U,
                                                flag_mask,
                                                0U,
                                                1U,
                                                kUSNJournalReaderBufferSize,
                                                d->journal_id,
                                                2U,
                                                3U};

  read_data_command.StartUsn = d->next_update_seq_number;

  DWORD bytes_received = 0U;
  if (!::DeviceIoControl(d->volume_handle,
                         FSCTL_READ_USN_JOURNAL,
                         &read_data_command,
                         sizeof(read_data_command),
                         d->read_buffer.data(),
                         static_cast<DWORD>(d->read_buffer.size()),
                         &bytes_received,
                         nullptr) ||
      bytes_received < sizeof(USN)) {
    std::stringstream error_message;
    error_message << "Failed to read the journal of the following volume: "
                  << d->volume_path << ". Terminating...";

    return Status(1, error_message.str());
  }

  d->bytes_received = static_cast<size_t>(bytes_received);

  // Save the new update sequence number for the next query
  auto next_update_seq_number_ptr =
      reinterpret_cast<USN*>(d->read_buffer.data());

  d->next_update_seq_number = *next_update_seq_number_ptr;
  return Status(0);
}

// V4 records are only used for range tracking; they are not useful for us since
// they are emitted only after a file has been closed.
//
// NTFS range tracking is enabled or disabled system-wide, and MSDN mention that
// system components may toggle it on. When it is activated, the filesystem will
// stop outputting V2 records, and only use V3 and V4 instead.
Status USNJournalReader::processAcquiredRecords(
    std::vector<USNJournalEventRecord>& record_list) {
  record_list.clear();

  const auto buffer_start_ptr = d->read_buffer.data() + sizeof(USN);
  const auto buffer_end_ptr = d->read_buffer.data() + d->bytes_received;

  auto current_buffer_ptr = d->read_buffer.data() + sizeof(USN);

  while (current_buffer_ptr < buffer_end_ptr) {
    auto current_record =
        reinterpret_cast<const USN_RECORD*>(current_buffer_ptr);

    auto next_buffer_ptr = current_buffer_ptr + current_record->RecordLength;
    if (next_buffer_ptr > buffer_end_ptr) {
      return Status(1, "Received a malformed USN_RECORD. Terminating...");
    }

    auto status =
        ProcessAndAppendUSNRecord(record_list,
                                  current_record,
                                  d->per_file_last_record_type_map,
                                  d->journal_reader_context->drive_letter);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
    }

    current_buffer_ptr = next_buffer_ptr;
  }

  return Status(0);
}

void USNJournalReader::dispatchEventRecords(
    const std::vector<USNJournalEventRecord>& record_list) {
  if (record_list.empty()) {
    return;
  }

  // Notify the publisher that we have new records ready to be acquired
  auto& context = d->journal_reader_context;

  {
    std::unique_lock<std::mutex> lock(context->processed_records_mutex);

    context->processed_record_list.reserve(
        context->processed_record_list.size() + record_list.size());

    context->processed_record_list.insert(context->processed_record_list.end(),
                                          record_list.begin(),
                                          record_list.end());

    context->processed_records_cv.notify_all();
  }
}

void USNJournalReader::start() {
  // Acquire a handle to the device, as well as the journal id and the initial
  // sequence number
  auto status = initialize();
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return;
  }

  // Enter the main loop, listening for journal changes
  while (!interrupted() && !d->journal_reader_context->terminate) {
    status = acquireRecords();
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      return;
    }

    // Process the records
    std::vector<USNJournalEventRecord> record_list;
    status = processAcquiredRecords(record_list);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      return;
    }

    // Send the new records to the event publisher
    dispatchEventRecords(record_list);
  }
}

void USNJournalReader::stop() {
  if (d->volume_handle != INVALID_HANDLE_VALUE) {
    ::CloseHandle(d->volume_handle);
    d->volume_handle = INVALID_HANDLE_VALUE;
  }
}

USNJournalReader::USNJournalReader(
    USNJournalReaderContextRef journal_reader_context)
    : InternalRunnable("USNJournalReader"), d(new PrivateData) {
  d->journal_reader_context = journal_reader_context;
}

USNJournalReader::~USNJournalReader() {}

// TODO(alessandro): Write a test for this
Status USNJournalReader::DecompressRecord(
    std::vector<USNJournalEventRecord>& new_records,
    const USNJournalEventRecord& base_record,
    DWORD journal_record_reason,
    USNPerFileLastRecordType& per_file_last_record_type_map) {
  for (const auto& reason_bit : kUSNChangeReasonFlagList) {
    if ((journal_record_reason & reason_bit) == 0) {
      continue;
    }

    auto new_record = base_record;
    if (!USNParsers::GetEventType(
            new_record.type, reason_bit, base_record.attributes)) {
      return Status(1, "Failed to get the event type");
    }

    bool emit_record = true;
    auto last_file_state_it =
        per_file_last_record_type_map.find(new_record.node_ref_number);

    if (last_file_state_it == per_file_last_record_type_map.end()) {
      emit_record = true;

    } else {
      auto last_file_state = last_file_state_it->second;
      emit_record = last_file_state != new_record.type;
    }

    if (emit_record) {
      if (FLAGS_usn_journal_reader_debug) {
        std::stringstream buffer;
        buffer << new_record << "\n";
        std::cout << buffer.str();
      }

      new_records.push_back(std::move(new_record));
      per_file_last_record_type_map[new_record.node_ref_number] =
          new_record.type;

      if (per_file_last_record_type_map.size() >= 20000U) {
        auto range_start = per_file_last_record_type_map.begin();
        auto range_end = std::next(range_start, 10000U);

        per_file_last_record_type_map.erase(range_start, range_end);
      }
    }
  }

  return Status(0);
}

// TODO(alessandro): Write a test for this
Status USNJournalReader::ProcessAndAppendUSNRecord(
    std::vector<USNJournalEventRecord>& record_list,
    const USN_RECORD* record,
    USNPerFileLastRecordType& per_file_last_record_type_map,
    char drive_letter) {
  // We don't care about range tracking records
  if (record->MajorVersion == 4U) {
    return Status(0);
  }

  if (record->MinorVersion != 0U) {
    LOG(WARNING) << "Unexpected minor version value";
  }

  USNJournalEventRecord base_event_record = {};
  base_event_record.drive_letter = drive_letter;

  base_event_record.journal_record_version =
      static_cast<size_t>(record->MajorVersion);

  if (!USNParsers::GetUpdateSequenceNumber(
          base_event_record.update_sequence_number, record)) {
    return Status(1,
                  "Failed to get the update sequence number from the record");
  }

  if (!USNParsers::GetFileReferenceNumber(base_event_record.node_ref_number,
                                          record)) {
    return Status(1, "Failed to get the file reference number");
  }

  if (!USNParsers::GetParentFileReferenceNumber(
          base_event_record.parent_ref_number, record)) {
    return Status(1, "Failed to get the parent reference number");
  }

  if (!USNParsers::GetTimeStamp(base_event_record.record_timestamp, record)) {
    return Status(1, "Failed to get the timestamp");
  }

  if (!USNParsers::GetAttributes(base_event_record.attributes, record)) {
    return Status(1, "Failed to get the file attributes");
  }

  if (!USNParsers::GetEventString(base_event_record.name, record)) {
    return Status(1, "Failed to acquire the file name");
  }

  // Now decompress the record by splitting the `reason` field
  DWORD reason;
  if (!USNParsers::GetReason(reason, record)) {
    return Status(1, "Failed to get the `reason` field from the record");
  }

  auto status = DecompressRecord(
      record_list, base_event_record, reason, per_file_last_record_type_map);
  if (!status.ok()) {
    return status;
  }

  return Status(0);
}

void GetNativeFileIdFromUSNReference(FILE_ID_DESCRIPTOR& file_id,
                                     const USNFileReferenceNumber& ref) {
  std::vector<unsigned char> buffer;
  boostmp::export_bits(ref, std::back_inserter(buffer), 8, false);

  file_id = {};
  file_id.dwSize = sizeof(FILE_ID_DESCRIPTOR);

  // export_bits will only push as many unsinged chars as are needed to
  // represent
  // a value, so we've no guarantee to sizes, but if bits are set above the 64th
  // bit, it's an extended file id
  if (buffer.size() <= sizeof(std::uint64_t)) {
    file_id.Type = FileIdType;

    buffer.resize(sizeof(std::uint64_t));
    auto id_ptr = reinterpret_cast<const std::uint64_t*>(buffer.data());
    file_id.FileId.QuadPart = *id_ptr;

  } else {
    file_id.Type = ExtendedFileIdType;
    buffer.resize(sizeof(FILE_ID_128::Identifier));

    for (auto i = 0U; i < buffer.size(); i++) {
      file_id.ExtendedFileId.Identifier[i] = buffer[i];
    }
  }
}

namespace USNParsers {
bool GetUpdateSequenceNumber(USN& usn, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U:
    usn = reinterpret_cast<const USN_RECORD_V2*>(record)->Usn;
    return true;

  case 3U:
    usn = reinterpret_cast<const USN_RECORD_V3*>(record)->Usn;
    return true;

  default:
    return false;
  }
}

bool GetFileReferenceNumber(USNFileReferenceNumber& ref_number,
                            const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U: {
    ref_number =
        reinterpret_cast<const USN_RECORD_V2*>(record)->FileReferenceNumber;

    return true;
  }

  case 3U: {
    const auto& byte_array = reinterpret_cast<const USN_RECORD_V3*>(record)
                                 ->FileReferenceNumber.Identifier;

    boostmp::import_bits(ref_number,
                         byte_array,
                         byte_array + sizeof(FILE_ID_128::Identifier),
                         0,
                         false);

    return true;
  }

  default:
    return false;
  }
}

bool GetParentFileReferenceNumber(USNFileReferenceNumber& ref_number,
                                  const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U: {
    ref_number = reinterpret_cast<const USN_RECORD_V2*>(record)
                     ->ParentFileReferenceNumber;
    return true;
  }

  case 3U: {
    const auto& byte_array = reinterpret_cast<const USN_RECORD_V3*>(record)
                                 ->ParentFileReferenceNumber.Identifier;

    boostmp::import_bits(ref_number,
                         byte_array,
                         byte_array + sizeof(FILE_ID_128::Identifier),
                         0,
                         false);

    return true;
  }

  default:
    return false;
  }
}

bool GetTimeStamp(std::time_t& record_timestamp, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  LARGE_INTEGER update_timestamp = {};

  switch (record->MajorVersion) {
  case 2U:
    update_timestamp =
        reinterpret_cast<const USN_RECORD_V2*>(record)->TimeStamp;
    break;

  case 3U:
    update_timestamp =
        reinterpret_cast<const USN_RECORD_V3*>(record)->TimeStamp;
    break;

  default:
    return false;
  }

  // Convert the timestamp to seconds and rebase it (from 1601 to the epoch
  // time)
  record_timestamp =
      static_cast<std::time_t>(update_timestamp.QuadPart / 10000000ULL) -
      11644473600ULL;

  return true;
}

bool GetAttributes(DWORD& attributes, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U:
    attributes = reinterpret_cast<const USN_RECORD_V2*>(record)->FileAttributes;
    return true;

  case 3U:
    attributes = reinterpret_cast<const USN_RECORD_V3*>(record)->FileAttributes;
    return true;

  default:
    return false;
  }
}

bool GetReason(DWORD& reason, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U:
    reason = reinterpret_cast<const USN_RECORD_V2*>(record)->Reason;
    return true;

  case 3U:
    reason = reinterpret_cast<const USN_RECORD_V3*>(record)->Reason;
    return true;

  default:
    return false;
  }
}

bool GetEventType(USNJournalEventRecord::Type& type,
                  DWORD reason_bit,
                  DWORD journal_file_attributes) {
  auto it = kReasonConversionMap.find(reason_bit);
  if (it == kReasonConversionMap.end()) {
    return false;
  }

  bool is_directory = (journal_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

  const auto& event_type_pair = it->second;
  if (is_directory) {
    type = event_type_pair.second;
  } else {
    type = event_type_pair.first;
  }

  return true;
}

bool GetEventString(std::string& buffer, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  size_t name_offset = 0U;
  size_t name_length = 0U;
  size_t record_length = 0U;

  switch (record->MajorVersion) {
  case 2U: {
    auto temp = reinterpret_cast<const USN_RECORD_V2*>(record)->FileNameOffset;
    name_offset = static_cast<size_t>(temp);

    temp = reinterpret_cast<const USN_RECORD_V2*>(record)->FileNameLength;
    name_length = static_cast<size_t>(temp) / 2U;

    auto temp2 = reinterpret_cast<const USN_RECORD_V2*>(record)->RecordLength;
    record_length = static_cast<size_t>(temp2);

    break;
  }

  case 3U: {
    auto temp = reinterpret_cast<const USN_RECORD_V3*>(record)->FileNameOffset;
    name_offset = static_cast<size_t>(temp);

    temp = reinterpret_cast<const USN_RECORD_V3*>(record)->FileNameLength;
    name_length = static_cast<size_t>(temp) / 2U;

    auto temp2 = reinterpret_cast<const USN_RECORD_V3*>(record)->RecordLength;
    record_length = static_cast<size_t>(temp2);

    break;
  }

  default:
    return false;
  }

  if (name_length == 0U) {
    buffer.clear();
    return true;
  }

  // Make sure we are not going outside of the record boundaries
  auto record_start_ptr = reinterpret_cast<const std::uint8_t*>(record);
  auto record_end_ptr = record_start_ptr + record_length;

  auto string_start_ptr = record_start_ptr + name_offset;
  auto string_end_ptr = string_start_ptr + (name_length * sizeof(WCHAR));

  if (string_end_ptr > record_end_ptr) {
    LOG(ERROR) << "Invalid string length"
               << "record size:" << record_length
               << " name offset:" << name_offset
               << " name length: " << name_length;

    return false;
  }

  std::wstring wide_chars_file_name(
      reinterpret_cast<const wchar_t*>(string_start_ptr), name_length);
  buffer = wstringToString(wide_chars_file_name.c_str());

  return true;
}
}

std::ostream& operator<<(std::ostream& stream,
                         const USNJournalEventRecord::Type& type) {
  auto it = kNTFSEventToStringMap.find(type);
  if (it == kNTFSEventToStringMap.end()) {
    stream << "UnknownEventRecordType";
    return stream;
  }

  const auto& label = it->second;
  stream << label;

  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         const USNFileReferenceNumber& ref) {
  std::ios_base::fmtflags original_stream_settings(stream.flags());

  FILE_ID_DESCRIPTOR native_file_id = {};
  GetNativeFileIdFromUSNReference(native_file_id, ref);

  auto source_ptr = native_file_id.ExtendedFileId.Identifier +
                    sizeof(FILE_ID_128::Identifier) - 1;
  bool skip = true;

  stream << "0x";

  for (auto i = 0U; i < sizeof(FILE_ID_128::Identifier); i++, source_ptr--) {
    auto value = static_cast<int>(*source_ptr);
    if (value == 0 && skip) {
      continue;

    } else {
      stream << std::hex << std::setfill('0') << std::setw(2) << value;
      skip = false;
    }
  }

  stream.flags(original_stream_settings);
  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         const USNJournalEventRecord& record) {
  stream << "journal_record_version:\"" << record.journal_record_version
         << "\" ";

  stream << "drive_letter:\"" << record.drive_letter << "\" ";
  stream << "type:\"" << record.type << "\" ";
  stream << "usn:\"" << record.update_sequence_number << "\" ";
  stream << "parent_ref:\"" << record.parent_ref_number << "\" ";
  stream << "ref:\"" << record.node_ref_number << "\" ";

  {
    std::tm local_time;
    localtime_s(&local_time, &record.record_timestamp);

    char buffer[100] = {};
    std::strftime(buffer, sizeof(buffer), "%y-%m-%d %H:%M:%S", &local_time);

    stream << "timestamp:\"" << buffer << "\" ";
  }

  stream << "attributes:\"";

  bool add_separator = false;
  for (const auto& p : kWindowsFileAttributeMap) {
    const auto& bit = p.first;
    const auto& label = p.second;

    if ((record.attributes & bit) != 0) {
      if (add_separator) {
        stream << " | ";
      }

      stream << label;
      add_separator = true;
    }
  }

  stream << "\"";

  if (!record.name.empty()) {
    stream << " name:\"" << record.name << "\"";
  }

  return stream;
}
} // namespace osquery