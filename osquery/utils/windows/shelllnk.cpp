/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <sstream>

#include <iostream>
struct LinkFlags {
  bool has_target_id_list;
  bool has_link_info;
  bool has_name;
  bool has_relative_path;
  bool has_working_dir;
  bool has_arguments;
  bool has_icon_location;
  bool is_unicode;
  bool no_link_info;
  bool has_exp_string;
  bool separate_process;
  bool unused;
  bool has_darwin_id;
  bool run_as_user;
  bool has_icon;
  bool pid_alias;
  bool unused2;
  bool shim_layer;
  bool no_link_track;
  bool target_metadata;
  bool disable_link_path;
  bool disable_folder_tracking;
  bool disable_folder_alias;
  bool link_to_link;
  bool unalias_on_save;
  bool environment_path;
  bool local_id_for_unc_target;
};
struct LinkFileHeader {
  std::string header;
  std::string guid;
  LinkFlags flags;
  std::string file_attribute;
  long long creation_time;
  long long access_time;
  long long modified_time;
  long long file_size;
  std::string icon_index;
  std::string window_value;
  std::string hot_key;
};

struct TargetInfo {
  std::string root_folder;
  std::string path;
  long long mft_entry;
  int mft_sequence;
  std::string data;
};

struct LocationInfo {
  std::string type;
  std::string serial;
  std::string data;
  std::string local_path;
  std::string common_path;
  std::string share_name;
};

struct DataStringInfo {
  std::string description;
  std::string relative_path;
  std::string working_path;
  std::string arguments;
  std::string icon_location;
  std::string data;
};

struct ExtraDataTracker {
  std::string hostname;
  std::string droid_volume;
  std::string droid_file;
  std::string birth_droid_volume;
  std::string birth_droid_file;
};

namespace osquery {
LinkFlags parseShortcutFlags(const std::string& flags) {
  std::string flags_swap = swapEndianess(flags);
  int flags_int = std::stoi(flags_swap, nullptr, 16);
  LinkFlags lnk_flags;
  lnk_flags.has_target_id_list = (bool)(flags_int & 0x1);
  lnk_flags.has_link_info = (bool)(flags_int & 0x2);
  lnk_flags.has_name = (bool)(flags_int & 0x4);
  lnk_flags.has_relative_path = (bool)(flags_int & 0x8);
  lnk_flags.has_working_dir = (bool)(flags_int & 0x10);
  lnk_flags.has_arguments = (bool)(flags_int & 0x20);
  lnk_flags.has_icon_location = (bool)(flags_int & 0x40);
  lnk_flags.is_unicode = (bool)(flags_int & 0x80);
  lnk_flags.no_link_info = (bool)(flags_int & 0x100);
  lnk_flags.has_exp_string = (bool)(flags_int & 0x200);
  lnk_flags.separate_process = (bool)(flags_int & 0x400);
  lnk_flags.unused = (bool)(flags_int & 0x800);
  lnk_flags.has_darwin_id = (bool)(flags_int & 0x1000);
  lnk_flags.run_as_user = (bool)(flags_int & 0x2000);
  lnk_flags.has_icon = (bool)(flags_int & 0x4000);
  lnk_flags.pid_alias = (bool)(flags_int & 0x5000);
  lnk_flags.unused2 = (bool)(flags_int & 0x10000);
  lnk_flags.shim_layer = (bool)(flags_int & 0x20000);
  lnk_flags.no_link_track = (bool)(flags_int & 0x40000);
  lnk_flags.target_metadata = (bool)(flags_int & 0x80000);
  lnk_flags.disable_link_path = (bool)(flags_int & 0x100000);
  lnk_flags.disable_folder_tracking = (bool)(flags_int & 0x200000);
  lnk_flags.disable_folder_alias = (bool)(flags_int & 0x400000);
  lnk_flags.link_to_link = (bool)(flags_int & 0x800000);
  lnk_flags.unalias_on_save = (bool)(flags_int & 0x1000000);
  lnk_flags.environment_path = (bool)(flags_int & 0x2000000);
  lnk_flags.local_id_for_unc_target = (bool)(flags_int & 0x4000000);
  return lnk_flags;
}
LinkFileHeader parseShortcutHeader(const std::string& header) {
  LinkFileHeader lnk_header;

  if (header.size() < 132) {
    LOG(WARNING) << "Header size smaller than expected: " << header;
    lnk_header.header = "";
    return lnk_header;
  }
  lnk_header.header = header.substr(0, 8);
  lnk_header.guid = header.substr(8, 32);
  std::string header_flags = header.substr(40, 8);
  lnk_header.flags = parseShortcutFlags(header_flags);
  lnk_header.file_attribute = header.substr(48, 8);
  std::string target_timestamp = header.substr(56, 16);
  if (target_timestamp == "0000000000000000") {
    lnk_header.creation_time = 0LL;
  } else {
    lnk_header.creation_time = littleEndianToUnixTime(target_timestamp);
  }
  target_timestamp = header.substr(72, 16);
  if (target_timestamp == "0000000000000000") {
    lnk_header.access_time = 0LL;
  } else {
    lnk_header.access_time = littleEndianToUnixTime(target_timestamp);
  }
  target_timestamp = header.substr(88, 16);
  if (target_timestamp == "0000000000000000") {
    lnk_header.modified_time = 0LL;
  } else {
    lnk_header.modified_time = littleEndianToUnixTime(target_timestamp);
  }
  std::string file_size_str = swapEndianess(header.substr(104, 8));

  lnk_header.file_size = std::stoll(file_size_str, nullptr, 16);
  lnk_header.icon_index = header.substr(112, 8);
  lnk_header.window_value = header.substr(120, 8);
  lnk_header.hot_key = header.substr(128, 4);
  return lnk_header;
}
TargetInfo parseTargetInfo(const std::string& target_info) {
    // Skip the first two bytes
  std::string data = target_info.substr(4);
  TargetInfo target_lnk;
  std::vector<std::string> build_path;
  ShellFileEntryData file_entry;
  file_entry.mft_entry = -1LL;
  file_entry.mft_sequence = -1;
  // Loop through all the shellitems
  while (true) {
    std::string str_item_size = data.substr(0, 4);
    str_item_size = swapEndianess(str_item_size);
    int item_size = std::stoi(str_item_size, nullptr, 16) * 2;
    // Empty target item sizes will cause infinte loop, sometimes at the end of
    // the item there will be extra zeros
    if (item_size == 0) {
      break;
    }
    std::string sig = data.substr(4, 2);
    std::string item_string = data.substr(0, item_size);
    if (sig == "1F") {
      target_lnk.root_folder = rootFolderItem(item_string);
      data.erase(0, item_size);
      continue;
    } else if (sig == "31" || sig == "30" || sig == "32" || sig == "35" ||
               sig == "B1") {
      file_entry = fileEntry(item_string);
      build_path.push_back(file_entry.path);
      data.erase(0, item_size);
      continue;
    } else if (sig == "2F" || sig == "23" || sig == "25" || sig == "29" ||
               sig == "2A" || sig == "2E") {
      if (item_string.substr(6, 2) == "80" ||
          (item_string.find("2600EFBE") != std::string::npos ||
           item_string.find("2500EFBE") !=
               std::string::npos)) { // Check if GUID exists
        std::string guid_little = item_string.substr(8, 32);
        std::string guid_string = guidParse(guid_little);

        build_path.push_back("{" + guid_string + "}");
        data.erase(0, item_size);
        continue;
      }
      std::string drive = driveLetterItem(item_string);
      drive.pop_back();
      build_path.push_back(drive);
      data.erase(0, item_size);
      continue;
    } else if ((sig == "74") &&
               item_string.find("43465346") != std::string::npos) {
      file_entry = fileEntry(item_string);
      build_path.push_back(file_entry.path);
      data.erase(0, item_size);
      continue;
    } else if ((sig == "61")) {
      std::vector<std::string> ftp_data = ftpItem(item_string);
      build_path.push_back(ftp_data[1]);
      data.erase(0, item_size);
      continue;
    } else if (sig == "00") { // Variable shell item, can contain a variety of
                              // shell item formats
      if (item_string.find("EEBBFE23") != std::string::npos) {
        std::string guid_string = variableGuid(item_string);
        build_path.push_back("{" + guid_string + "}");
        data.erase(0, item_size);
        continue;
      } else if (item_string.substr(12, 8) == "05000000" ||
                 item_string.substr(12, 8) == "05000300") {
        std::string ftp_name = variableFtp(item_string);
        build_path.push_back(ftp_name);
        data.erase(0, item_size);
        continue;
      }
    }
    break;
  }
  target_lnk.path = osquery::join(build_path, "\\");
  target_lnk.mft_entry = file_entry.mft_entry;
  target_lnk.mft_sequence = file_entry.mft_sequence;
  target_lnk.data = data;
  return target_lnk;
}
LocationInfo parseLocationData(const std::string& location_data) {
  LocationInfo location_info;
  std::string data = location_data.substr(4);
  std::string str_location_size = data.substr(0, 8);
  str_location_size = swapEndianess(str_location_size);
  int location_size = std::stoi(str_location_size, nullptr, 16) * 2;

  std::string location_type = data.substr(16, 8);
  location_type = swapEndianess(location_type);

  if (location_type == "00000001") {
    std::string volume_offset = data.substr(24, 8);
    volume_offset = swapEndianess(volume_offset);
    int offset = std::stoi(volume_offset, nullptr, 16);
    std::string type = data.substr((offset * 2) + 8, 8);
    if (type == "03000000") {
      location_info.type = "Fixed storage media (harddisk)";
    } else if (type == "00000000") {
      location_info.type = "Unknown";
    } else if (type == "01000000") {
      location_info.type = "No root directory";
    } else if (type == "04000000") {
      location_info.type = "Remote storage";
    } else if (type == "05000000") {
      location_info.type = "Optical disc (CD-ROM, DVD, BD)";
    } else if (type == "06000000") {
      location_info.type = "RAM drive";
    } else {
      LOG(WARNING) << "Unknown volume type: " << type;
      data.erase(0, location_size);
      location_info.data = data;
      return location_info;
    }
    std::string local_path_offset = data.substr(32, 8);
    local_path_offset = swapEndianess(local_path_offset);
    int path_offset = std::stoi(local_path_offset, nullptr, 16) * 2;
    size_t local_path_size = data.find("00", path_offset);
    // Size should be even but if values end in base 10 it will be odd
    if (local_path_size % 2 != 0) {
      local_path_size++;
    }
    std::string local_path =
        data.substr(path_offset, local_path_size - path_offset);
    try {
      location_info.local_path = boost::algorithm::unhex(local_path);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode local path hex values to string: "
                   << local_path;
    }
    std::string serial = data.substr((offset * 2) + 16, 8);
    location_info.serial = swapEndianess(serial);
  } else if (location_type == "00000002") {
    std::string network_offset = data.substr(40, 8);
    network_offset = swapEndianess(network_offset);
    int offset = std::stoi(network_offset, nullptr, 16);
    std::string type = data.substr((offset * 2) + 32, 8);
    if (type == "00001a00") {
      location_info.type = "WNNC_NET_AVID";
    } else if (type == "00001b00") {
      location_info.type = "WNNC_NET_DOCUSPACE";
    } else if (type == "00001c00") {
      location_info.type = "WNNC_NET_MANGOSOFT";
    } else if (type == "00001d00") {
      location_info.type = "WNNC_NET_SERNET";
    } else if (type == "00001e00") {
      location_info.type = "WNNC_NET_RIVERFRONT1";
    } else if (type == "00001f00") {
      location_info.type = "WNNC_NET_RIVERFRONT2";
    } else if (type == "00002000") {
      location_info.type = "WNNC_NET_DECORB";
    } else if (type == "00002100") {
      location_info.type = "WNNC_NET_PROTSTOR";
    } else if (type == "00002200") {
      location_info.type = "WNNC_NET_FJ_REDIR";
    } else if (type == "00002300") {
      location_info.type = "WNNC_NET_DISTINCT";
    } else if (type == "00002400") {
      location_info.type = "WNNC_NET_TWINS";
    } else if (type == "00002500") {
      location_info.type = "WNNC_NET_RDR2SAMPLE";
    } else if (type == "00002600") {
      location_info.type = "WNNC_NET_CSC";
    } else if (type == "00002700") {
      location_info.type = "WNNC_NET_3IN1";
    } else if (type == "00002900") {
      location_info.type = "WNNC_NET_EXTENDNET";
    } else if (type == "00002a00") {
      location_info.type = "WNNC_NET_STAC";
    } else if (type == "00002b00") {
      location_info.type = "WNNC_NET_FOXBAT";
    } else if (type == "00002c00") {
      location_info.type = "WNNC_NET_YAHOO";
    } else if (type == "00002d00") {
      location_info.type = "WNNC_NET_EXIFS";
    } else if (type == "00002e00") {
      location_info.type = "WNNC_NET_DAV";
    } else if (type == "00002f00") {
      location_info.type = "WNNC_NET_KNOWARE";
    } else if (type == "00003000") {
      location_info.type = "WNNC_NET_OBJECT_DIRE";
    } else if (type == "00003100") {
      location_info.type = "WNNC_NET_MASFAX";
    } else if (type == "00003200") {
      location_info.type = "WNNC_NET_HOB_NFS";
    } else if (type == "00003300") {
      location_info.type = "WNNC_NET_SHIVA";
    } else if (type == "00003400") {
      location_info.type = "WNNC_NET_IBMAL";
    } else if (type == "00003500") {
      location_info.type = "WNNC_NET_LOCK";
    } else if (type == "00003600") {
      location_info.type = "WNNC_NET_TERMSRV";
    } else if (type == "00003700") {
      location_info.type = "WNNC_NET_SRT";
    } else if (type == "00003800") {
      location_info.type = "WNNC_NET_QUINCY";
    } else if (type == "00003900") {
      location_info.type = "WNNC_NET_OPENAFS";
    } else if (type == "00003a00") {
      location_info.type = "WNNC_NET_AVID1";
    } else if (type == "00003b00") {
      location_info.type = "WNNC_NET_DFS";
    } else if (type == "00003c00") {
      location_info.type = "WNNC_NET_KWNP";
    } else if (type == "00003d00") {
      location_info.type = "WNNC_NET_ZENWORKS";
    } else if (type == "00003e00") {
      location_info.type = "WNNC_NET_DRIVEONWEB";
    } else if (type == "00003f00") {
      location_info.type = "WNNC_NET_VMWARE";
    } else if (type == "00004000") {
      location_info.type = "WNNC_NET_RSFX";
    } else if (type == "00004100") {
      location_info.type = "WNNC_NET_MFILES";
    } else if (type == "00004200") {
      location_info.type = "WNNC_NET_MS_NFS";
    } else if (type == "00004300") {
      location_info.type = "WNNC_NET_GOOGLE";
    } else {
      LOG(WARNING) << "Unknown network type: " << type;
      data.erase(0, location_size);
      location_info.data = data;
      return location_info;
    }
    std::string common_path_offset = data.substr(48, 8);
    common_path_offset = swapEndianess(common_path_offset);
    int path_offset = std::stoi(common_path_offset, nullptr, 16) * 2;
    size_t common_path_size = data.find("00", path_offset);
    if (common_path_size % 2 != 0) {
      common_path_size++;
    }
    std::string common_path =
        data.substr(path_offset, common_path_size - path_offset);
    try {
      location_info.common_path = boost::algorithm::unhex(common_path);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode common path hex values to string: "
                   << common_path;
    }
    std::string share_name_offset = data.substr((offset * 2) + 16, 8);
    share_name_offset = swapEndianess(share_name_offset);
    int share_offset = std::stoi(share_name_offset, nullptr, 16);
    size_t share_name_size = data.find("00", (offset * 2) + share_offset * 2);
    std::string share_name =
        data.substr((offset * 2) + share_offset * 2,
                    share_name_size - ((offset * 2) + share_offset * 2));
    try {
      location_info.share_name = boost::algorithm::unhex(share_name);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode share name hex values to string: "
                   << share_name;
    }
  } else {
    LOG(WARNING) << "Unknown location type: " << location_type;
  }
  data.erase(0, location_size);
  location_info.data = data;
  return location_info;
}
DataStringInfo parseDataString(const std::string& data,
                               bool unicode,
                               bool& description,
                               bool& relative_path,
                               bool& working_path,
                               bool& icon_location,
                               bool& command_args) {
  std::string data_string = data;
  std::string data_str_type = "";
  DataStringInfo data_info;
  std::string str_data_size = data_string.substr(0, 4);
  str_data_size = swapEndianess(str_data_size);
  int data_size = std::stoi(str_data_size, nullptr, 16);
  if (description) {
    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.description = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Description hex values to string: "
                   << data_str_type;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  if (relative_path) {
    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.relative_path = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Relative Path hex values to string: "
                   << data_str_type;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  if (working_path) {
    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.working_path = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Working Path hex values to string: "
                   << data_str_type;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  if (command_args) {
    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.arguments = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Command args hex values to string: "
                   << data_str_type;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  if (icon_location) {
    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.icon_location = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Icon Location hex values to string: "
                   << data_str_type;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  data_info.data = data_string;
  return data_info;
}
ExtraDataTracker parseExtraDataTracker(const std::string& data) {
  ExtraDataTracker data_tracker;
  // Check for tracker database, contains hostname. It may not exist.
  if ((data.find("60000000") == std::string::npos) ||
      (data.find("030000A0") == std::string::npos)) {
    data_tracker.hostname = "";
    return data_tracker;
  }
  size_t extra_offset = data.find("030000A0") + 24;
  std::string hostname = data.substr(extra_offset, 32);
  try {
    data_tracker.hostname = boost::algorithm::unhex(hostname);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode hostname hex values to string: "
                 << hostname;
  }
  std::string guid = data.substr(extra_offset + 56, 32);
  data_tracker.droid_volume = guidParse(guid);
  guid = data.substr(extra_offset + 88, 32);
  data_tracker.droid_file = guidParse(guid);
  guid = data.substr(extra_offset + 120, 32);
  data_tracker.birth_droid_volume = guidParse(guid);
  guid = data.substr(extra_offset + 152, 32);
  data_tracker.birth_droid_file = guidParse(guid);
  return data_tracker;
}
} // namespace osquery