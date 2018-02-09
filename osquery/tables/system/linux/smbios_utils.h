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

#include "osquery/tables/system/smbios_utils.h"

namespace osquery {
namespace tables {

/**
 * @brief A flexible SMBIOS parser for Linux.
 *
 * The parsing work is within SMBIOSParser and is shared between platforms.
 * Each OS should implement a discover and set method that implements the
 * OS-specific SMBIOS facilities.
 *
 * On Linux SMBIOS is 'discovered' by reading from known locations in
 * virtual memory or on newer systems, through the sysfs.
 */
class LinuxSMBIOSParser : public SMBIOSParser {
 public:
  /// Attempt to read the system table and SMBIOS from an address.
  void readFromAddress(size_t address, size_t length);

  /// Parse the SMBIOS address from an EFI systab file.
  void readFromSystab(const std::string& systab);

  /// Parse the SMBIOS content from sysfs.
  void readFromSysfs(const std::string& sysfs_dmi);

  /// Cross version/boot read initializer.
  bool discover();

  /// Check if the read was successful.
  bool valid() {
    return (table_data_ != nullptr);
  }

 public:
  virtual ~LinuxSMBIOSParser() {
    if (data_ != nullptr) {
      free(data_);
      data_ = nullptr;
    }
    if (table_data_ != nullptr) {
      free(table_data_);
      table_data_ = nullptr;
    }
  }

 private:
  bool discoverTables(size_t address, size_t length);

  /// Hold the raw SMBIOS memory read.
  uint8_t* data_{nullptr};
};

/**
 * SMBIOS data in the formatted section can BYTE, WORD, DWORD, QWORD lengths.
 * They begin at an offset of the structure examined until the end of
 * length specificed in
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf
 **/

/**
 * @brief Returns uint16_t representation of a WORD length field
 *
 *
 * @param address A pointer to the examined structure.
 * @Param offset The field index into address.
 */
uint16_t linuxDmiToWord(uint8_t* address, uint8_t offset);

/**
 * @brief Returns uint32_t representation of a DWORD length field
 *
 *
 * @param address A pointer to the examined structure.
 * @Param offset The field index into address.
 */
uint32_t linuxDmiToDword(uint8_t* address, uint8_t offset);

/**
 * @brief Returns uint64_t representation of a QWORD length field
 *
 *
 * @param address A pointer to the examined structure.
 * @Param offset The field index into address.
 */
uint64_t linuxDmiToQword(uint8_t* address, uint8_t offset);
} // namespace tables
} // namespace osquery
