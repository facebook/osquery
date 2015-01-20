/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/md5.h"

namespace osquery {
namespace tables {

#define kIOACPIClassName_ "AppleACPIPlatformExpert"

void genACPITable(const void *key, const void *value, void *results) {
  Row r;

  r["name"] = stringFromCFString((CFStringRef)key);

  auto data = (CFDataRef)value;
  auto length = CFDataGetLength(data);
  r["length"] = INTEGER(length);

  md5::MD5 digest;
  auto md5_digest = digest.digestMemory(CFDataGetBytePtr(data), length);
  r["md5"] = std::string(md5_digest);

  ((QueryData *)results)->push_back(r);
}

QueryData genACPITables(QueryContext& context) {
  QueryData results;

  auto matching = IOServiceMatching(kIOACPIClassName_);
  if (matching == nullptr) {
    // No ACPI platform expert service found.
    return {};
  }

  auto service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
  if (service == 0) {
    return {};
  }

  CFTypeRef table = IORegistryEntryCreateCFProperty(service, CFSTR("ACPI Tables"), kCFAllocatorDefault, 0);
  if (table == nullptr) {
    return {};
  }

  CFDictionaryApplyFunction((CFDictionaryRef)table, genACPITable, &results);

  IOObjectRelease(service);
  return results;
}
}
}
