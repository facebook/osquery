/*
 *
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

#include <osquery/tables.h>

#import <IOKit/ps/IOPSKeys.h>
#import <IOKit/ps/IOPowerSources.h>
#import <IOKit/pwr_mgt/IOPM.h>
#import <IOKit/pwr_mgt/IOPMLib.h>

namespace osquery {
namespace tables {

NSDictionary* getIopmBatteryInfo() {
  CFTypeRef info = IOPSCopyPowerSourcesInfo();

  if (info == NULL)
    return NULL;

  CFArrayRef list = IOPSCopyPowerSourcesList(info);

  // Release if there are not viable battery sources
  if (list == NULL || !CFArrayGetCount(list)) {
    if (list) {
      CFRelease(list);
    }
    CFRelease(info);
    return NULL;
  }

  // Assumes the first battery returned in the array is the internal battery
  CFDictionaryRef battery = CFDictionaryCreateCopy(
      NULL,
      IOPSGetPowerSourceDescription(info, CFArrayGetValueAtIndex(list, 0)));

  CFRelease(list);
  CFRelease(info);

  return (__bridge_transfer NSDictionary*)battery;
}

NSDictionary* getIopmpsBatteryInfo() {
  CFMutableDictionaryRef matching, properties = NULL;
  io_registry_entry_t entry = 0;
  matching = IOServiceNameMatching("AppleSmartBattery");
  entry = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
  IORegistryEntryCreateCFProperties(entry, &properties, NULL, 0);
  return (__bridge_transfer NSDictionary*)properties;
}

QueryData genBatteryInfo(QueryContext& context) {
  QueryData results;
  Row r;

  NSDictionary* batteryInfo = getIopmBatteryInfo();
  NSDictionary* advancedBatteryInfo = getIopmpsBatteryInfo();

  // Don't return any rows if we don't have battery data.
  if (batteryInfo == NULL && advancedBatteryInfo == NULL) {
    return results;
  }

  if ([advancedBatteryInfo objectForKey:@"Manufacturer"]) {
    r["manufacturer"] =
        TEXT([[advancedBatteryInfo objectForKey:@"Manufacturer"] UTF8String]);
  }

  if ([advancedBatteryInfo objectForKey:@kIOPMPSManufactureDateKey]) {
    // Date is published in a bitfield per the Smart Battery Data spec rev 1.1
    // in section 5.1.26 Bits 0...4 => day (value 1-31; 5 bits) Bits 5...8 =>
    // month (value 1-12; 4 bits) Bits 9...15 => years since 1980 (value 0-127;
    // 7 bits)
    int dateMask = [
        [advancedBatteryInfo objectForKey:@kIOPMPSManufactureDateKey] intValue];
    int day = dateMask & 31;
    int month = (dateMask >> 5) & 15;
    int year = (dateMask >> 9) + 1980;

    NSCalendar* calendar = [[NSCalendar alloc]
        initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
    calendar.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    NSDateComponents* components = [[NSDateComponents alloc] init];
    [components setDay:day];
    [components setMonth:month];
    [components setYear:year];
    NSDate* date = [calendar dateFromComponents:components];

    r["manufacture_date"] = INTEGER([date timeIntervalSince1970]);
  }

  if ([advancedBatteryInfo objectForKey:@kIOPMDeviceNameKey]) {
    r["model"] = TEXT(
        [[advancedBatteryInfo objectForKey:@kIOPMDeviceNameKey] UTF8String]);
  }

  if ([batteryInfo objectForKey:@kIOPSHardwareSerialNumberKey]) {
    r["serial_number"] = TEXT(
        [[batteryInfo objectForKey:@kIOPSHardwareSerialNumberKey] UTF8String]);
  }

  if ([advancedBatteryInfo objectForKey:@"CycleCount"]) {
    r["cycle_count"] =
        INTEGER([[advancedBatteryInfo objectForKey:@"CycleCount"] intValue]);
  }

  if ([batteryInfo objectForKey:@kIOPSBatteryHealthKey]) {
    r["health"] =
        TEXT([[batteryInfo objectForKey:@kIOPSBatteryHealthKey] UTF8String]);
  }

  if ([batteryInfo objectForKey:@kIOPSBatteryHealthConditionKey]) {
    r["condition"] = TEXT([
        [batteryInfo objectForKey:@kIOPSBatteryHealthConditionKey] UTF8String]);
  } else {
    r["condition"] = TEXT("Normal");
  }

  if ([batteryInfo objectForKey:@kIOPSPowerSourceStateKey]) {
    r["state"] =
        TEXT([[batteryInfo objectForKey:@kIOPSPowerSourceStateKey] UTF8String]);
  }

  if ([batteryInfo objectForKey:@kIOPSIsChargingKey]) {
    r["charging"] =
        INTEGER([[batteryInfo objectForKey:@kIOPSIsChargingKey] intValue]);
  }

  if ([batteryInfo objectForKey:@kIOPSIsChargedKey]) {
    r["charged"] =
        INTEGER([[batteryInfo objectForKey:@kIOPSIsChargedKey] intValue]);
  } else {
    // the absence of this value means the battery is not fully charged
    r["charged"] = INTEGER(0);
  }

  if ([advancedBatteryInfo objectForKey:@"DesignCapacity"]) {
    r["designed_capacity"] = INTEGER(
        [[advancedBatteryInfo objectForKey:@"DesignCapacity"] intValue]);
  }

  if ([advancedBatteryInfo objectForKey:@"MaxCapacity"]) {
    r["max_capacity"] =
        INTEGER([[advancedBatteryInfo objectForKey:@"MaxCapacity"] intValue]);
  }

  if ([advancedBatteryInfo objectForKey:@"CurrentCapacity"]) {
    r["current_capacity"] = INTEGER(
        [[advancedBatteryInfo objectForKey:@"CurrentCapacity"] intValue]);
  }

  if ([batteryInfo objectForKey:@kIOPSCurrentCapacityKey]) {
    r["percent_remaining"] =
        INTEGER([[batteryInfo objectForKey:@kIOPSCurrentCapacityKey] intValue]);
  }

  if ([advancedBatteryInfo objectForKey:@kIOPSVoltageKey]) {
    r["amperage"] =
        INTEGER([[advancedBatteryInfo objectForKey:@"Amperage"] intValue]);
  }

  if ([advancedBatteryInfo objectForKey:@kIOPSVoltageKey]) {
    r["voltage"] =
        INTEGER([[advancedBatteryInfo objectForKey:@kIOPSVoltageKey] intValue]);
  }

  if ([batteryInfo objectForKey:@kIOPSTimeToEmptyKey]) {
    r["minutes_until_empty"] =
        BIGINT([[batteryInfo objectForKey:@kIOPSTimeToEmptyKey] intValue]);
  }

  if ([batteryInfo objectForKey:@kIOPSTimeToFullChargeKey]) {
    r["minutes_to_full_charge"] =
        BIGINT([[batteryInfo objectForKey:@kIOPSTimeToFullChargeKey] intValue]);
  }

  results.push_back(r);
  return results;
}

} // namespace tables
} // namespace osquery
