/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/utils/system/system.h>

#include <string>

namespace osquery {

/**
 * @brief Windows helper function for converting FILETIME to Unix epoch
 *
 * @returns The unix epoch timestamp representation of the FILETIME
 */
LONGLONG filetimeToUnixtime(const FILETIME& ft);

/**
 * @brief Windows helper function for converting LARGE INTs to Unix epoch
 *
 * @returns The unix epoch timestamp representation of the LARGE int value
 */
LONGLONG longIntToUnixtime(LARGE_INTEGER& ft);

/**
* @brief Windows helper function for converting Little Endian FILETIME to Unix epoch. Windows Registry sometimes stores FILETIME in little endian format
* 
* @returns The unix epoch timestamp representation of the FILETIME
*/
LONGLONG littleEndianToUnixTime(const std::string& time_data);

} // namespace osquery
