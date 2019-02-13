/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <osquery/utils/status/status.h>

namespace osquery {

/// Returns a C++ string explaining the errnum
std::string platformStrerr(int errnum);

#ifdef WIN32
/// Converts a Windows error (winerror.h/GetLastError()) to a string
Status getWindowsErrorDescription(std::string& error_message, DWORD error_id);
#endif

}
