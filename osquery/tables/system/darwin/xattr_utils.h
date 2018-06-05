/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

namespace osquery {
ssize_t getxattr(const char* path, const char* name, void* value, size_t size);
ssize_t listxattr(const char* path, char* list, size_t size);
int setxattr(const char* path,
             const char* name,
             const void* value,
             size_t size,
             int flags);

Status readSpecialExtendedAttribute(
    std::vector<std::pair<std::string, std::string>>& output,
    const std::string& path,
    const std::string& name);
} // namespace osquery
