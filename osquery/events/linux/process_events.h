/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <asm/unistd_64.h>

#include <set>

namespace osquery {
const std::set<int> kExecProcessEventsSyscalls = {__NR_execve, __NR_execveat};

const std::set<int> kKillProcessEventsSyscalls = {
    __NR_kill, __NR_tkill, __NR_tgkill};

const std::set<int> kForkProcessEventsSyscalls = {
    __NR_fork, __NR_vfork, __NR_clone};
} // namespace osquery
