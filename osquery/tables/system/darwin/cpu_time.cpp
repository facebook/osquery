/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

/*
 *  Inspired from the psutil per_cpu_times function -
 *  https://github.com/giampaolo/psutil/blob/ec1d35e41c288248818388830f0e4f98536b93e4/psutil/_psutil_osx.c#L739
 */

#include <mach/mach.h>
#include <time.h>

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

#define DECLARE_TABLE_IMPLEMENTATION_cpu_time
#include <generated/tables/tbl_cpu_time_defs.hpp>


namespace osquery {
namespace tables {

static inline long int ticks_to_usecs(int ticks) {
  return static_cast<long int>(
      (static_cast<double>(ticks) / CLOCKS_PER_SEC * 1000000));
}

QueryData genCpuTime(QueryContext& context) {
  QueryData results;

  natural_t processor_count;
  processor_cpu_load_info_data_t* processor_times;
  mach_port_t host = mach_host_self();
  mach_msg_type_number_t processor_msg_count;

  kern_return_t ret =
      host_processor_info(host,
                          PROCESSOR_CPU_LOAD_INFO,
                          &processor_count,
                          reinterpret_cast<processor_info_t*>(&processor_times),
                          &processor_msg_count);

  if (ret == KERN_SUCCESS) {
    // Loop through the cores and add rows for each core.
    for (unsigned int core = 0; core < processor_count; core++) {
      Row r;
      r["core"] = INTEGER(core);
      r["user"] = BIGINT(
          ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_USER]));
      r["idle"] = BIGINT(
          ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_IDLE]));
      r["system"] = BIGINT(
          ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_SYSTEM]));
      r["nice"] = BIGINT(
          ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_NICE]));

      results.push_back(r);
    }
    vm_deallocate(
        mach_task_self(),
        reinterpret_cast<vm_address_t>(processor_times),
        static_cast<vm_size_t>(processor_count * sizeof(*processor_times)));
  }
  return results;
}
} // namespace tables
} // namespace osquery
