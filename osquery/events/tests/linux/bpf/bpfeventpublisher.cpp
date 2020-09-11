/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpftestsmain.h"

#include <osquery/events/linux/bpf/bpfeventpublisher.h>
#include <osquery/events/linux/bpf/systemstatetracker.h>

#include <fcntl.h>

namespace osquery {
namespace {
// clang-format off
const tob::ebpfpub::IFunctionTracer::Event::Header kBaseBPFEventHeader = {
  // timestamp (nsecs from boot)
  1234567890ULL,

  // thread id
  1001,

  // process id
  1001,

  // user id
  1000,

  // group id
  1000,

  // cgroup id
  12345ULL,

  // exit code
  0ULL,

  // probe error flag
  false
};
// clang-format on

// clang-format off
const tob::ebpfpub::IFunctionTracer::Event kBaseBPFEvent = {
  // event identifier
  1,

  // event name
  "",

  // header
  kBaseBPFEventHeader,

  // in field map
  {},

  // out field map
  {}
};
// clang-format on

bool mockedProcessContextFactory(ProcessContext& process_context,
                                 pid_t process_id) {
  process_context = {};

  if (process_id == 2) {
    process_context.parent_process_id = 1;

  } else if (process_id == 1000) {
    process_context.parent_process_id = 2;

  } else if (process_id == 1001) {
    process_context.parent_process_id = 1000;

  } else if (process_id == 1002) {
    return false;

  } else {
    throw std::logic_error(
        "Invalid process id specified in the process context factory");
  }

  process_context.binary_path = "/usr/bin/zsh";
  process_context.argv = {"zsh", "-H", "-i"};
  process_context.cwd = "/home/alessandro";

  // clang-format off
  process_context.fd_map = {
    { 0, { "/dev/pts/1", true } },
    { 1, { "/dev/pts/1", true } },
    { 2, { "/dev/pts/1", true } },
    { 11, { "/usr/share/zsh/functions/VCS_Info.zwc", false } },
    { 12, { "/usr/share/zsh/functions/Completion.zwc", false } },
    { 13, { "/usr/share/zsh/functions/VCS_Info/Backends.zwc", false } },
    { 14, { "/usr/share/zsh/functions/Completion/Base.zwc", false } },
    { 15, { "/usr/share/zsh/functions/Misc.zwc", false } }
  };
  // clang-format on

  return true;
}

bool mockedProcessContextMapFactory(ProcessContextMap& process_map) {
  ProcessContext process_context;
  mockedProcessContextFactory(process_context, 2);

  process_map.insert({2, process_context});
  return true;
}
} // namespace

TEST_F(BPFEventPublisherTests, processForkEvent_and_processVforkEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  //
  // Process creations that returned with an error should be ignored
  //

  // fork()
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "fork";
  bpf_event.header.exit_code = -1; // child process id

  auto succeeded =
      BPFEventPublisher::processForkEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // vfork()
  bpf_event.name = "vfork";

  succeeded = BPFEventPublisher::processVforkEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  //
  // Valid process creations should update the process context
  //

  // fork()
  bpf_event.name = "fork";
  bpf_event.header.exit_code = 1001; // child process id
  bpf_event.header.process_id = 1000; // parent process id
  succeeded = BPFEventPublisher::processForkEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);

  // We should now have 2 entries: the parent process 1000, and the child
  // process 1001
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 3U);

  // vfork()
  bpf_event.name = "vfork";
  bpf_event.header.exit_code = 1002; // child process id
  bpf_event.header.process_id = 1001; // parent process id
  succeeded = BPFEventPublisher::processVforkEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);

  // We should now have one additional process map entry for pid 1002
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 4U);
}

TEST_F(BPFEventPublisherTests, processCloneEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  // Processing should fail if the clone_flags parameter is missing
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "clone";

  auto succeeded =
      BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Add the clone_flags parameter, but update the exit code so that it
  // appears that the syscall has failed. This event should be ignored

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "clone_flags",

      {
        "clone_flags",
        true,
        0ULL
      }
    }
  );
  // clang-format on

  bpf_event.header.exit_code = -1; // child process id

  succeeded = BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Update the exit code so that the syscall succeeds. This should now
  // add two new entries to the process context map, one for the parent
  // and one for the child process
  bpf_event.header.exit_code = 1001; // child process id
  bpf_event.header.process_id = 1000; // parent process id

  succeeded = BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 3U);

  // Update the flags so that the syscall creates a thread; this should
  // be ignored
  bpf_event.in_field_map.at("clone_flags").data_var =
      static_cast<std::uint64_t>(CLONE_THREAD);

  succeeded = BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 3U);
}

TEST_F(BPFEventPublisherTests, processExecveEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "execve";

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/usr/bin/zsh"
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field argv_field = {
    "argv",
    true,

    std::vector<std::string> {
      "zsh",
      "-H",
      "-i"
    }
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({filename_field.name, filename_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({argv_field.name, argv_field});
    }

    auto succeeded =
        BPFEventPublisher::processExecveEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with both parameters
  bpf_event.in_field_map.insert({filename_field.name, filename_field});
  bpf_event.in_field_map.insert({argv_field.name, argv_field});

  auto succeeded =
      BPFEventPublisher::processExecveEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  // We should now have a new entry for the process that called execve
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 2U);
}

TEST_F(BPFEventPublisherTests, processExecveatEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "execveat";

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/usr/bin/zsh"
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field argv_field = {
    "argv",
    true,

    std::vector<std::string> {
      "zsh",
      "-H",
      "-i"
    }
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    static_cast<std::uint64_t>(AT_FDCWD)
  };
  // clang-format on

  for (std::size_t i = 0U; i < 0x0F; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({filename_field.name, filename_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({argv_field.name, argv_field});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    if ((i & 8) != 0) {
      bpf_event.in_field_map.insert({fd_field.name, fd_field});
    }

    auto succeeded =
        BPFEventPublisher::processExecveatEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_TRUE(state_tracker.eventList().empty());
  }

  // Try again with all the parameters
  bpf_event.in_field_map.insert({filename_field.name, filename_field});
  bpf_event.in_field_map.insert({argv_field.name, argv_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});
  bpf_event.in_field_map.insert({fd_field.name, fd_field});

  auto succeeded =
      BPFEventPublisher::processExecveatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  succeeded = BPFEventPublisher::processExecveatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  // We should now have a new entry for the process that called execveat
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 2U);
}

TEST_F(BPFEventPublisherTests, processCloseEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "close";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processCloseEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Try with an invalid fd value. This will be ignored

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "fd",

      {
        "fd",
        true,
        static_cast<std::uint64_t>(-1)
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processCloseEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with a valid fd parameter
  bpf_event.in_field_map.at("fd").data_var = 15ULL;

  succeeded = BPFEventPublisher::processCloseEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now only have 7 file descriptors in the mocked process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 7U);
}

TEST_F(BPFEventPublisherTests, processDupEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "dup";
  bpf_event.header.process_id = 2;

  auto succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Try with an invalid fd value. This will be ignored
  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "fildes",

      {
        "fildes",
        true,
        static_cast<std::uint64_t>(-1)
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Now try again with a valid fd parameter, but set the return value so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.at("fildes").data_var = 15ULL;
  succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Fix the exit code so that the syscall succeeds.
  bpf_event.header.exit_code = 16ULL;
  succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processDup2Event) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "dup2";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field oldfd_field = {
    "oldfd",
    true,
    15ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field newfd_field = {
    "newfd",
    true,
    16ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({newfd_field.name, newfd_field});
    }

    auto succeeded =
        BPFEventPublisher::processDup2Event(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with both parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
  bpf_event.in_field_map.insert({newfd_field.name, newfd_field});

  auto succeeded =
      BPFEventPublisher::processDup2Event(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0;

  succeeded = BPFEventPublisher::processDup2Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processDup3Event) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "dup3";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field oldfd_field = {
    "oldfd",
    true,
    15ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field newfd_field = {
    "newfd",
    true,
    16ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 7; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({newfd_field.name, newfd_field});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    auto succeeded =
        BPFEventPublisher::processDup3Event(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
  bpf_event.in_field_map.insert({newfd_field.name, newfd_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});

  auto succeeded =
      BPFEventPublisher::processDup3Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0;

  succeeded = BPFEventPublisher::processDup3Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processCreatEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "creat";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processCreatEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with the parameter but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "pathname",

      {
        "pathname",
        true,
        "/home/alessandro/test_file.txt"
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processCreatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;

  succeeded = BPFEventPublisher::processCreatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processOpenEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "open";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/home/alessandro/test_file.txt"
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({filename_field.name, filename_field});
    }

    auto succeeded =
        BPFEventPublisher::processOpenEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({filename_field.name, filename_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});

  auto succeeded =
      BPFEventPublisher::processOpenEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;

  succeeded = BPFEventPublisher::processOpenEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processOpenatEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "openat";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/home/alessandro/test_file.txt"
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field dfd_field = {
    "dfd",
    true,
    15ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 7; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({filename_field.name, filename_field});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({dfd_field.name, dfd_field});
    }

    auto succeeded =
        BPFEventPublisher::processOpenatEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({filename_field.name, filename_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});
  bpf_event.in_field_map.insert({dfd_field.name, dfd_field});

  auto succeeded =
      BPFEventPublisher::processOpenatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;

  succeeded = BPFEventPublisher::processOpenatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processChdirEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "chdir";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processChdirEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with the parameter but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "filename",

      {
        "filename",
        true,
        "/root"
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processChdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should not have been changed yet
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).cwd,
            "/home/alessandro");

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0ULL;

  succeeded = BPFEventPublisher::processChdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should now be /root
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).cwd, "/root");
}

TEST_F(BPFEventPublisherTests, processFchdirEvent) {
  auto state_tracker_ref = SystemStateTracker::create(
      mockedProcessContextFactory, mockedProcessContextMapFactory);

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "fchdir";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processFchdirEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with the parameter but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "fd",

      {
        "fd",
        true,
        15ULL
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processFchdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should not have been changed yet
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).cwd,
            "/home/alessandro");

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0ULL;

  succeeded = BPFEventPublisher::processFchdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should now be the same path set in the file descriptor
  // 15
  EXPECT_EQ(
      state_tracker.getContextCopy().process_map.at(2).cwd,
      state_tracker.getContextCopy().process_map.at(2).fd_map.at(15).path);
}
} // namespace osquery
