/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/events/linux/bpf/iprocesscontextfactory.h>
#include <osquery/events/linux/bpf/isystemstatetracker.h>

#include <functional>
#include <memory>
#include <unordered_map>

#include <unistd.h>

namespace osquery {
class SystemStateTracker final : public ISystemStateTracker {
 public:
  static Ref create();
  static Ref create(IProcessContextFactory::Ref process_context_factory);

  virtual ~SystemStateTracker() override;

  virtual bool createProcess(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      pid_t child_process_id) override;

  virtual bool executeBinary(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int dirfd,
      int flags,
      const std::string& binary_path,
      const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) override;

  virtual bool setWorkingDirectory(pid_t process_id, int dirfd) override;

  virtual bool setWorkingDirectory(pid_t process_id,
                                   const std::string& path) override;

  virtual bool openFile(pid_t process_id,
                        int dirfd,
                        int newfd,
                        const std::string& path,
                        int flags) override;

  virtual bool duplicateHandle(pid_t process_id,
                               int oldfd,
                               int newfd,
                               bool close_on_exec) override;

  virtual bool closeHandle(pid_t process_id, int fd) override;

  virtual bool createSocket(
      pid_t process_id, int domain, int type, int protocol, int fd) override;

  virtual bool bind(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) override;

  virtual bool connect(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) override;

  virtual EventList eventList() override;

  struct Context;
  Context getContextCopy() const;

 private:
  SystemStateTracker(IProcessContextFactory::Ref process_context_factory);

 public:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  struct Context final {
    ProcessContextMap process_map;
    EventList event_list;
  };

  static ProcessContext& getProcessContext(
      Context& context,
      IProcessContextFactory& process_context_factory,
      pid_t process_id);

  static bool createProcess(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      pid_t child_process_id);

  static bool executeBinary(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int dirfd,
      int flags,
      const std::string& binary_path,
      const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv);

  static bool setWorkingDirectory(
      Context& context,
      IProcessContextFactory& process_context_factory,
      pid_t process_id,
      int dirfd);

  static bool setWorkingDirectory(
      Context& context,
      IProcessContextFactory& process_context_factory,
      pid_t process_id,
      const std::string& path);

  static bool openFile(Context& context,
                       IProcessContextFactory& process_context_factory,
                       pid_t process_id,
                       int dirfd,
                       int newfd,
                       const std::string& path,
                       int flags);

  static bool duplicateHandle(Context& context,
                              pid_t process_id,
                              int oldfd,
                              int newfd,
                              bool close_on_exec);

  static bool closeHandle(Context& context,
                          IProcessContextFactory& process_context_factory,
                          pid_t process_id,
                          int fd);

  // clang-format off
  [[deprecated("createSocket() does not have a unit test yet")]]
  // clang-format on
  static bool
  createSocket(Context& context,
               IProcessContextFactory& process_context_factory,
               pid_t process_id,
               int domain,
               int type,
               int protocol,
               int fd);

  // clang-format off
  [[deprecated("bind() does not have a unit test yet")]]
  // clang-format on
  static bool
  bind(Context& context,
       IProcessContextFactory& process_context_factory,
       const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
       pid_t process_id,
       int fd,
       const std::vector<std::uint8_t>& sockaddr);

  // clang-format off
  [[deprecated("connect() does not have a unit test yet")]]
  // clang-format on
  static bool
  connect(Context& context,
          IProcessContextFactory& process_context_factory,
          const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
          pid_t process_id,
          int fd,
          const std::vector<std::uint8_t>& sockaddr);

  // clang-format off
  [[deprecated("parseUnixSockaddr() does not have a unit test yet")]]
  // clang-format on
  static bool
  parseUnixSockaddr(std::string& path,
                    const std::vector<std::uint8_t>& sockaddr);

  // clang-format off
  [[deprecated("parseInetSockaddr() does not have a unit test yet")]]
  // clang-format on
  static bool
  parseInetSockaddr(std::string& address,
                    std::uint16_t& port,
                    const std::vector<std::uint8_t>& sockaddr);

  // clang-format off
  [[deprecated("parseNetlinkSockaddr() does not have a unit test yet")]]
  // clang-format on
  static bool
  parseNetlinkSockaddr(std::string& address,
                       std::uint16_t& port,
                       const std::vector<std::uint8_t>& sockaddr);

  // clang-format off
  [[deprecated("parseInet6Sockaddr() does not have a unit test yet")]]
  // clang-format on
  static bool
  parseInet6Sockaddr(std::string& address,
                     std::uint16_t& port,
                     const std::vector<std::uint8_t>& sockaddr);

  // clang-format off
  [[deprecated("parseSocketAddress() does not have a unit test yet")]]
  // clang-format on
  static bool
  parseSocketAddress(ProcessContext::FileDescriptor::SocketData& socket_data,
                     const std::vector<std::uint8_t>& sockaddr,
                     bool local);
};
} // namespace osquery
