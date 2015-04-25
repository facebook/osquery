/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/date_time/posix_time/posix_time.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/dispatcher/dispatcher.h"

using namespace apache::thrift::concurrency;

namespace osquery {

/// The worker_threads define the default thread pool size.
FLAG(int32, worker_threads, 4, "Number of work dispatch threads");

void interruptableSleep(size_t milli) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(milli));
}

Dispatcher& Dispatcher::getInstance() {
  static Dispatcher d;
  return d;
}

Dispatcher::Dispatcher() {
  thread_manager_ = InternalThreadManager::newSimpleThreadManager(
      (size_t)FLAGS_worker_threads, 0);
  auto threadFactory = ThriftThreadFactory(new PosixThreadFactory());
  thread_manager_->threadFactory(threadFactory);
  thread_manager_->start();
}

Status Dispatcher::add(ThriftInternalRunnableRef task) {
  try {
    thread_manager_->add(task, 0, 0);
  } catch (std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status Dispatcher::addService(InternalRunnableRef service) {
  if (service->hasRun()) {
    return Status(1, "Cannot schedule a service twice");
  }

  auto thread = std::make_shared<boost::thread>(
      boost::bind(&InternalRunnable::run, &*service));
  service_threads_.push_back(thread);
  services_.push_back(std::move(service));
  return Status(0, "OK");
}

InternalThreadManagerRef Dispatcher::getThreadManager() {
  return thread_manager_;
}

void Dispatcher::join() { thread_manager_->join(); }

void Dispatcher::joinServices() {
  for (auto& thread : getInstance().service_threads_) {
    thread->join();
  }
}

void Dispatcher::removeServices() {
  for (const auto& service : services_) {
    while (true) {
      // Wait for each thread's entry point (enter) meaning the thread context
      // was allocated and (run) was called by boost::thread started.
      if (service->hasRun()) {
        break;
      }
      // We only need to check if std::terminate is call very quickly after
      // the boost::thread is created.
      ::usleep(200);
    }
  }

  for (auto& thread : service_threads_) {
    thread->interrupt();
  }

  // Deallocate services.
  service_threads_.clear();
  services_.clear();
}

InternalThreadManager::STATE Dispatcher::state() const {
  return thread_manager_->state();
}

void Dispatcher::addWorker(size_t value) { thread_manager_->addWorker(value); }

void Dispatcher::removeWorker(size_t value) {
  thread_manager_->removeWorker(value);
}

size_t Dispatcher::idleWorkerCount() const {
  return thread_manager_->idleWorkerCount();
}

size_t Dispatcher::workerCount() const {
  return thread_manager_->workerCount();
}

size_t Dispatcher::pendingTaskCount() const {
  return thread_manager_->pendingTaskCount();
}

size_t Dispatcher::totalTaskCount() const {
  return thread_manager_->totalTaskCount();
}

size_t Dispatcher::pendingTaskCountMax() const {
  return thread_manager_->pendingTaskCountMax();
}

size_t Dispatcher::expiredTaskCount() const {
  return thread_manager_->expiredTaskCount();
}
}
