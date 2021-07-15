/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/events/eventfactory.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>

namespace osquery {

namespace {

/**
 * @brief Details for each subscriber as it relates to the schedule.
 *
 * This is populated for each configuration update by scanning the schedule.
 */
struct SubscriberExpirationDetails {
 public:
  /// The max internal is the minimum wait time for expiring subscriber data.
  size_t max_interval{0};

  /// The number of queries that should run between intervals.
  size_t query_count{0};
};

} // namespace

FLAG(bool, disable_events, false, "Disable osquery publish/subscribe system");

// There's no reason for the event factory to keep multiple instances.
EventFactory& EventFactory::getInstance() {
  static EventFactory ef;
  return ef;
}

Status EventFactory::registerEventSubscriber(const PluginRef& sub) {
  auto base_sub = std::dynamic_pointer_cast<EventSubscriberPlugin>(sub);

  if (base_sub == nullptr) {
    return Status::failure("Invalid subscriber type: " + sub->getName());
  }

  // The config may use an "events" key to explicitly enabled or disable
  // event subscribers. See EventSubscriber::disable.
  auto name = base_sub->getName();
  if (name.empty()) {
    // This subscriber did not override its name.
    return Status::failure("Subscribers must have set a name");
  }

  auto plugin = Config::get().getParser("events");
  if (plugin != nullptr && plugin.get() != nullptr) {
    const auto& data = plugin->getData().doc();
    // First perform explicit enabling.
    if (data["events"].HasMember("enable_subscribers") &&
        data["events"]["enable_subscribers"].IsArray()) {
      for (const auto& item : data["events"]["enable_subscribers"].GetArray()) {
        if (item.GetString() == name) {
          VLOG(1) << "Enabling event subscriber: " << name;
          base_sub->disabled = false;
        }
      }
    }
    // Then use explicit disabling as an ultimate override.
    if (data["events"].HasMember("disable_subscribers") &&
        data["events"]["disable_subscribers"].IsArray()) {
      for (const auto& item :
           data["events"]["disable_subscribers"].GetArray()) {
        if (item.GetString() == name) {
          VLOG(1) << "Disabling event subscriber: " << name;
          base_sub->disabled = true;
        }
      }
    }
  }

  if (base_sub->state() != EventState::EVENT_NONE) {
    base_sub->tearDown();
  }

  // Allow subscribers a configure-time setup to determine if they should run.
  auto status = base_sub->setUp();
  if (!status) {
    base_sub->disabled = true;
  }
  base_sub->state(EventState::EVENT_SETUP);

  // Let the subscriber initialize any Subscriptions.
  if (!FLAGS_disable_events && !base_sub->disabled) {
    status = base_sub->init();
    base_sub->state(EventState::EVENT_RUNNING);
  } else {
    base_sub->state(EventState::EVENT_PAUSED);
  }

  auto& ef = EventFactory::getInstance();
  {
    RecursiveLock lock(ef.factory_lock_);
    ef.event_subs_[name] = base_sub;
  }

  // Set state of subscriber.
  if (!status.ok()) {
    base_sub->state(EventState::EVENT_FAILED);
    return Status::failure(status.getMessage());
  } else {
    return Status::success();
  }
}

Status EventFactory::registerEventPublisher(const PluginRef& pub) {
  auto base_pub = std::dynamic_pointer_cast<EventPublisherPlugin>(pub);

  if (base_pub == nullptr) {
    return Status::failure("Invalid publisher type: " + pub->getName());
  }

  auto type_id = base_pub->type();
  if (type_id.empty()) {
    // This publisher did not override its name.
    return Status::failure("Publishers must have a type");
  }

  auto& ef = EventFactory::getInstance();
  {
    RecursiveLock lock(ef.factory_lock_);
    if (ef.event_pubs_.count(type_id) != 0) {
      // This is a duplicate event publisher.
      return Status::failure("Duplicate publisher type");
    }

    ef.event_pubs_[type_id] = base_pub;
  }

  // Do not set up event publisher if events are disabled.
  if (!FLAGS_disable_events) {
    if (base_pub->state() != EventState::EVENT_NONE) {
      base_pub->tearDown();
    }

    auto status = base_pub->setUp();
    base_pub->state(EventState::EVENT_SETUP);
    if (!status.ok()) {
      // Only start event loop if setUp succeeds.
      LOG(INFO) << "Event publisher not enabled: " << type_id << ": "
                << status.what();
      base_pub->isEnding(true);
      return status;
    }
  }

  return Status::success();
}

Status EventFactory::deregisterEventSubscriber(const std::string& sub) {
  auto& ef = EventFactory::getInstance();

  RecursiveLock lock(ef.factory_lock_);

  auto subscriber_it = ef.event_subs_.find(sub);
  if (subscriber_it == ef.event_subs_.end()) {
    return Status::failure("Event subscriber is missing");
  }

  auto subscriber = subscriber_it->second;
  ef.event_subs_.erase(subscriber_it);

  subscriber->tearDown();
  subscriber->state(EventState::EVENT_NONE);

  return Status(0);
}

Status EventFactory::addSubscription(const std::string& type_id,
                                     const std::string& name_id,
                                     const SubscriptionContextRef& mc,
                                     EventCallback cb) {
  auto subscription = Subscription::create(name_id, mc, cb);
  return EventFactory::addSubscription(type_id, subscription);
}

Status EventFactory::addSubscription(const std::string& type_id,
                                     const SubscriptionRef& subscription) {
  EventPublisherRef publisher = getInstance().getEventPublisher(type_id);
  if (publisher == nullptr) {
    return Status::failure("Unknown event publisher");
  }

  // The event factory is responsible for configuring the event types.
  return publisher->addSubscription(subscription);
}

size_t EventFactory::numSubscriptions(const std::string& type_id) {
  EventPublisherRef publisher;
  try {
    publisher = EventFactory::getInstance().getEventPublisher(type_id);
  } catch (std::out_of_range& /* e */) {
    return 0;
  }
  if (publisher == nullptr) {
    return 0;
  }
  return publisher->numSubscriptions();
}

size_t EventFactory::numEventPublishers() {
  return EventFactory::getInstance().event_pubs_.size();
}

Status EventFactory::deregisterEventPublisher(const EventPublisherRef& pub) {
  return EventFactory::deregisterEventPublisher(pub->type());
}

Status EventFactory::deregisterEventPublisher(const std::string& type_id) {
  auto& ef = EventFactory::getInstance();

  RecursiveLock lock(ef.factory_lock_);
  EventPublisherRef publisher = ef.getEventPublisher(type_id);
  if (publisher == nullptr) {
    return Status::failure("No event publisher to deregister");
  }

  if (!FLAGS_disable_events) {
    publisher->isEnding(true);
    if (!publisher->hasStarted()) {
      // If a publisher's run loop was not started, call tearDown since
      // the setUp happened at publisher registration time.
      publisher->tearDown();
      publisher->state(EventState::EVENT_NONE);
      // If the run loop did run the tear down and erase will happen in the
      // event thread wrapper when isEnding is next checked.
      ef.event_pubs_.erase(type_id);
    } else {
      publisher->stop();
    }
  }
  return Status::success();
}

EventPublisherRef EventFactory::getEventPublisher(const std::string& type_id) {
  auto& ef = EventFactory::getInstance();

  RecursiveLock lock(ef.factory_lock_);
  if (ef.event_pubs_.count(type_id) == 0) {
    LOG(ERROR) << "Requested unknown/failed event publisher: " << type_id;
    return nullptr;
  }
  return ef.event_pubs_.at(type_id);
}

EventSubscriberRef EventFactory::getEventSubscriber(
    const std::string& name_id) {
  auto& ef = EventFactory::getInstance();

  RecursiveLock lock(ef.factory_lock_);
  if (!exists(name_id)) {
    LOG(ERROR) << "Requested unknown event subscriber: " << name_id;
    return nullptr;
  }
  return ef.event_subs_.at(name_id);
}

bool EventFactory::exists(const std::string& name_id) {
  return (getInstance().event_subs_.count(name_id) > 0);
}

std::set<std::string> EventFactory::publisherTypes() {
  RecursiveLock lock(getInstance().factory_lock_);
  std::set<std::string> types;
  for (const auto& publisher : getInstance().event_pubs_) {
    types.insert(publisher.first);
  }
  return types;
}

std::set<std::string> EventFactory::subscriberNames() {
  RecursiveLock lock(getInstance().factory_lock_);
  std::set<std::string> names;
  for (const auto& subscriber : getInstance().event_subs_) {
    names.insert(subscriber.first);
  }
  return names;
}

void EventFactory::addForwarder(const std::string& logger) {
  getInstance().loggers_.push_back(logger);
}

void EventFactory::forwardEvent(const std::string& event) {
  for (const auto& logger : getInstance().loggers_) {
    Registry::call("logger", logger, {{"event", event}});
  }
}

void EventFactory::configUpdate() {
  // Scan the schedule for queries that touch "_events" tables.
  // We will count the queries
  std::map<std::string, SubscriberExpirationDetails> subscriber_details;

  Config::get().scheduledQueries(
      [&subscriber_details](std::string name, const ScheduledQuery& query) {
        std::vector<std::string> tables;
        // Convert query string into a list of virtual tables effected.
        if (!getQueryTables(query.query, tables)) {
          VLOG(1) << "Cannot get tables from query: " << name;
          return;
        }

        // Remove duplicates and select only the subscriber tables.
        std::set<std::string> subscribers;
        for (const auto& table : tables) {
          if (Registry::get().exists("event_subscriber", table)) {
            subscribers.insert(table);
          }
        }

        for (const auto& subscriber : subscribers) {
          auto& details = subscriber_details[subscriber];
          details.max_interval = (query.interval > details.max_interval)
                                     ? query.interval
                                     : details.max_interval;
          details.query_count++;
        }
      });

  auto& ef = EventFactory::getInstance();
  for (const auto& details : subscriber_details) {
    if (!ef.exists(details.first)) {
      continue;
    }

    RecursiveLock lock(ef.factory_lock_);
    auto subscriber = ef.getEventSubscriber(details.first);
    auto min_expiry = details.second.max_interval * 3;
    min_expiry += (60 - (min_expiry % 60));
    subscriber->setMinExpiry(min_expiry);

    // Emit a warning for each subscriber affected by the small expiration.
    auto expiry = subscriber->getEventsExpiry();
    if (expiry > 0 && min_expiry > expiry) {
      LOG(INFO) << "The minimum events expiration timeout for "
                << subscriber->getName()
                << " has been adjusted: " << min_expiry;
    }
    subscriber->resetQueryCount(details.second.query_count);
  }

  // If events are enabled configure the subscribers before publishers.
  if (!FLAGS_disable_events) {
    RegistryFactory::get().registry("event_subscriber")->configure();
    RegistryFactory::get().registry("event_publisher")->configure();
  }
}

Status EventFactory::run(const std::string& type_id) {
  if (FLAGS_disable_events) {
    return Status::success();
  }

  // An interesting take on an event dispatched entrypoint.
  // There is little introspection into the event type.
  // Assume it can either make use of an entrypoint poller/selector or
  // take care of async callback registrations in setUp/configure/run
  // only once and handle event queuing/firing in callbacks.
  EventPublisherRef publisher = nullptr;
  {
    auto& ef = EventFactory::getInstance();
    RecursiveLock lock(ef.factory_lock_);
    publisher = ef.getEventPublisher(type_id);
  }

  if (publisher == nullptr) {
    return Status::failure("Event publisher is missing");
  } else if (publisher->hasStarted()) {
    return Status::failure("Cannot restart an event publisher");
  }

  setThreadName(publisher->name());
  VLOG(1) << "Starting event publisher run loop: " + type_id;
  publisher->hasStarted(true);
  publisher->state(EventState::EVENT_RUNNING);

  auto status = Status(0, "OK");
  while (!publisher->isEnding()) {
    // Can optionally implement a global cooloff latency here.
    status = publisher->run();
    if (!status.ok()) {
      break;
    }
    publisher->restart_count_++;
    // This is a 'default' cool-off implemented in InterruptibleRunnable.
    // If a publisher fails to perform some sort of interruption point, this
    // prevents the thread from thrashing through exiting checks.
    publisher->pause(std::chrono::milliseconds(200));
  }

  if (!status.ok()) {
    // The runloop status is not reflective of the event type's.
    VLOG(1) << "Event publisher " << publisher->type()
            << " run loop terminated for reason: " << status.getMessage();
    // Publishers auto tear down when their run loop stops.
  }
  publisher->tearDown();
  publisher->state(EventState::EVENT_NONE);

  // Do not remove the publisher from the event factory.
  // If the event factory's `end` method was called these publishers will be
  // cleaned up after their thread context is removed; otherwise, a removed
  // thread context and failed publisher will remain available for stats.
  return Status::success();
}

void EventFactory::delay() {
  // Caller may disable event publisher threads.
  if (FLAGS_disable_events) {
    return;
  }

  // Create a thread for each event publisher.
  auto& ef = EventFactory::getInstance();
  for (const auto& publisher : EventFactory::getInstance().event_pubs_) {
    // Publishers that did not set up correctly are put into an ending state.
    if (!publisher.second->isEnding()) {
      auto thread_ = std::make_shared<std::thread>(
          std::bind(&EventFactory::run, publisher.first));
      ef.threads_.push_back(thread_);
    }
  }
}

void EventFactory::end(bool join) {
  auto& ef = EventFactory::getInstance();

  // Call deregister on each publisher.
  for (const auto& publisher : ef.publisherTypes()) {
    deregisterEventPublisher(publisher);
  }

  // Stop handling exceptions for the publisher threads.
  for (const auto& thread : ef.threads_) {
    if (join) {
      thread->join();
    } else {
      thread->detach();
    }
  }

  {
    RecursiveLock lock(ef.factory_lock_);
    // A small cool off helps OS API event publisher flushing.
    if (!FLAGS_disable_events) {
      ef.threads_.clear();
    }

    // Threads may still be executing, when they finish, release publishers.
    ef.event_pubs_.clear();
    ef.event_subs_.clear();
  }
}

} // namespace osquery
