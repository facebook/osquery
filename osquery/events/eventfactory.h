/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <memory>
#include <vector>

#include <osquery/events/eventer.h>
#include <osquery/events/eventpublisherplugin.h>
#include <osquery/events/eventsubscriberplugin.h>
#include <osquery/events/subscription.h>
#include <osquery/events/types.h>

namespace osquery {

/**
 * @brief A factory for associating event generators to EventPublisherID%s.
 *
 * This factory both registers new event types and the subscriptions that use
 * them. An EventPublisher is also a factory, the single event factory
 * arbitrates Subscription creation and management for each associated
 * EventPublisher.
 *
 * Since event types may be plugins, they are created using the factory.
 * Since subscriptions may be configured/disabled they are also factory-managed.
 */
class EventFactory : private boost::noncopyable {
 public:
  /// Access to the EventFactory instance.
  static EventFactory& getInstance();

  /**
   * @brief Add an EventPublisher to the factory.
   *
   * The registration is mostly abstracted using osquery's registry.
   *
   * @param pub If for some reason the caller needs access to the
   * EventPublisher instance they can register-by-instance.
   *
   * Access to the EventPublisher instance is not discouraged, but using the
   * EventFactory `getEventPublisher` accessor is encouraged.
   */
  static Status registerEventPublisher(const PluginRef& pub);

  /**
   * @brief Add an EventSubscriber to the factory.
   *
   * The registration is mostly abstracted using osquery's registry.
   */
  template <class T>
  static Status registerEventSubscriber() {
    auto sub = std::make_shared<T>();
    return registerEventSubscriber(sub);
  };

  /**
   * @brief Add an EventSubscriber to the factory.
   *
   * The registration is mostly abstracted using osquery's registry.
   *
   * @param sub If the caller must access the EventSubscriber instance
   * control may be passed to the registry.
   *
   * Access to the EventSubscriber instance outside of the within-instance
   * table generation method and set of EventCallback%s is discouraged.
   */
  static Status registerEventSubscriber(const PluginRef& sub);

  /**
   * @brief Add a SubscriptionContext and EventCallback Subscription to an
   * EventPublisher.
   *
   * Create a Subscription from a given SubscriptionContext and EventCallback
   * and add that Subscription to the EventPublisher associated identifier.
   *
   * @param type_id ID string for an EventPublisher receiving the Subscription.
   * @param name_id ID string for the EventSubscriber.
   * @param sc A SubscriptionContext related to the EventPublisher.
   * @param cb When the EventPublisher fires an event the SubscriptionContext
   * will be evaluated, if the event matches optional specifics in the context
   * this callback function will be called. It should belong to an
   * EventSubscription.
   *
   * @return Was the SubscriptionContext appropriate for the EventPublisher.
   */
  static Status addSubscription(const std::string& type_id,
                                const std::string& name_id,
                                const SubscriptionContextRef& sc,
                                EventCallback cb = nullptr);

  /// Add a Subscription using a caller Subscription instance.
  static Status addSubscription(const std::string& type_id,
                                const SubscriptionRef& subscription);

  /// Get the total number of Subscription%s across ALL EventPublisher%s.
  static size_t numSubscriptions(const std::string& type_id);

  /// Get the number of EventPublishers.
  static size_t numEventPublishers();

  /**
   * @brief Halt the EventPublisher run loop.
   *
   * Any EventSubscriber%s with Subscription%s for this EventPublisher will
   * become useless. osquery callers MUST deregister events.
   * EventPublisher%s assume they can hook/trampoline, which requires cleanup.
   * This will tear down and remove the publisher if the run loop did not start.
   * Otherwise it will call end on the publisher and assume the run loop will
   * tear down and remove.
   *
   * @param pub The string label for the EventPublisher.
   *
   * @return Did the EventPublisher deregister cleanly.
   */
  static Status deregisterEventPublisher(const EventPublisherRef& pub);

  /// Deregister an EventPublisher by publisher name.
  static Status deregisterEventPublisher(const std::string& type_id);

  /// Deregister an EventSubscriber by the subscriber name.
  static Status deregisterEventSubscriber(const std::string& sub);

  /// Return an instance to a registered EventPublisher.
  static EventPublisherRef getEventPublisher(const std::string& pub);

  /// Return an instance to a registered EventSubscriber.
  static EventSubscriberRef getEventSubscriber(const std::string& sub);

  /// Check if an event subscriber exists.
  static bool exists(const std::string& sub);

  /// Return a list of publisher types, these are their registry names.
  static std::set<std::string> publisherTypes();

  /// Return a list of subscriber registry names,
  static std::set<std::string> subscriberNames();

  /// Set log forwarding by adding a logger receiver.
  static void addForwarder(const std::string& logger);

  /// Optionally forward events to loggers.
  static void forwardEvent(const std::string& event);

  /**
   * @brief The event factory, subscribers, and publishers respond to updates.
   *
   * This should be called by the Config instance when configuration data is
   * updated. It is separate from the config parser that takes configuration
   * information specific to events and acts. This allows the event factory
   * to make changes relative to the schedule or packs.
   */
  static void configUpdate();

 public:
  /// The dispatched event thread's entry-point (if needed).
  static Status run(const std::string& type_id);

  /// An initializer's entry-point for spawning all event type run loops.
  static void delay();

  /// If a static EventPublisher callback wants to fire
  template <typename PUB>
  static void fire(const EventContextRef& ec) {
    auto event_pub = getEventPublisher(getType<PUB>());
    if (event_pub != nullptr) {
      // A publisher may not exist anymore if an OS event callback is fired
      // during process teardown. A publisher cannot-be-found log is generated.
      event_pub->fire(ec);
    }
  }

  /**
   * @brief Return the publisher registry name given a type.
   *
   * Subscriber initialization and runtime static callbacks can lookup the
   * publisher type name, which is the registry plugin name. This allows static
   * callbacks to fire into subscribers.
   */
  template <class PUB>
  static const std::string getType() {
    static std::string _type = std::make_shared<PUB>()->type();
    return _type;
  }

  /**
   * @brief End all EventPublisher run loops and deregister.
   *
   * End is NOT the same as deregistration. End will call deregister on all
   * publishers then either join or detach their run loop threads.
   * See EventFactory::deregisterEventPublisher for actions taken during
   * deregistration.
   *
   * @param join if true, threads will be joined
   */
  static void end(bool join = false);

 public:
  EventFactory(EventFactory const&) = delete;
  EventFactory& operator=(EventFactory const&) = delete;

 private:
  /// An EventFactory will exist for the lifetime of the application.
  EventFactory() = default;
  ~EventFactory() = default;

 private:
  /// Set of registered EventPublisher instances.
  std::map<std::string, EventPublisherRef> event_pubs_;

  /// Set of instantiated EventSubscriber subscriptions.
  std::map<std::string, EventSubscriberRef> event_subs_;

  /// Set of running EventPublisher run loop threads.
  std::vector<std::shared_ptr<std::thread>> threads_;

  /// Set of logger plugins to forward events.
  std::vector<std::string> loggers_;

  /// Factory publisher state manipulation.
  RecursiveMutex factory_lock_;
};

} // namespace osquery
