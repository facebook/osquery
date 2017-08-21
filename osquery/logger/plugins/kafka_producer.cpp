
/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <unistd.h>

#include <librdkafka/rdkafka.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/config/parsers/kafka_topics.h"
#include "osquery/logger/plugins/kafka_producer.h"

namespace osquery {

FLAG(string,
     logger_kafka_brokers,
     "localhost",
     "Bootstrap broker(s) as a comma-separated list of host or host:port "
     "(default port 9092)");

FLAG(string, logger_kafka_topic, "", "Kafka topic to publish logs under");

FLAG(string,
     logger_kafka_acks,
     "all",
     "The number of acknowledgments the leader has to receive (0, 1, 'all')");

/// How often to poll Kafka broker for publish results.
const std::chrono::seconds kKafkaPollDuration = std::chrono::seconds(5);

/// Deleter for rd_kafka_t unique_ptr.
static inline void delKafkaHandle(rd_kafka_t* k) {
  if (k != nullptr) {
    rd_kafka_destroy(k);
  }
};

/// Deleter for rd_kafka_topic_t unique_ptr.
static inline void delKafkaTopic(rd_kafka_topic_t* kt) {
  if (kt != nullptr) {
    rd_kafka_topic_destroy(kt);
  }
};

/// Deleter for rd_kafka_conf_t.
static inline void delKafkaConf(rd_kafka_conf_t* conf) {
  if (conf != nullptr) {
    rd_kafka_conf_destroy(conf);
  }
}

REGISTER(KafkaProducerPlugin, "logger", "kafka_producer");

/// Flag to ensure shutdown method is called only once
std::once_flag KafkaProducerPlugin::shutdownFlag_;

inline std::string getMsgName(const std::string& payload) {
  const std::string fieldName = "\"name\"";
  size_t ipos = payload.rfind(fieldName);
  if (ipos == std::string::npos) {
    // return base topic key
    return "";
  }

  size_t first = payload.find('"', ipos + 6);
  if (first == std::string::npos) {
    return "";
  }

  size_t last = payload.find('"', first + 1);
  if (last == std::string::npos) {
    return "";
  }

  return payload.substr(first + 1, last - first - 1);
}

/**
 * @brief callback for status of message delivery
 *
 * Logs an error message for failed deliveries; does nothing if successful.
 * Callback is invoked by rd_kafka_poll.
 */
void onMsgDelivery(rd_kafka_t* rk,
                   const rd_kafka_message_t* rkmessage,
                   void* opaque) {
  if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR) {
    LOG(ERROR) << "Kafka message delivery failed: "
               << rd_kafka_err2str(rkmessage->err);
  }
}

void KafkaProducerPlugin::flushMessages() {
  WriteLock lock(producerMutex_);
  rd_kafka_flush(producer_.get(), 3 * 1000);
}

void KafkaProducerPlugin::pollKafka() {
  WriteLock lock(producerMutex_);
  rd_kafka_poll(producer_.get(), 0 /*non-blocking*/);
}

void KafkaProducerPlugin::start() {
  while (!interrupted() && running_.load()) {
    pauseMilli(kKafkaPollDuration);
    if (interrupted()) {
      return;
    }
    pollKafka();
  }
}

void KafkaProducerPlugin::stop() {
  std::call_once(shutdownFlag_, [this]() {
    if (running_.load()) {
      running_.store(false);
      flushMessages();
    }
  });
}

void KafkaProducerPlugin::init(const std::string& name,
                               const std::vector<StatusLogLine>& log) {
  // Get local hostname to use as client id and Kafka msg key.
  std::string hostname(getHostname());

  msgKey_ = hostname + "_" + name;

  // Configure Kafka producer.
  char errstr[512] = {0};

  /* Per rd_kafka.h in describing `rd_kafka_new`: "The \p conf object is freed
   * by this function on success and must not be used". Therefore we only
   * explicitly delete until that function is called.
   */
  auto conf = rd_kafka_conf_new();

  if (rd_kafka_conf_set(
          conf, "client.id", hostname.c_str(), errstr, sizeof(errstr)) !=
      RD_KAFKA_CONF_OK) {
    LOG(ERROR) << "Could not initiate Kafka client.id configuration: "
               << errstr;
    delKafkaConf(conf);
    return;
  }

  if (rd_kafka_conf_set(conf,
                        "bootstrap.servers",
                        FLAGS_logger_kafka_brokers.c_str(),
                        errstr,
                        sizeof(errstr)) != RD_KAFKA_CONF_OK) {
    LOG(ERROR) << "Could not initiate Kafka brokers configuration: " << errstr;
    delKafkaConf(conf);
    return;
  }

  // Register send callback.
  rd_kafka_conf_set_dr_msg_cb(conf, onMsgDelivery);

  // Create producer handle.
  std::unique_ptr<rd_kafka_t, std::function<void(rd_kafka_t*)>> rk(
      rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr)),
      delKafkaHandle);
  producer_.swap(rk);
  if (producer_.get() == nullptr) {
    LOG(ERROR) << "Could not initiate Kafka producer handle: " << errstr;
    delKafkaConf(conf);
    return;
  }

  // Configure Kafka topics
  if (!configureTopics()) {
    LOG(ERROR)
        << "Could not initial Kafka logger because configuration is invalid";
    return;
  }

  // Start bg loop for polling to ensure onMsgDelivery callback is invoked even
  // at times were no messages are produced
  // (http://docs.confluent.io/2.0.0/clients/producer.html#asynchronous-writes)
  running_.store(true);

  Dispatcher::addService(std::shared_ptr<KafkaProducerPlugin>(
      this, [](KafkaProducerPlugin* k) { k->stop(); }));
}

Status KafkaProducerPlugin::logString(const std::string& payload) {
  if (!running_.load()) {
    return Status(
        1, "Cannot log because Kafka producer did not initiate properly.");
  }

  std::string name(getMsgName(payload));

  rd_kafka_topic_t* topic = nullptr;
  try {
    topic = queryToTopics_.at(name);
  } catch (const std::out_of_range& _) {
    topic = queryToTopics_[kKafkaBaseTopic];
  }

  if (topic == nullptr) {
    std::string errMsg(
        "Could not publish message: Topic not configured for message name '" +
        name + "'");
    LOG(ERROR) << errMsg;
    return Status(2, errMsg);
  }

  Status status = publishMsg(topic, payload);
  if (!status.ok()) {
    LOG(ERROR) << "Could not publish message: " << status.getMessage();
  }

  // Poll after every produce attempt.
  pollKafka();

  return status;
}

Status KafkaProducerPlugin::publishMsg(rd_kafka_topic_t* topic,
                                       const std::string& payload) {
  if (rd_kafka_produce(topic,
                       RD_KAFKA_PARTITION_UA,
                       RD_KAFKA_MSG_F_COPY,
                       (char*)payload.c_str(),
                       payload.length(),
                       msgKey_.c_str(), // Optional key
                       msgKey_.length(), // key length
                       nullptr) == -1) {
    return Status(1,
                  "Failed to produce on Kafka topic " +
                      std::string(rd_kafka_topic_name(topic)) + " : " +
                      rd_kafka_err2str(rd_kafka_last_error()));
  }

  return Status(0, "OK");
}

inline rd_kafka_topic_t* KafkaProducerPlugin::initTopic(
    const std::string& topicName) {
  char errstr[512] = {0};
  rd_kafka_topic_conf_t* topicConf = rd_kafka_topic_conf_new();
  if (rd_kafka_topic_conf_set(topicConf,
                              "acks",
                              FLAGS_logger_kafka_acks.c_str(),
                              errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
    LOG(ERROR) << "Could not initiate Kafka request.required.acks "
                  "configuration: "
               << errstr;
    return nullptr;
  }

  return rd_kafka_topic_new(producer_.get(), topicName.c_str(), topicConf);
}

bool KafkaProducerPlugin::configureTopics() {
  auto parser = Config::getParser("kafka_topics");

  if (parser != nullptr || parser.get() != nullptr) {
    const auto& config = parser->getData().get_child(
        kKafkaTopicParserRootKey, boost::property_tree::ptree("UNEXPECTED"));
    if (!config.empty() && config.get_value("") != "UNEXPECTED") {
      for (const auto& t : config) {
        auto topic = initTopic(t.first);
        if (topic == nullptr) {
          continue;
        }

        topics_.push_back(
            std::unique_ptr<rd_kafka_topic_t,
                            std::function<void(rd_kafka_topic_t*)>>(
                topic, delKafkaTopic));

        // Configure queryToTopics_
        for (const auto& n :
             config.get_child(t.first, boost::property_tree::ptree())) {
          if (!n.first.empty()) {
            LOG(WARNING)
                << "Query names for a topic must be in JSON array format";
            continue;
          }

          queryToTopics_[n.second.data()] = topic;
        }
      }
    }
  }

  // Initiate base Kafka topic.
  if (!FLAGS_logger_kafka_topic.empty()) {
    auto topic = initTopic(FLAGS_logger_kafka_topic);
    if (topic != nullptr) {
      topics_.push_back(std::unique_ptr<rd_kafka_topic_t,
                                        std::function<void(rd_kafka_topic_t*)>>(
          topic, delKafkaTopic));
    }

    queryToTopics_[kKafkaBaseTopic] = topic;

  } else {
    /* If no previous topics successfully configured and no base topic is set
     * then configuration fails.*/
    if (topics_.empty()) {
      return false;
    }

    queryToTopics_[kKafkaBaseTopic] = nullptr;
  }

  return true;
}
} // namespace osquery
