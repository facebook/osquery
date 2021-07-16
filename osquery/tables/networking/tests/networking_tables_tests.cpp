/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/remote/tests/test_utils.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

// generate the content that would be found in an /etc/hosts file
std::string getEtcHostsContent() {
  std::string content;
  readFile(getTestConfigDirectory() / "test_hosts.txt", content);
  return content;
}

// generate the content that would be found in an /etc/hosts.ics file
std::string getEtcHostsIcsContent() {
  std::string content;
  readFile(getTestConfigDirectory() / "test_hosts_ics.txt", content);
  return content;
}

// generate the content that would be found in an /etc/protocols file
std::string getEtcProtocolsContent() {
  std::string content;
  readFile(getTestConfigDirectory() / "test_protocols.txt", content);
  return content;
}

// generate the expected data that getEtcHostsIcsContent() should parse into
QueryData getEtcHostsIcsExpectedResults() {
  Row row1;

  row1["address"] = "192.168.11.81";
  row1["hostnames"] = "VM-q27rkc8son.mshome.net";
  row1["pid_with_namespace"] = "0";
  return {row1};
}

// generate the expected data that getEtcHostsContent() should parse into
QueryData getEtcHostsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;
  Row row4;
  Row row5;
  Row row6;

  row1["address"] = "127.0.0.1";
  row1["hostnames"] = "localhost";
  row1["pid_with_namespace"] = "0";
  row2["address"] = "255.255.255.255";
  row2["hostnames"] = "broadcasthost";
  row2["pid_with_namespace"] = "0";
  row3["address"] = "::1";
  row3["hostnames"] = "localhost";
  row3["pid_with_namespace"] = "0";
  row4["address"] = "fe80::1%lo0";
  row4["hostnames"] = "localhost";
  row4["pid_with_namespace"] = "0";
  row5["address"] = "127.0.0.1";
  row5["hostnames"] = "example.com example";
  row5["pid_with_namespace"] = "0";
  row6["address"] = "127.0.0.1";
  row6["hostnames"] = "example.net";
  row6["pid_with_namespace"] = "0";
  return {row1, row2, row3, row4, row5, row6};
}

// generate the expected data that getEtcProtocolsContent() should parse into
QueryData getEtcProtocolsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;

  row1["name"] = "ip";
  row1["number"] = "0";
  row1["alias"] = "IP";
  row1["comment"] = "internet protocol, pseudo protocol number";
  row2["name"] = "icmp";
  row2["number"] = "1";
  row2["alias"] = "ICMP";
  row2["comment"] = "internet control message protocol";
  row3["name"] = "tcp";
  row3["number"] = "6";
  row3["alias"] = "TCP";
  row3["comment"] = "transmission control protocol";

  return {row1, row2, row3};
}

QueryData parseEtcHostsContent(const std::string& content);
QueryData parseEtcProtocolsContent(const std::string& content);

class NetworkingTablesTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(NetworkingTablesTests, test_parse_etc_hosts_content) {
  EXPECT_EQ(parseEtcHostsContent(getEtcHostsContent()),
            getEtcHostsExpectedResults());
}

TEST_F(NetworkingTablesTests, test_parse_etc_hosts_ics_content) {
  EXPECT_EQ(parseEtcHostsContent(getEtcHostsIcsContent()),
            getEtcHostsIcsExpectedResults());
}

TEST_F(NetworkingTablesTests, test_parse_etc_protocols_content) {
  EXPECT_EQ(parseEtcProtocolsContent(getEtcProtocolsContent()),
            getEtcProtocolsExpectedResults());
}

TEST_F(NetworkingTablesTests, test_listening_ports) {
  auto& server = TLSServerRunner::instance();
  ASSERT_TRUE(server.start());
  auto results = SQL::selectAllFrom("listening_ports");

  // Expect to find a process PID for the server.
  std::string pid;
  for (const auto& row : results) {
    // We are not interested in rows without ports (i.e. UNIX sockets)
    const auto& listening_port = row.at("port");
    if (listening_port.empty()) {
      continue;
    }

    if (listening_port == server.port()) {
      const auto& process_id = row.at("pid");
      if (process_id.empty()) {
        VLOG(1) << "Failed to acquire the process id";
        break;
      }

      pid = process_id;
      break;
    }
  }

  EXPECT_GT(pid.size(), 0U);
  EXPECT_NE(pid, "-1");
  server.stop();
}

TEST_F(NetworkingTablesTests, test_address_details_join) {
  // Expect that we can join interface addresses with details
  auto query =
      "select * from interface_details id, interface_addresses ia "
      "on ia.interface = id.interface "
      "where ia.address = '127.0.0.1';";

  auto results = SQL(query);
  EXPECT_GT(results.rows().size(), 0U);
}
} // namespace tables
} // namespace osquery
