/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <deque>
#include <random>
#include <sstream>
#include <thread>

#include <signal.h>
#include <time.h>

#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/tests/test_util.h"

#ifdef WIN32
#include <lmcons.h>
#endif

namespace fs = boost::filesystem;

namespace osquery {

std::string kFakeDirectory = "";

#if defined(DARWIN)
std::string kTestWorkingDirectory = "/private/tmp/osquery-tests";
#elif defined(WIN32)
std::string kTestWorkingDirectory =
    (fs::temp_directory_path() / "osquery-tests").make_preferred().string();
#else
std::string kTestWorkingDirectory = "/tmp/osquery-tests";
#endif

/// Most tests will use binary or disk-backed content for parsing tests.
#ifndef OSQUERY_BUILD_SDK
std::string kTestDataPath =
    fs::path("../../../tools/tests/").make_preferred().string();
#else
std::string kTestDataPath =
    fs::path("../../../../tools/tests/").make_preferred().string();
#endif

DECLARE_string(database_path);
DECLARE_string(extensions_socket);
DECLARE_string(modules_autoload);
DECLARE_string(extensions_autoload);
DECLARE_string(enroll_tls_endpoint);
DECLARE_bool(disable_logging);
DECLARE_bool(disable_database);

typedef std::chrono::high_resolution_clock chrono_clock;

static std::string getUserId() {
#ifdef WIN32
  std::vector<unsigned char> user_name(UNLEN + 1);
  user_name.assign(UNLEN + 1, '\0');
  DWORD size = user_name.size() - 1;

  if (!::GetUserNameA((LPSTR) &user_name[0], &size)) {
    return "";
  }

  return std::string((const char *)&user_name[0], size - 1);
#else
  return std::to_string(getuid());
#endif
}

static std::unique_ptr<PlatformProcess> launchTestServer(const std::string &port) {
  std::unique_ptr<PlatformProcess> server;

#ifdef WIN32
  STARTUPINFOA si = { 0 };
  PROCESS_INFORMATION pi = { 0 };

  auto argv = "python " + kTestDataPath + "/test_http_server.py --tls " + port;
  std::vector<char> mutable_argv(argv.begin(), argv.end());
  si.cb = sizeof(si);


  auto drive = getEnvVar("SystemDrive");
  std::string python_path("");
  if (drive.is_initialized()) {
    python_path = *drive;
  }

  // Python is installed here if provisioning script is used
  python_path += "\\tools\python2\\python.exe";
  if (::CreateProcessA(python_path.c_str(), &mutable_argv[0], NULL, NULL, FALSE,
                       0, NULL, NULL, &si, &pi)) {
    server.reset(new PlatformProcess(pi.hProcess));
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
  }
#else
  int server_pid = fork();
  if (server_pid == 0) {
    // Start a python TLS/HTTPS or HTTP server.
    auto script = kTestDataPath + "/test_http_server.py --tls " + port;
    execlp("sh", "sh", "-c", script.c_str(), nullptr);
    ::exit(0);
  } else if (server_pid > 0) {
    server.reset(new PlatformProcess(server_pid));
  }
#endif

  return std::move(server);
}

void initTesting() {
  // Allow unit test execution from anywhere in the osquery source/build tree.
  while (osquery::kTestDataPath != "/") {
    if (!fs::exists(osquery::kTestDataPath)) {
      osquery::kTestDataPath =
          osquery::kTestDataPath.substr(3, osquery::kTestDataPath.size());
    } else {
      break;
    }
  }

  // Seed the random number generator, some tests generate temporary files
  // ports, sockets, etc using random numbers.
  std::srand(chrono_clock::now().time_since_epoch().count());

  // Set safe default values for path-based flags.
  // Specific unittests may edit flags temporarily.
  kTestWorkingDirectory = fs::path(kTestWorkingDirectory + getUserId() + "/")
                              .make_preferred()
                              .string();
  kFakeDirectory = fs::path(kTestWorkingDirectory + kFakeDirectoryName)
                       .make_preferred()
                       .string();

  fs::remove_all(kTestWorkingDirectory);
  fs::create_directories(kTestWorkingDirectory);
  FLAGS_database_path = fs::path(kTestWorkingDirectory + "unittests.db")
                            .make_preferred()
                            .string();
  FLAGS_extensions_socket = kTestWorkingDirectory + "unittests.em";
  FLAGS_extensions_autoload =
      fs::path(kTestWorkingDirectory + "unittests-ext.load")
          .make_preferred()
          .string();
  FLAGS_modules_autoload =
      fs::path(kTestWorkingDirectory + "unittests-mod.load")
          .make_preferred()
          .string();
  FLAGS_disable_logging = true;
  FLAGS_disable_database = true;

  // Tests need a database plugin.
  // Set up the database instance for the unittests.
  DatabasePlugin::setAllowOpen(true);

  // Initializing database plugin does not work 
#ifndef WIN32
  DatabasePlugin::initPlugin();
#endif
}

void shutdownTesting() { DatabasePlugin::shutdown(); }

std::map<std::string, std::string> getTestConfigMap() {
  std::string content;
  readFile(fs::path(kTestDataPath + "test_parse_items.conf")
               .make_preferred()
               .string(),
           content);
  std::map<std::string, std::string> config;
  config["awesome"] = content;
  return config;
}

pt::ptree getExamplePacksConfig() {
  std::string content;
  auto s = readFile(fs::path(kTestDataPath + "test_inline_pack.conf")
                        .make_preferred()
                        .string(),
                    content);
  assert(s.ok());
  std::stringstream json;
  json << content;
  pt::ptree tree;
  pt::read_json(json, tree);
  return tree;
}

/// no discovery queries, no platform restriction
pt::ptree getUnrestrictedPack() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("unrestricted_pack");
}

// several restrictions (version, platform, shard)
pt::ptree getRestrictedPack() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("restricted_pack");
}

/// 1 discovery query, darwin platform restriction
pt::ptree getPackWithDiscovery() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("discovery_pack");
}

/// 1 discovery query which will always pass
pt::ptree getPackWithValidDiscovery() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("valid_discovery_pack");
}

/// no discovery queries, no platform restriction, fake version string
pt::ptree getPackWithFakeVersion() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("fake_version_pack");
}

QueryData getTestDBExpectedResults() {
  QueryData d;
  Row row1;
  row1["username"] = "mike";
  row1["age"] = "23";
  d.push_back(row1);
  Row row2;
  row2["username"] = "matt";
  row2["age"] = "24";
  d.push_back(row2);
  return d;
}

std::vector<std::pair<std::string, QueryData>> getTestDBResultStream() {
  std::vector<std::pair<std::string, QueryData>> results;

  std::string q2 =
      "INSERT INTO test_table (username, age) VALUES (\"joe\", 25)";
  QueryData d2;
  Row row2_1;
  row2_1["username"] = "mike";
  row2_1["age"] = "23";
  d2.push_back(row2_1);
  Row row2_2;
  row2_2["username"] = "matt";
  row2_2["age"] = "24";
  d2.push_back(row2_2);
  Row row2_3;
  row2_3["username"] = "joe";
  row2_3["age"] = "25";
  d2.push_back(row2_3);
  results.push_back(std::make_pair(q2, d2));

  std::string q3 = "UPDATE test_table SET age = 27 WHERE username = \"matt\"";
  QueryData d3;
  Row row3_1;
  row3_1["username"] = "mike";
  row3_1["age"] = "23";
  d3.push_back(row3_1);
  Row row3_2;
  row3_2["username"] = "matt";
  row3_2["age"] = "27";
  d3.push_back(row3_2);
  Row row3_3;
  row3_3["username"] = "joe";
  row3_3["age"] = "25";
  d3.push_back(row3_3);
  results.push_back(std::make_pair(q3, d3));

  std::string q4 =
      "DELETE FROM test_table WHERE username = \"matt\" AND age = 27";
  QueryData d4;
  Row row4_1;
  row4_1["username"] = "mike";
  row4_1["age"] = "23";
  d4.push_back(row4_1);
  Row row4_2;
  row4_2["username"] = "joe";
  row4_2["age"] = "25";
  d4.push_back(row4_2);
  results.push_back(std::make_pair(q4, d4));

  return results;
}

ScheduledQuery getOsqueryScheduledQuery() {
  ScheduledQuery sq;
  sq.query = "SELECT filename FROM fs WHERE path = '/bin' ORDER BY filename";
  sq.interval = 5;
  return sq;
}

std::pair<pt::ptree, Row> getSerializedRow() {
  Row r;
  r["foo"] = "bar";
  r["meaning_of_life"] = "42";
  pt::ptree arr;
  arr.put<std::string>("foo", "bar");
  arr.put<std::string>("meaning_of_life", "42");
  return std::make_pair(arr, r);
}

std::pair<pt::ptree, QueryData> getSerializedQueryData() {
  auto r = getSerializedRow();
  QueryData q = {r.second, r.second};
  pt::ptree arr;
  arr.push_back(std::make_pair("", r.first));
  arr.push_back(std::make_pair("", r.first));
  return std::make_pair(arr, q);
}

std::pair<pt::ptree, DiffResults> getSerializedDiffResults() {
  auto qd = getSerializedQueryData();
  DiffResults diff_results;
  diff_results.added = qd.second;
  diff_results.removed = qd.second;

  pt::ptree root;
  root.add_child("added", qd.first);
  root.add_child("removed", qd.first);

  return std::make_pair(root, diff_results);
}

std::pair<std::string, DiffResults> getSerializedDiffResultsJSON() {
  auto results = getSerializedDiffResults();
  std::ostringstream ss;
  pt::write_json(ss, results.first, false);
  return std::make_pair(ss.str(), results.second);
}

std::pair<std::string, QueryData> getSerializedQueryDataJSON() {
  auto results = getSerializedQueryData();
  std::ostringstream ss;
  pt::write_json(ss, results.first, false);
  return std::make_pair(ss.str(), results.second);
}

std::pair<pt::ptree, QueryLogItem> getSerializedQueryLogItem() {
  QueryLogItem i;
  pt::ptree root;
  auto dr = getSerializedDiffResults();
  i.results = dr.second;
  i.name = "foobar";
  i.calendar_time = "Mon Aug 25 12:10:57 2014";
  i.time = 1408993857;
  i.identifier = "foobaz";
  root.add_child("diffResults", dr.first);
  root.put<std::string>("name", "foobar");
  root.put<std::string>("hostIdentifier", "foobaz");
  root.put<std::string>("calendarTime", "Mon Aug 25 12:10:57 2014");
  root.put<int>("unixTime", 1408993857);
  return std::make_pair(root, i);
}

std::pair<std::string, QueryLogItem> getSerializedQueryLogItemJSON() {
  auto results = getSerializedQueryLogItem();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::vector<SplitStringTestData> generateSplitStringTestData() {
  SplitStringTestData s1;
  s1.test_string = "a b\tc";
  s1.test_vector = {"a", "b", "c"};

  SplitStringTestData s2;
  s2.test_string = " a b   c";
  s2.test_vector = {"a", "b", "c"};

  SplitStringTestData s3;
  s3.test_string = "  a     b   c";
  s3.test_vector = {"a", "b", "c"};

  return {s1, s2, s3};
}

std::string getCACertificateContent() {
  std::string content;
  readFile(fs::path(kTestDataPath + "test_cert.pem").make_preferred().string(),
           content);
  return content;
}

std::string getEtcHostsContent() {
  std::string content;
  readFile(fs::path(kTestDataPath + "test_hosts.txt").make_preferred().string(),
           content);
  return content;
}

std::string getEtcProtocolsContent() {
  std::string content;
  readFile(
      fs::path(kTestDataPath + "test_protocols.txt").make_preferred().string(),
      content);
  return content;
}

QueryData getEtcHostsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;
  Row row4;
  Row row5;
  Row row6;

  row1["address"] = "127.0.0.1";
  row1["hostnames"] = "localhost";
  row2["address"] = "255.255.255.255";
  row2["hostnames"] = "broadcasthost";
  row3["address"] = "::1";
  row3["hostnames"] = "localhost";
  row4["address"] = "fe80::1%lo0";
  row4["hostnames"] = "localhost";
  row5["address"] = "127.0.0.1";
  row5["hostnames"] = "example.com example";
  row6["address"] = "127.0.0.1";
  row6["hostnames"] = "example.net";
  return {row1, row2, row3, row4, row5, row6};
}

::std::ostream& operator<<(::std::ostream& os, const Status& s) {
  return os << "Status(" << s.getCode() << ", \"" << s.getMessage() << "\")";
}

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

void createMockFileStructure() {
  fs::create_directories(fs::path(kFakeDirectory + "/deep11/deep2/deep3/")
                             .make_preferred()
                             .string());
  fs::create_directories(
      fs::path(kFakeDirectory + "/deep1/deep2/").make_preferred().string());
  writeTextFile(
      fs::path(kFakeDirectory + "/root.txt").make_preferred().string(), "root");
  writeTextFile(
      fs::path(kFakeDirectory + "/door.txt").make_preferred().string(), "toor");
  writeTextFile(
      fs::path(kFakeDirectory + "/roto.txt").make_preferred().string(), "roto");
  writeTextFile(
      fs::path(kFakeDirectory + "/deep1/level1.txt").make_preferred().string(),
      "l1");
  writeTextFile(
      fs::path(kFakeDirectory + "/deep11/not_bash").make_preferred().string(),
      "l1");
  writeTextFile(fs::path(kFakeDirectory + "/deep1/deep2/level2.txt")
                    .make_preferred()
                    .string(),
                "l2");

  writeTextFile(
      fs::path(kFakeDirectory + "/deep11/level1.txt").make_preferred().string(),
      "l1");
  writeTextFile(fs::path(kFakeDirectory + "/deep11/deep2/level2.txt")
                    .make_preferred()
                    .string(),
                "l2");
  writeTextFile(fs::path(kFakeDirectory + "/deep11/deep2/deep3/level3.txt")
                    .make_preferred()
                    .string(),
                "l3");

  boost::system::error_code ec;
#ifdef WIN32
  writeTextFile(
      fs::path(kFakeDirectory + "/root2.txt").make_preferred().string(), "l1");
#else
  fs::create_symlink(
      kFakeDirectory + "/root.txt", kFakeDirectory + "/root2.txt", ec);
#endif
}

void tearDownMockFileStructure() {
  boost::filesystem::remove_all(kFakeDirectory);
}

void TLSServerRunner::start() {
  auto& self = instance();
  if (self.server_ != nullptr) {
    return;
  }

  // Pick a port in an ephemeral range at random.
  self.port_ = std::to_string(rand() % 10000 + 20000);

  // Fork then exec a shell.
  self.server_ = launchTestServer(self.port_);
  if (self.server_ == nullptr) {
    return;
  }

  size_t delay = 0;
  std::string query =
      "select pid from listening_ports where port = '" + self.port_ + "'";
  while (delay < 2 * 1000) {
    auto results = SQL(query);
    if (results.rows().size() > 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    delay += 100;
  }
}

void TLSServerRunner::setClientConfig() {
  auto& self = instance();

  self.tls_hostname_ = Flag::getValue("tls_hostname");
  Flag::updateValue("tls_hostname", "localhost:" + port());

  self.enroll_tls_endpoint_ = Flag::getValue("enroll_tls_endpoint");
  Flag::updateValue("enroll_tls_endpoint", "/enroll");

  self.tls_server_certs_ = Flag::getValue("tls_server_certs");
  Flag::updateValue("tls_server_certs", kTestDataPath + "/test_server_ca.pem");

  self.enroll_secret_path_ = Flag::getValue("enroll_secret_path");
  Flag::updateValue("enroll_secret_path",
                    fs::path(kTestDataPath + "/test_enroll_secret.txt")
                        .make_preferred()
                        .string());
}

void TLSServerRunner::unsetClientConfig() {
  auto& self = instance();
  Flag::updateValue("tls_hostname", self.tls_hostname_);
  Flag::updateValue("enroll_tls_endpoint", self.enroll_tls_endpoint_);
  Flag::updateValue("tls_server_certs", self.tls_server_certs_);
  Flag::updateValue("enroll_secret_path", self.enroll_secret_path_);
}

void TLSServerRunner::stop() {
  auto& self = instance();
  if (self.server_ != nullptr) {
    self.server_->kill();
    self.server_.reset(nullptr);
  }
}
}
