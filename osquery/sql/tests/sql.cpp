/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/format.hpp>
#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sql.h>
#include <osquery/sql/tests/sql_test_utils.h>

namespace osquery {

extern void escapeNonPrintableBytesEx(std::string& data);

class SQLTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
  }
};

TEST_F(SQLTests, test_raw_access) {
  // Access to the table plugins (no SQL parsing required) works in both
  // extensions and core, though with limitations on available tables.
  auto results = SQL::selectAllFrom("time");
  EXPECT_EQ(results.size(), 1U);
}

class TestTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("test_int", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("test_text", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  TableRows generate(QueryContext& ctx) {
    TableRows results;
    if (ctx.constraints["test_int"].existsAndMatches("1")) {
      results.push_back(
          make_table_row({{"test_int", "1"}, {"test_text", "0"}}));
    } else {
      results.push_back(
          make_table_row({{"test_int", "0"}, {"test_text", "1"}}));
    }

    auto ints = ctx.constraints["test_int"].getAll<int>(EQUALS);
    for (const auto& int_match : ints) {
      results.push_back(make_table_row({{"test_int", INTEGER(int_match)}}));
    }

    return results;
  }
};

TEST_F(SQLTests, test_raw_access_context) {
  auto tables = RegistryFactory::get().registry("table");
  tables->add("test", std::make_shared<TestTablePlugin>());
  auto results = SQL::selectAllFrom("test");

  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["test_text"], "1");

  results = SQL::selectAllFrom("test", "test_int", EQUALS, "1");
  EXPECT_EQ(results.size(), 2U);

  results = SQL::selectAllFrom("test", "test_int", EQUALS, "2");
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["test_int"], "2");
}

TEST_F(SQLTests, test_sql_escape) {
  std::string input = "しかたがない";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input,
            "\\xE3\\x81\\x97\\xE3\\x81\\x8B\\xE3\\x81\\x9F\\xE3\\x81\\x8C\\xE3"
            "\\x81\\xAA\\xE3\\x81\\x84");

  input = "悪因悪果";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input,
            "\\xE6\\x82\\xAA\\xE5\\x9B\\xA0\\xE6\\x82\\xAA\\xE6\\x9E\\x9C");

  input = "モンスターハンター";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input,
            "\\xE3\\x83\\xA2\\xE3\\x83\\xB3\\xE3\\x82\\xB9\\xE3\\x82\\xBF\\xE3"
            "\\x83\\xBC\\xE3\\x83\\x8F\\xE3\\x83\\xB3\\xE3\\x82\\xBF\\xE3\\x83"
            "\\xBC");

  input = "съешь же ещё этих мягких французских булок, да выпей чаю";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(
      input,
      "\\xD1\\x81\\xD1\\x8A\\xD0\\xB5\\xD1\\x88\\xD1\\x8C \\xD0\\xB6\\xD0\\xB5 "
      "\\xD0\\xB5\\xD1\\x89\\xD1\\x91 \\xD1\\x8D\\xD1\\x82\\xD0\\xB8\\xD1\\x85 "
      "\\xD0\\xBC\\xD1\\x8F\\xD0\\xB3\\xD0\\xBA\\xD0\\xB8\\xD1\\x85 "
      "\\xD1\\x84\\xD1\\x80\\xD0\\xB0\\xD0\\xBD\\xD1\\x86\\xD1\\x83\\xD0\\xB7\\"
      "xD1\\x81\\xD0\\xBA\\xD0\\xB8\\xD1\\x85 "
      "\\xD0\\xB1\\xD1\\x83\\xD0\\xBB\\xD0\\xBE\\xD0\\xBA, "
      "\\xD0\\xB4\\xD0\\xB0 \\xD0\\xB2\\xD1\\x8B\\xD0\\xBF\\xD0\\xB5\\xD0\\xB9 "
      "\\xD1\\x87\\xD0\\xB0\\xD1\\x8E");

  input = "The quick brown fox jumps over the lazy dog.";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input, "The quick brown fox jumps over the lazy dog.");
}

TEST_F(SQLTests, test_sql_base64_encode) {
  QueryData d;
  query("select to_base64('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "dGVzdA==");
}

TEST_F(SQLTests, test_sql_base64_decode) {
  QueryData d;
  query("select from_base64('dGVzdA==') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "test");
}

TEST_F(SQLTests, test_sql_base64_conditional_encode) {
  QueryData d;
  query("select conditional_to_base64('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "test");

  QueryData d2;
  query("select conditional_to_base64('悪因悪果') as test;", d2);
  ASSERT_EQ(d2.size(), 1U);
  EXPECT_EQ(d2[0]["test"], "5oKq5Zug5oKq5p6c");
}

TEST_F(SQLTests, test_sql_md5) {
  QueryData d;
  query("select md5('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "098f6bcd4621d373cade4e832627b4f6");
}

TEST_F(SQLTests, test_sql_sha1) {
  QueryData d;
  query("select sha1('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
}

TEST_F(SQLTests, test_sql_sha256) {
  QueryData d;
  query("select sha256('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"],
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

/*
 * regex_match
 */

TEST_F(SQLTests, test_regex_match_multiple) {
  QueryData d;

  query(
      "select regex_match('hello world', '(l)(o).*', 0) as t0, \
                regex_match('hello world', '(l)(o).*', 1) as t1, \
                regex_match('hello world', '(l)(o).*', 2) as t2, \
                regex_match('hello world', '(l)(o).*', 3) as t3;",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "lo world");
  EXPECT_EQ(d[0]["t1"], "l");
  EXPECT_EQ(d[0]["t2"], "o");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_match_nomatch) {
  QueryData d;

  query(
      "select regex_match('hello world', 'no match', 0) as t0 \
                regex_match('hello world', 'no match', 1) as t1;",
      d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_match_complex) {
  QueryData d;

  query(
      "select regex_match('hello world', '(\\w+) .*(or|ld)', 0) as t0, \
                regex_match('hello world', '(\\w+) .*(or|ld)', 1) as t1, \
                regex_match('hello world', '(\\w+) .*(or|ld)', 2) as t2, \
                regex_match('hello world', '(\\w+) .*(or|ld)', 3) as t3",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "hello world");
  EXPECT_EQ(d[0]["t1"], "hello");
  EXPECT_EQ(d[0]["t2"], "ld");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_match_fileextract) {
  QueryData d;

  query(
      "select regex_match('/filesystem/path/download.extension.zip', "
      "'.+/([^./]+)', 1) as basename",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["basename"], "download");
}

TEST_F(SQLTests, test_regex_match_empty) {
  QueryData d;
  // Empty regex gets you a null result
  query("select regex_match('hello world', '', 0) as test", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "");
}

TEST_F(SQLTests, test_regex_match_invalid1) {
  QueryData d;
  query("select regex_match('foo/bar', '(/', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_match_invalid2) {
  QueryData d;
  query("select regex_match('foo/bar', '+', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_match_invalid3) {
  QueryData d;
  // `|` is an invalid regexp but std::basic_regex doesn't complain, and treats
  // it much as an empty string. Encode that expection here in tests.
  query("select regex_match('foo/bar', '|', 0) as test", d);
  ASSERT_EQ(d.size(), 1U);

  std::string query_result;
  ASSERT_NO_THROW(query_result = d[0].at("test"));
  ASSERT_TRUE(query_result.empty());
}

TEST_F(SQLTests, test_regex_match_too_big) {
  QueryData d;
  std::string regex(100000, '|');
  auto status = query("select regex_match('foo/bar', '" + regex + "', 0)", d);
  ASSERT_TRUE(!status.ok());
  std::string error_too_big = "Invalid regex: too big";
  ASSERT_EQ(status.getMessage().compare(0, error_too_big.size(), error_too_big),
            0);
}

/*
 * split
 */

TEST_F(SQLTests, test_split_slash) {
  QueryData d;

  query(
      "select split('/foo/bar', '/', 0) as t0, \
                split('/foo/bar', '/', 1) as t1, \
                split('/foo/bar', '/', 2) as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "");
}

TEST_F(SQLTests, test_split_double_semicolon) {
  QueryData d;

  query(
      "select split('foo;;bar', ';;', 0) as t0, \
                split('foo;;bar', ';;', 1) as t1, \
                split('foo;;bar', ';;', 2) as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "");
}

TEST_F(SQLTests, test_split_empty) {
  QueryData d;

  query("select split('foo;;bar', '', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

/*
 * regex_split
 */

TEST_F(SQLTests, test_regex_split_slashes) {
  QueryData d;

  query(
      "select regex_split('/foo/bar', '/', 0) as t0, \
                regex_split('/foo/bar', '/', 1) as t1, \
                regex_split('/foo/bar', '/', 2) as t2, \
                regex_split('/foo/bar', '/', 3) as t3",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "");
  EXPECT_EQ(d[0]["t1"], "foo");
  EXPECT_EQ(d[0]["t2"], "bar");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_split_double_semicolon) {
  QueryData d;

  query(
      "select regex_split('foo;;bar', ';;', 0) as t0, \
                regex_split('foo;;bar', ';;', 1) as t1, \
                regex_split('foo;;bar', ';;', 2) as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "");
}

TEST_F(SQLTests, test_regex_split_options) {
  QueryData d;

  query(
      "select regex_split('foo;bar//qux', '(;|/)+', 0) as t0, \
                regex_split('foo;bar//qux', '(;|/)+', 1) as t1, \
                regex_split('foo;bar//qux', '(;|/)+', 2) as t2, \
                regex_split('foo;bar//qux', '(;|/)+', 3) as t3",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "qux");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_split_filename_extract) {
  QueryData d;
  // A more complex example.
  query(
      "select regex_split('/filesystem/path/download.extension.zip', "
      "'(.*/)|(.extension.zip)', 1) as test",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "download");
}

TEST_F(SQLTests, test_regex_split_empty) {
  QueryData d;
  query("select regex_split('foo/bar', '', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_split_invalid1) {
  QueryData d;
  query("select regex_split('foo/bar', '(/', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_split_invalid2) {
  QueryData d;
  query("select regex_split('foo/bar', '+', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_split_with_or) {
  QueryData d;
  // `|` is an invalid regexp but std::basic_regex doesn't complain, and treats
  // it much as an empty string. Encode that expection here in tests.
  query("select regex_split('foo/bar', '|', 0) as test", d);
  ASSERT_EQ(d.size(), 1U);

  std::string query_result;
  ASSERT_NO_THROW(query_result = d[0].at("test"));
  ASSERT_TRUE(query_result.empty());
}

TEST_F(SQLTests, test_regex_split_too_big) {
  QueryData d;
  std::string regex(100000, '|');
  auto status = query("select regex_split('foo/bar', '" + regex + "', 0)", d);
  ASSERT_TRUE(!status.ok());
}

/*
 * ssdeep_compare
 */

#ifdef OSQUERY_POSIX
TEST_F(SQLTests, test_sql_ssdeep_compare) {
  QueryData d;
  // random 32KB file vs same file concatenated with another random 32KB file
  std::stringstream query_stream;
  query_stream << boost::format(
                      "select ssdeep_compare('%s', '%s') as test_int;") %
                      "768:hRWoDxStE/p76XkJx2HIjxZ2bhX+wQp+uCRdONCGav/"
                      "IGdBR:aoD582YotZMLQp+5RdONCGM/BR" %
                      "1536:aoD582YotZMLQp+5RdONCGM/BnxFEu4vNz/xC+Oi+u/UD/"
                      "9LYD:h22YWZVsRBGMZndQNz/xCfi+qeYD";
  query(query_stream.str(), d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test_int"], "68");
}
#endif

TEST_F(SQLTests, test_version_collate) {
  QueryData d;
  auto status = query("create temp table test_version(v string);", d);
  ASSERT_TRUE(status.ok());

  status = query("insert into 'test_version' values('1');", d);
  ASSERT_TRUE(status.ok());

  status = query("insert into 'test_version' values('1.2.0');", d);
  ASSERT_TRUE(status.ok());

  status = query("insert into 'test_version' values('1.11.0');", d);
  ASSERT_TRUE(status.ok());

  status = query("select * from test_version ORDER BY v;", d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 3U);
  EXPECT_EQ(d[0]["v"], "1");
  EXPECT_EQ(d[1]["v"], "1.11.0");
  EXPECT_EQ(d[2]["v"], "1.2.0");

  status = query("select * from test_version ORDER BY v COLLATE VERSION;", d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 3U);
  EXPECT_EQ(d[0]["v"], "1");
  EXPECT_EQ(d[1]["v"], "1.2.0");
  EXPECT_EQ(d[2]["v"], "1.11.0");
}

TEST_F(SQLTests, test_version_collate_in_table) {
  QueryData d;
  auto status =
      query("create temp table test_version_2(v string COLLATE VERSION);", d);
  ASSERT_TRUE(status.ok());

  status = query("insert into 'test_version_2' values('2');", d);
  ASSERT_TRUE(status.ok());

  status = query("insert into 'test_version_2' values('2.11.0');", d);
  ASSERT_TRUE(status.ok());

  status = query("insert into 'test_version_2' values('2.2.0');", d);
  ASSERT_TRUE(status.ok());

  status = query("select * from test_version_2 ORDER BY v;", d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 3U);
  EXPECT_EQ(d[0]["v"], "2");
  EXPECT_EQ(d[1]["v"], "2.2.0");
  EXPECT_EQ(d[2]["v"], "2.11.0");
}

TEST_F(SQLTests, test_version_comparisons) {
  QueryData d;

  auto status =
      query("select '2.1.1.1' > '1.1.1.1' COLLATE VERSION as test;", d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "1");

  status = query("select '2.11.1.1' > '2.2.1.1' COLLATE VERSION as test;", d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "1");

  status = query(
      "select '0.5.5-22-g85b16ae' > '0.5.5-3-ga7b9229' COLLATE VERSION as "
      "test;",
      d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "1");
}

} // namespace osquery
