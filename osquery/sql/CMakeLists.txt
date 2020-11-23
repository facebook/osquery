# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osquerySqlMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsquerySql()
endfunction()

function(generateOsquerySql)
  set(source_files
    dynamic_table_row.cpp
    sql.cpp
    sqlite_encoding.cpp
    sqlite_filesystem.cpp
    sqlite_hashing.cpp
    sqlite_math.cpp
    sqlite_operations.cpp
    sqlite_util.cpp
    sqlite_version.cpp
    virtual_sqlite_table.cpp
    virtual_table.cpp
  )

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS OR DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      sqlite_string.cpp
    )
  endif()

  add_osquery_library(osquery_sql EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_sql)

  target_link_libraries(osquery_sql PUBLIC
    osquery_cxx_settings
    osquery_carver_utils
    osquery_core
    osquery_core_plugins
    osquery_hashing
    osquery_process
    osquery_utils
    osquery_utils_conversions
    osquery_utils_system_errno
    osquery_utils_versioning_semantic
    thirdparty_boost
    thirdparty_googletest_headers
    thirdparty_sqlite
    thirdparty_gflags
  )

  if(NOT DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_sql PUBLIC
      thirdparty_ssdeep-cpp
    )
  endif()

  set(public_header_files
    sql.h
    dynamic_table_row.h
    sqlite_util.h
    virtual_table.h
  )

  generateIncludeNamespace(osquery_sql "osquery/sql" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_sql_tests-test COMMAND osquery_sql_tests-test)
  add_test(NAME osquery_sql_tests_virtualtabletests-test COMMAND osquery_sql_tests_virtualtabletests-test)
  add_test(NAME osquery_sql_tests_sqliteutilstests-test COMMAND osquery_sql_tests_sqliteutilstests-test)
  add_test(NAME osquery_sql_tests_sqlitehashingstests-test COMMAND osquery_sql_tests_sqlitehashingtests-test)
endfunction()

osquerySqlMain()
