# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryEventsTestsMain)
  generateOsqueryEventsTestsTest()
  generateOsqueryEventsTestsEventsdatabasetestsTest()

  if(DEFINED PLATFORM_LINUX)
    generateOsqueryEventsTestsSyslogtestsTest()
    generateOsqueryEventsTestsAudittestsTest()
    generateOsqueryEventsTestsProcessfileeventstestsTest()
    generateOsqueryEventsTestsInotifytestsTest()

    if(OSQUERY_BUILD_BPF)
      generateOsqueryEventsTestsBpftestsTest()
    endif()
  endif()

  if(DEFINED PLATFORM_MACOS)
    generateOsqueryEventsTestsFseventstestsTest()
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    generateOsqueryEventsTestsWindowsusnjournalreadertestsTest()
  endif()

endfunction()

function(generateOsqueryEventsTestsTest)
  add_osquery_executable(osquery_events_tests-test events_tests.cpp)

  target_link_libraries(osquery_events_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsEventsdatabasetestsTest)
  add_osquery_executable(osquery_events_tests_eventsdatabasetests-test
    mockedosquerydatabase.cpp
    eventsubscriberplugin.cpp
  )

  target_link_libraries(osquery_events_tests_eventsdatabasetests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsSyslogtestsTest)
  add_osquery_executable(osquery_events_tests_syslogtests-test linux/syslog_tests.cpp)

  target_link_libraries(osquery_events_tests_syslogtests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsAudittestsTest)
  add_osquery_executable(osquery_events_tests_audittests-test linux/audit_tests.cpp)

  target_link_libraries(osquery_events_tests_audittests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    specs_tables
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsProcessfileeventstestsTest)
  add_osquery_executable(osquery_events_tests_processfileeventstests-test linux/process_file_events_tests.cpp)

  target_link_libraries(osquery_events_tests_processfileeventstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsBpftestsTest)
  add_osquery_executable(
    osquery_events_tests_bpftests-test

    linux/bpf/bpfeventpublisher.cpp
    linux/bpf/bpftestsmain.h
    linux/bpf/mockedfilesystem.cpp
    linux/bpf/mockedfilesystem.h
    linux/bpf/mockedprocesscontextfactory.cpp
    linux/bpf/mockedprocesscontextfactory.h
    linux/bpf/processcontextfactory.cpp
    linux/bpf/systemstatetracker.cpp
    linux/bpf/utils.cpp
    linux/bpf/utils.h
    linux/bpf/usertracer.cpp
  )

  target_link_libraries(osquery_events_tests_bpftests-test PRIVATE
    osquery_cxx_settings
    osquery_remote_tests_remotetestutils
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsInotifytestsTest)
  add_osquery_executable(osquery_events_tests_inotifytests-test linux/inotify_tests.cpp)

  target_link_libraries(osquery_events_tests_inotifytests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsFseventstestsTest)
  add_osquery_executable(osquery_events_tests_fseventstests-test darwin/fsevents_tests.cpp)

  target_link_libraries(osquery_events_tests_fseventstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_utils
    osquery_utils_conversions
    specs_tables
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsWindowsusnjournalreadertestsTest)
  add_osquery_executable(osquery_events_tests_usnjournalreadertests-test windows/usn_journal_reader_tests.cpp)

  target_link_libraries(osquery_events_tests_usnjournalreadertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_utils
    osquery_utils_conversions
    specs_tables
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryEventsTestsMain()
