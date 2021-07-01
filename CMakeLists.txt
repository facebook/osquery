# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

cmake_minimum_required(VERSION 3.17.5 FATAL_ERROR)

cmake_policy(SET CMP0083 NEW)

# toolchain.cmake needs to be included before project() because the former sets the compiler path for the custom toolchain,
# if the user specify it and the latter does compiler detection.
# utilities.cmake is a dependency of toolchain.cmake.
include(cmake/utilities.cmake)
include(cmake/toolchain.cmake)

project(osquery)

if(OSQUERY_BUILD_TESTS)
  enable_testing()
endif()

include(cmake/globals.cmake)
include(cmake/options.cmake)
include(cmake/flags.cmake)

if(OSQUERY_TOOLCHAIN_SYSROOT AND NOT DEFINED PLATFORM_LINUX)
  message(FATAL_ERROR "The custom toolchain can only be used with Linux, undefine OSQUERY_TOOLCHAIN_SYSROOT and specify a compiler to use")
endif()

# clang-tidy needs to be initialized in global scope, before any
# target is created
if(OSQUERY_ENABLE_CLANG_TIDY)
  find_package(clang-tidy)
  if(TARGET clang-tidy::clang-tidy)
    foreach(language C CXX)
      set("CMAKE_${language}_CLANG_TIDY"
        "${CLANG-TIDY_EXECUTABLE};${OSQUERY_CLANG_TIDY_CHECKS}"
      )
    endforeach()

  else()
    message(WARNING "clang-tidy: Disabled because it was not found")
  endif()
endif()

function(main)

  findClangFormat()
  findPythonExecutablePath()
  generateSpecialTargets()

  if(OSQUERY_ENABLE_FORMAT_ONLY)
    return()
  endif()

  message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
  message(STATUS "Shared libraries: ${BUILD_SHARED_LIBS}")

  if(DEFINED PLATFORM_MACOS)
    if((NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" AND NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang") OR
      (NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang"))
      message(STATUS "Warning: the selected C or C++ compiler is not clang/clang++. Compilation may fail")
    endif()
  elseif(NOT DEFINED PLATFORM_WINDOWS)
    if(NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
       NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      message(STATUS "Warning: the selected C or C++ compiler is not clang/clang++. Compilation may fail")
    endif()
  endif()

  add_subdirectory("libraries")
  importLibraries()

  add_subdirectory("osquery")
  add_subdirectory("plugins")
  add_subdirectory("tools")
  add_subdirectory("specs")
  add_subdirectory("external")
  add_subdirectory("tests")

  if(DEFINED PLATFORM_WINDOWS)
    enableOsqueryWEL()
  endif()

  generateInstallDirectives()
endfunction()

function(importLibraries)
  set(library_descriptor_list
    "Linux,Darwin:augeas"
    "Linux,Darwin,Windows:boost"
    "Linux,Darwin,Windows:bzip2"
    "Linux,Darwin,Windows:gflags"
    "Linux,Darwin,Windows:glog"
    "Linux,Darwin,Windows:googletest"
    "Linux,Darwin,Windows:libarchive"
    "Linux:libaudit"
    "Linux:libcryptsetup"
    "Linux:libdevmapper"
    "Linux:libelfin"
    "Linux:libgcrypt"
    "Linux:libgpg-error"
    "Linux:libiptables"
    "Linux,Darwin:libmagic"
    "Linux,Darwin,Windows:librdkafka"
    "Linux:librpm"
    "Linux:libudev"
    "Linux,Darwin,Windows:libxml2"
    "Linux,Darwin,Windows:linenoise-ng"
    "Linux,Darwin:lldpd"
    "Linux,Darwin,Windows:lzma"
    "Linux,Darwin:popt"
    "Linux,Darwin,Windows:rapidjson"
    "Linux,Darwin,Windows:rocksdb"
    "Linux,Darwin,Windows:sleuthkit"
    "Linux,Darwin:smartmontools"
    "Linux,Darwin,Windows:sqlite"
    "Linux,Darwin:ssdeep-cpp"
    "Linux,Darwin,Windows:thrift"
    "Linux:util-linux"
    "Linux,Darwin,Windows:yara"
    "Linux,Darwin,Windows:zlib"
    "Linux,Darwin,Windows:zstd"
    "Linux,Darwin,Windows:openssl"
    "Linux,Darwin,Windows:icu"
    "Linux:expat"
    "Linux:dbus"
    "Linux:libcap"
  )

  if(OSQUERY_BUILD_BPF)
    list(APPEND library_descriptor_list
      "Linux:ebpfpub"
    )
  endif()

  if(OSQUERY_BUILD_AWS)
    list(APPEND library_descriptor_list
      "Linux,Darwin,Windows:aws-sdk-cpp"
    )
  endif()

  if(OSQUERY_BUILD_DPKG)
    list(APPEND library_descriptor_list
      "Linux:libdpkg"
    )
  endif()

  foreach(library_descriptor ${library_descriptor_list})
    # Expand the library descriptor
    string(REPLACE ":" ";" library_descriptor "${library_descriptor}")

    list(GET library_descriptor 0 platform_list)
    list(GET library_descriptor 1 library)

    string(REPLACE "," ";" platform_list "${platform_list}")

    list(FIND platform_list "${CMAKE_SYSTEM_NAME}" platform_index)
    if(platform_index EQUAL -1)
      continue()
    endif()

    find_package("${library}" REQUIRED)

    # Skip libraries which already use our internal target name
    if(TARGET "thirdparty_${library}")
      continue()

    # For generic libraries that import the library name, let's create
    # an alias
    elseif(TARGET "${library}")
      add_library("thirdparty_${library}" ALIAS "${library}")

    # Legacy libraries will just export variables; build a new INTERFACE
    # target with them
    elseif(DEFINED "${library}_LIBRARIES")
      if(NOT DEFINED "${library}_INCLUDE_DIRS")
        message(FATAL_ERROR "Variable ${library}_INCLUDE_DIRS was not found!")
      endif()

      add_library("thirdparty_${library}" INTERFACE)

      target_link_libraries("thirdparty_${library}" INTERFACE
        ${library}_LIBRARIES
      )

      target_include_directories("thirdparty_${library}" INTERFACE
        ${library}_INCLUDE_DIRS
      )

      if(DEFINED "${library}_DEFINITIONS")
        target_compile_definitions("thirdparty_${library}" INTERFACE
          ${library}_DEFINITIONS
        )
      endif()

    else()
      # In case we were trying to import ebpfpub, check whether the build option
      # has been turned OFF automatically because the installed LLVM libraries
      # were broken/not compatible
      if(NOT OSQUERY_BUILD_BPF AND "${library}" STREQUAL "ebpfpub")
        message(WARNING "ebpfpub could not correctly import the LLVM libraries. BPF support has been disabled")
      else()
        message(FATAL_ERROR "The '${library}' library was found but it couldn't be imported correctly")
      endif()
    endif()
  endforeach()
endfunction()

function(generateInstallDirectives)
  get_property(augeas_lenses_path
    GLOBAL PROPERTY "AUGEAS_LENSES_FOLDER_PATH"
  )

  if(PLATFORM_LINUX)
    install(
      FILES "tools/deployment/linux_packaging/deb/conffiles"
      DESTINATION "/control/deb"
    )

    install(
      FILES "tools/deployment/linux_packaging/deb/osqueryd.service"
      DESTINATION "/control/deb/lib/systemd/system"
    )

    install(
      FILES "tools/deployment/linux_packaging/deb/copyright"
      DESTINATION "/control/deb"
    )

    install(
      FILES "tools/deployment/linux_packaging/deb/osquery.initd"
      DESTINATION "/control/deb/etc/init.d"
      RENAME "osqueryd"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      FILES "tools/deployment/linux_packaging/rpm/osquery.initd"
      DESTINATION "/control/rpm/etc/init.d"
      RENAME "osqueryd"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      FILES "tools/deployment/linux_packaging/rpm/osqueryd.service"
      DESTINATION "/control/rpm/lib/systemd/system"
    )

    install(
      FILES "tools/deployment/linux_packaging/postinst"
      DESTINATION "/control"
    )

    install(
      TARGETS osqueryd
      DESTINATION "bin"
    )

    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E create_symlink osqueryd osqueryi
      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    install(
      FILES "${CMAKE_CURRENT_BINARY_DIR}/osqueryi"
      DESTINATION "bin"
    )

    install(
      FILES "tools/deployment/osqueryctl"
      DESTINATION "bin"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      FILES "tools/deployment/osquery.example.conf"
      DESTINATION "share/osquery"
    )

    install(
      DIRECTORY "${augeas_lenses_path}/"
      DESTINATION "share/osquery/lenses"
      FILES_MATCHING PATTERN "*.aug"
      PATTERN "tests" EXCLUDE
    )

    install(
      FILES "${augeas_lenses_path}/../COPYING"
      DESTINATION "share/osquery/lenses"
    )

    install(
      DIRECTORY "packs"
      DESTINATION "share/osquery"
    )

    install(
      FILES "${CMAKE_SOURCE_DIR}/tools/deployment/certs.pem"
      DESTINATION "share/osquery/certs"
    )

    install(
      FILES "tools/deployment/linux_packaging/osqueryd.sysconfig"
      DESTINATION "/control/deb/etc/default"
      RENAME "osqueryd"
    )

    install(
      FILES "tools/deployment/linux_packaging/osqueryd.sysconfig"
      DESTINATION "/control/rpm/etc/sysconfig"
      RENAME "osqueryd"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control"
      RENAME "LICENSE.txt"
    )

  elseif(PLATFORM_WINDOWS)

    # CMake doesn't prefer 'Program Files' on x64 platforms, more information
    # here: https://gitlab.kitware.com/cmake/cmake/-/issues/18312
    # This is a workaround, to ensure that we leverage 'Program Files' when
    # on a 64 bit system.
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
      if(CMAKE_SIZEOF_VOID_P MATCHES "8") 
        set(CMAKE_INSTALL_PREFIX "/Program Files/${CMAKE_PROJECT_NAME}" CACHE PATH "" FORCE) 
      else() 
        set(CMAKE_INSTALL_PREFIX "/Program Files (x86)/${CMAKE_PROJECT_NAME}" CACHE PATH "" FORCE) 
      endif() 
    endif()

    install(
      TARGETS osqueryd
      DESTINATION "osqueryd"
    )

    install(
      PROGRAMS "$<TARGET_FILE:osqueryd>"
      DESTINATION "."
      RENAME "osqueryi.exe"
    )

    install(
      DIRECTORY "tools/deployment/windows_packaging/chocolatey/tools"
      DESTINATION "/control/nupkg"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control/nupkg/extras"
      RENAME "LICENSE.txt"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control"
      RENAME "LICENSE.txt"
    )

    # Icon for the MSI package
    install(
      FILES "tools/deployment/windows_packaging/osquery.ico"
      DESTINATION "/control"
    )

    # Icon for the nuget package
    install(
      FILES "tools/deployment/windows_packaging/osquery.png"
      DESTINATION "/control"
    )

    install(
      FILES "tools/deployment/windows_packaging/chocolatey/VERIFICATION.txt"
      DESTINATION "/control/nupkg/extras"
    )
    
    install(
      FILES "tools/deployment/osquery.example.conf"
      DESTINATION "."
      RENAME "osquery.conf"
    )

    install(
      FILES "tools/wel/osquery.man"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/manage-osqueryd.ps1"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/osquery_utils.ps1"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/osquery.flags"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/manage-osqueryd.ps1"
      DESTINATION "/control/nupkg/extras"
    )

    install(
      FILES "tools/deployment/windows_packaging/osquery_utils.ps1"
      DESTINATION "/control/nupkg/tools"
    )

    install(
      FILES "tools/deployment/windows_packaging/msi/osquery_wix_patch.xml"
      DESTINATION "/control/msi"
    )

    install(
      FILES "tools/deployment/certs.pem"
      DESTINATION "certs"
    )

    install(
      DIRECTORY
      DESTINATION "log"
    )

  elseif(PLATFORM_MACOS)

    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
      set(CMAKE_INSTALL_PREFIX "/opt" CACHE PATH "" FORCE) 
    endif()
    
    install(
      FILES
        "tools/deployment/macos_packaging/osquery.entitlements"
        "tools/deployment/macos_packaging/embedded.provisionprofile"
        "tools/deployment/macos_packaging/Info.plist"
        "tools/deployment/macos_packaging/PkgInfo"

      DESTINATION
        "/control"
    )

    install(
      FILES
        "tools/deployment/macos_packaging/pkg/productbuild.sh"

      DESTINATION
        "/control/pkg"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      TARGETS osqueryd
      DESTINATION "bin"
    )

    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E create_symlink osqueryd osqueryi
      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    install(
      FILES "${CMAKE_CURRENT_BINARY_DIR}/osqueryi"
      DESTINATION "bin"
    )

    install(
      FILES "tools/deployment/osqueryctl"
      DESTINATION "bin"
    )

    install(
      DIRECTORY "${augeas_lenses_path}"
      DESTINATION "/private/var/osquery"
      FILES_MATCHING PATTERN "*.aug"
      PATTERN "tests" EXCLUDE
    )

    install(
      DIRECTORY "packs"
      DESTINATION "/private/var/osquery"
    )

    install(
      FILES "tools/deployment/certs.pem"
      DESTINATION "/private/var/osquery/certs"
    )

    install(
      FILES
        "tools/deployment/osquery.example.conf"

      DESTINATION
        "/private/var/osquery"
    )

    install(
      FILES
        "tools/deployment/macos_packaging/pkg/com.facebook.osqueryd.conf"
        "tools/deployment/macos_packaging/pkg/com.facebook.osqueryd.plist"

      DESTINATION
        "/control/pkg"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control"
      RENAME "LICENSE.txt"
    )

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()
endfunction()

main()
