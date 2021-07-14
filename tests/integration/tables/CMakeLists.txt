# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(testsIntegrationTablesMain)
  generateTestsIntegrationTablesIntegrationtestshelper()
  generateTestsIntegrationTablesTestsTest()

endfunction()

function(generateTestsIntegrationTablesIntegrationtestshelper)
  add_osquery_library(tests_integration_tables_integrationtestshelper EXCLUDE_FROM_ALL helper.cpp)

  set(public_headers
    helper.h
  )

  generateIncludeNamespace(tests_integration_tables_integrationtestshelper "osquery/tests/integration/tables" "FILE_ONLY" ${public_headers})

  target_link_libraries(tests_integration_tables_integrationtestshelper PUBLIC
    osquery_cxx_settings
    osquery_database
    osquery_sql
    osquery_utils
    thirdparty_boost
    thirdparty_googletest_headers
  )
endfunction()

function(generateTestsIntegrationTablesTestsTest)
  set(source_files
    carbon_black_info.cpp
    carves.cpp
    chrome_extensions.cpp
    curl.cpp
    curl_certificate.cpp
    etc_hosts.cpp
    etc_protocols.cpp
    etc_services.cpp
    file.cpp
    firefox_addons.cpp
    groups.cpp
    hash.cpp
    interface_addresses.cpp
    interface_details.cpp
    listening_ports.cpp
    logged_in_users.cpp
    os_version.cpp
    osquery_events.cpp
    osquery_extensions.cpp
    osquery_flags.cpp
    osquery_info.cpp
    osquery_packs.cpp
    osquery_registry.cpp
    osquery_schedule.cpp
    platform_info.cpp
    process_memory_map.cpp
    process_open_sockets.cpp
    processes.cpp
    python_packages.cpp
    routes.cpp
    system_info.cpp
    time.cpp
    uptime.cpp
    user_groups.cpp
    users.cpp
    ssh_configs.cpp
    user_ssh_keys.cpp
    device_file.cpp
    device_hash.cpp
    device_partitions.cpp
    ycloud_instance_metadata.cpp
  )

  if(TARGET_PROCESSOR STREQUAL "x86_64")
    list(APPEND source_files cpuid.cpp)
  endif()

  if(DEFINED PLATFORM_POSIX)
    set(platform_source_files
      acpi_tables.cpp
      apt_sources.cpp
      augeas.cpp
      authorized_keys.cpp
      block_devices.cpp
      cpu_time.cpp
      crontab.cpp
      disk_encryption.cpp
      dns_resolvers.cpp
      docker_container_labels.cpp
      docker_container_mounts.cpp
      docker_container_networks.cpp
      docker_container_ports.cpp
      docker_container_processes.cpp
      docker_container_stats.cpp
      docker_containers.cpp
      docker_image_history.cpp
      docker_image_labels.cpp
      docker_image_layers.cpp
      docker_images.cpp
      docker_info.cpp
      docker_network_labels.cpp
      docker_networks.cpp
      docker_version.cpp
      docker_volume_labels.cpp
      docker_volumes.cpp
      file_events.cpp
      hardware_events.cpp
      interface_ipv6.cpp
      known_hosts.cpp
      last.cpp
      lldp_neighbors.cpp
      load_average.cpp
      magic.cpp
      memory_array_mapped_addresses.cpp
      memory_arrays.cpp
      memory_device_mapped_addresses.cpp
      memory_devices.cpp
      memory_error_info.cpp
      mounts.cpp
      oem_strings.cpp
      pci_devices.cpp
      process_envs.cpp
      process_events.cpp
      process_open_files.cpp
      prometheus_metrics.cpp
      shell_history.cpp
      smbios_tables.cpp
      sudoers.cpp
      suid_bin.cpp
      system_controls.cpp
      ulimit_info.cpp
      usb_devices.cpp
      user_events.cpp
      yum_sources.cpp
    )

    list(APPEND source_files ${platform_source_files})
  endif()

  if(OSQUERY_BUILD_AWS AND (DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_WINDOWS))
    list(APPEND source_files
      ec2_instance_metadata.cpp
      ec2_instance_tags.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    set(platform_source_files
      arp_cache.cpp
      atom_packages.cpp
      elf_dynamic.cpp
      elf_info.cpp
      elf_sections.cpp
      elf_segments.cpp
      elf_symbols.cpp
      intel_me_info.cpp
      iptables.cpp
      kernel_info.cpp
      kernel_modules.cpp
      md_devices.cpp
      md_drives.cpp
      md_personalities.cpp
      memory_info.cpp
      memory_map.cpp
      msr.cpp
      npm_packages.cpp
      portage_keywords.cpp
      portage_packages.cpp
      portage_use.cpp
      process_file_events.cpp
      process_namespaces.cpp
      process_open_pipes.cpp
      rpm_package_files.cpp
      rpm_packages.cpp
      selinux_events.cpp
      shadow.cpp
      shared_memory.cpp
      smart_drive_info.cpp
      socket_events.cpp
      startup_items.cpp
      syslog_events.cpp
      systemd_units.cpp
      yara_events.cpp
      yara.cpp
    )

    if(OSQUERY_BUILD_DPKG)
      list(APPEND platform_source_files
        deb_packages.cpp
      )
    endif()

    list(APPEND source_files ${platform_source_files})
  elseif(DEFINED PLATFORM_MACOS)
    set(platform_source_files
      account_policy_data.cpp
      ad_config.cpp
      alf.cpp
      alf_exceptions.cpp
      alf_explicit_auths.cpp
      alf_services.cpp
      app_schemes.cpp
      apps.cpp
      arp_cache.cpp
      asl.cpp
      atom_packages.cpp
      authorization_mechanisms.cpp
      authorizations.cpp
      battery.cpp
      browser_plugins.cpp
      certificates.cpp
      crashes.cpp
      cups_destinations.cpp
      cups_jobs.cpp
      device_firmware.cpp
      disk_events.cpp
      event_taps.cpp
      extended_attributes.cpp
      fan_speed_sensors.cpp
      gatekeeper.cpp
      gatekeeper_approved_apps.cpp
      homebrew_packages.cpp
      ibridge.cpp
      iokit_devicetree.cpp
      iokit_registry.cpp
      kernel_extensions.cpp
      kernel_info.cpp
      kernel_panics.cpp
      keychain_acls.cpp
      keychain_items.cpp
      launchd.cpp
      launchd_overrides.cpp
      location_services.cpp
      managed_policies.cpp
      mdfind.cpp
      nfs_shares.cpp
      nvram.cpp
      package_bom.cpp
      package_install_history.cpp
      package_receipts.cpp
      plist.cpp
      power_sensors.cpp
      preferences.cpp
      quicklook_cache.cpp
      running_apps.cpp
      safari_extensions.cpp
      sandboxes.cpp
      shared_folders.cpp
      sharing_preferences.cpp
      signature.cpp
      sip_config.cpp
      smart_drive_info.cpp
      smc_keys.cpp
      startup_items.cpp
      system_extensions.cpp
      temperature_sensors.cpp
      time_machine_backups.cpp
      time_machine_destinations.cpp
      user_interaction_events.cpp
      virtual_memory_info.cpp
      wifi_networks.cpp
      wifi_status.cpp
      wifi_survey.cpp
      xprotect_entries.cpp
      xprotect_meta.cpp
      xprotect_reports.cpp
      yara_events.cpp
      yara.cpp
    )

    list(APPEND source_files ${platform_source_files})
  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_source_files
      appcompat_shims.cpp
      arp_cache.cpp
      authenticode.cpp
      autoexec.cpp
      background_activities_moderator.cpp
      bitlocker_info.cpp
      certificates.cpp
      connectivity.cpp
      chassis_info.cpp
      chocolatey_packages.cpp
      cpu_info.cpp
      default_environment.cpp
      disk_info.cpp
      drivers.cpp
      ie_extensions.cpp
      intel_me_info.cpp
      logon_sessions.cpp
      kernel_info.cpp
      kva_speculative_info.cpp
      logical_drives.cpp
      office_mru.cpp
      ntdomains.cpp
      ntfs_acl_permissions.cpp
      patches.cpp
      physical_disk_performance.cpp
      pipes.cpp
      powershell_events.cpp
      prefetch.cpp
      programs.cpp
      registry.cpp
      scheduled_tasks.cpp
      services.cpp
      shared_resources.cpp
      shellbags.cpp
      shimcache.cpp
      shortcut_files.cpp
      startup_items.cpp
      userassist.cpp
      video_info.cpp
      winbaseobj.cpp
      windows_crashes.cpp
      windows_events.cpp
      windows_eventlog.cpp
      windows_security_products.cpp
      wmi_bios_info.cpp
      wmi_cli_event_consumers.cpp
      wmi_event_filters.cpp
      wmi_filter_consumer_binding.cpp
      wmi_script_event_consumers.cpp
      hvci_status.cpp
      yara.cpp
      tpm_info.cpp
    )

    list(APPEND source_files ${platform_source_files})
  elseif(DEFINED PLATFORM_FREEBSD)
    set(platform_source_files
      fbsd_kmods.cpp
      pkg_packages.cpp
    )

    list(APPEND source_files ${platform_source_files})

  endif()

  add_osquery_executable(tests_integration_tables-test ${source_files})

  target_link_libraries(tests_integration_tables-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    plugins_config_tlsconfig
    specs_tables
    tests_integration_tables_integrationtestshelper
    thirdparty_googletest
  )

  add_test(NAME tests_integration_tables-test COMMAND tests_integration_tables-test)
  set_tests_properties(
        tests_integration_tables-test
        PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )

endfunction()

testsIntegrationTablesMain()
