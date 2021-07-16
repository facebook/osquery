# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(specsMain)
  add_osquery_library(specs_tables INTERFACE)

  generateNativeTables()
  list(APPEND table_target_list "${generateNativeTables_output}")

  generateForeignTables(${foreign_spec_file_list_output})
  list(APPEND table_target_list "${generateForeignTables_output}")

  foreach(table_target ${table_target_list})
    target_link_libraries("${table_target}" PUBLIC osquery_tables_tableimplementations)
    enableLinkWholeArchive("${table_target}")
  endforeach()

  target_link_libraries(specs_tables INTERFACE ${table_target_list})

  generateCopyFileTarget("specs_table_files" "" "REGEX" "*.table" "${TEST_CONFIGS_DIR}/specs")
endfunction()

function(generateForeignTables spec_file_list)
  generateTableCategoryAmalgamation("foreign" ${spec_file_list})
  set(generateForeignTables_output "${generateTableCategoryAmalgamation_output}" PARENT_SCOPE)
endfunction()

function(generateNativeTables)
  set(platform_independent_spec_files
    azure_instance_metadata.table
    azure_instance_tags.table
    carbon_black_info.table
    carves.table
    chrome_extensions.table
    chrome_extension_content_scripts.table
    curl.table
    curl_certificate.table
    etc_hosts.table
    etc_protocols.table
    etc_services.table
    groups.table
    firefox_addons.table
    hash.table
    interface_addresses.table
    interface_details.table
    listening_ports.table
    logged_in_users.table
    os_version.table
    platform_info.table
    process_memory_map.table
    process_open_sockets.table
    processes.table
    python_packages.table
    routes.table
    ssh_configs.table
    startup_items.table
    system_info.table
    uptime.table
    user_ssh_keys.table
    users.table
    utility/file.table
    utility/osquery_events.table
    utility/osquery_extensions.table
    utility/osquery_flags.table
    utility/osquery_info.table
    utility/osquery_packs.table
    utility/osquery_registry.table
    utility/osquery_schedule.table
    utility/time.table
    ycloud_instance_metadata.table
  )

  if(TARGET_PROCESSOR STREQUAL "x86_64")
    list(APPEND platform_independent_spec_files cpuid.table)
  endif()

  set(platform_dependent_spec_files
    "arp_cache.table:linux,macos,windows"
    "atom_packages.table:linux,macos,windows"
    "darwin/account_policy_data.table:macos"
    "darwin/ad_config.table:macos"
    "darwin/alf.table:macos"
    "darwin/alf_exceptions.table:macos"
    "darwin/alf_explicit_auths.table:macos"
    "darwin/app_schemes.table:macos"
    "darwin/apps.table:macos"
    "darwin/asl.table:macos"
    "darwin/authorization_mechanisms.table:macos"
    "darwin/authorizations.table:macos"
    "darwin/battery.table:macos"
    "darwin/browser_plugins.table:macos"
    "darwin/crashes.table:macos"
    "darwin/cups_destinations.table:macos"
    "darwin/cups_jobs.table:macos"
    "darwin/device_firmware.table:macos"
    "darwin/disk_events.table:macos"
    "darwin/es_process_events.table:macos"
    "darwin/event_taps.table:macos"
    "darwin/fan_speed_sensors.table:macos"
    "darwin/gatekeeper.table:macos"
    "darwin/gatekeeper_approved_apps.table:macos"
    "darwin/homebrew_packages.table:macos"
    "darwin/ibridge_info.table:macos"
    "darwin/iokit_devicetree.table:macos"
    "darwin/iokit_registry.table:macos"
    "darwin/kernel_extensions.table:macos"
    "darwin/kernel_panics.table:macos"
    "darwin/keychain_acls.table:macos"
    "darwin/keychain_items.table:macos"
    "darwin/launchd.table:macos"
    "darwin/launchd_overrides.table:macos"
    "darwin/location_services.table:macos"
    "darwin/managed_policies.table:macos"
    "darwin/mdfind.table:macos"
    "darwin/mdls.table:macos"
    "darwin/nfs_shares.table:macos"
    "darwin/nvram.table:macos"
    "darwin/package_bom.table:macos"
    "darwin/package_install_history.table:macos"
    "darwin/package_receipts.table:macos"
    "darwin/plist.table:macos"
    "darwin/power_sensors.table:macos"
    "darwin/preferences.table:macos"
    "darwin/quicklook_cache.table:macos"
    "darwin/running_apps.table:macos"
    "darwin/safari_extensions.table:macos"
    "darwin/sandboxes.table:macos"
    "darwin/screenlock.table:macos"
    "darwin/shared_folders.table:macos"
    "darwin/sharing_preferences.table:macos"
    "darwin/signature.table:macos"
    "darwin/sip_config.table:macos"
    "darwin/smc_keys.table:macos"
    "darwin/system_extensions.table:macos"
    "darwin/temperature_sensors.table:macos"
    "darwin/time_machine_backups.table:macos"
    "darwin/time_machine_destinations.table:macos"
    "darwin/unified_log.table:macos"
    "darwin/user_interaction_events.table:macos"
    "darwin/virtual_memory_info.table:macos"
    "darwin/wifi_networks.table:macos"
    "darwin/wifi_scan.table:macos"
    "darwin/wifi_status.table:macos"
    "darwin/xprotect_entries.table:macos"
    "darwin/xprotect_meta.table:macos"
    "darwin/xprotect_reports.table:macos"
    "freebsd/fbsd_kmods.table:freebsd"
    "freebsd/pkg_packages.table:freebsd"
    "linux/selinux_events.table:linux"
    "linux/seccomp_events.table:linux"
    "linux/elf_symbols.table:linux"
    "linux/portage_use.table:linux"
    "linux/rpm_package_files.table:linux"
    "linux/shared_memory.table:linux"
    "linux/iptables.table:linux"
    "linux/portage_keywords.table:linux"
    "linux/elf_segments.table:linux"
    "linux/md_devices.table:linux"
    "linux/process_namespaces.table:linux"
    "linux/syslog_events.table:linux"
    "linux/rpm_packages.table:linux"
    "linux/portage_packages.table:linux"
    "linux/process_file_events.table:linux"
    "linux/md_drives.table:linux"
    "linux/npm_packages.table:linux"
    "linux/elf_info.table:linux"
    "linux/md_personalities.table:linux"
    "linux/kernel_modules.table:linux"
    "linux/shadow.table:linux"
    "linux/memory_info.table:linux"
    "linux/msr.table:linux"
    "linux/memory_map.table:linux"
    "linux/elf_dynamic.table:linux"
    "linux/elf_sections.table:linux"
    "linux/selinux_settings.table:linux"
    "linux/apparmor_profiles.table:linux"
    "linux/apparmor_events.table:linux"
    "linux/systemd_units.table:linux"
    "linwin/intel_me_info.table:linux,windows"
    "lldpd/lldp_neighbors.table:linux,macos,freebsd"
    "kernel_info.table:linux,macos,windows"
    "macwin/certificates.table:macos,windows"
    "posix/extended_attributes.table:linux,macos"
    "posix/acpi_tables.table:linux,macos"
    "posix/apt_sources.table:linux,macos,freebsd"
    "posix/augeas.table:linux,macos,freebsd"
    "posix/authorized_keys.table:linux,macos,freebsd"
    "posix/block_devices.table:linux,macos"
    "posix/cpu_time.table:linux,macos,freebsd"
    "posix/crontab.table:linux,macos,freebsd"
    "posix/disk_encryption.table:linux,macos"
    "posix/dns_resolvers.table:linux,macos,freebsd"
    "posix/docker_container_labels.table:linux,macos,freebsd"
    "posix/docker_container_mounts.table:linux,macos,freebsd"
    "posix/docker_container_networks.table:linux,macos,freebsd"
    "posix/docker_container_ports.table:linux,macos,freebsd"
    "posix/docker_container_processes.table:linux,macos,freebsd"
    "posix/docker_container_fs_changes.table:linux,macos,freebsd"
    "posix/docker_container_stats.table:linux,macos,freebsd"
    "posix/docker_containers.table:linux,macos,freebsd"
    "posix/docker_image_history.table:linux,macos,freebsd"
    "posix/docker_image_labels.table:linux,macos,freebsd"
    "posix/docker_image_layers.table:linux,macos,freebsd"
    "posix/docker_images.table:linux,macos,freebsd"
    "posix/docker_info.table:linux,macos,freebsd"
    "posix/docker_network_labels.table:linux,macos,freebsd"
    "posix/docker_networks.table:linux,macos,freebsd"
    "posix/docker_version.table:linux,macos,freebsd"
    "posix/docker_volume_labels.table:linux,macos,freebsd"
    "posix/docker_volumes.table:linux,macos,freebsd"
    "posix/file_events.table:linux,macos"
    "posix/hardware_events.table:linux,macos"
    "posix/interface_ipv6.table:linux,macos,freebsd"
    "posix/known_hosts.table:linux,macos,freebsd"
    "posix/last.table:linux,macos,freebsd"
    "posix/load_average.table:linux,macos,freebsd"
    "posix/lxd_instances.table:linux"
    "posix/lxd_instance_config.table:linux"
    "posix/lxd_instance_devices.table:linux"
    "posix/lxd_cluster.table:linux"
    "posix/lxd_cluster_members.table:linux"
    "posix/lxd_images.table:linux"
    "posix/lxd_certificates.table:linux"
    "posix/lxd_networks.table:linux"
    "posix/lxd_storage_pools.table:linux"
    "posix/magic.table:linux,macos,freebsd"
    "posix/memory_array_mapped_addresses.table:linux,macos"
    "posix/memory_arrays.table:linux,macos"
    "posix/memory_device_mapped_addresses.table:linux,macos"
    "posix/memory_devices.table:linux,macos"
    "posix/memory_error_info.table:linux,macos"
    "posix/mounts.table:linux,macos,freebsd"
    "posix/oem_strings.table:linux,macos"
    "posix/pci_devices.table:linux,macos"
    "posix/process_envs.table:linux,macos,freebsd"
    "posix/process_events.table:linux,macos,freebsd"
    "posix/process_open_files.table:linux,macos,freebsd"
    "posix/process_open_pipes.table:linux"
    "posix/prometheus_metrics.table:linux,macos,freebsd"
    "posix/shell_history.table:linux,macos,freebsd"
    "posix/smbios_tables.table:linux,macos"
    "posix/socket_events.table:linux,macos"
    "posix/sudoers.table:linux,macos,freebsd"
    "posix/suid_bin.table:linux,macos,freebsd"
    "posix/system_controls.table:linux,macos,freebsd"
    "posix/ulimit_info.table:linux,macos,freebsd"
    "posix/usb_devices.table:linux,macos"
    "posix/user_events.table:linux,macos,freebsd"
    "posix/yum_sources.table:linux,macos,freebsd"
    "sleuthkit/device_file.table:linux,macos,freebsd,windows"
    "sleuthkit/device_hash.table:linux,macos,freebsd,windows"
    "sleuthkit/device_partitions.table:linux,macos,freebsd,windows"
    "smart/smart_drive_info.table:linux,macos"
    "user_groups.table:linux,macos,windows"
    "windows/background_activities_moderator.table:windows"
    "windows/bitlocker_info.table:windows"
    "windows/chassis_info.table:windows"
    "windows/logon_sessions.table:windows"
    "windows/ntfs_acl_permissions.table:windows"
    "windows/office_mru.table:windows"
    "windows/scheduled_tasks.table:windows"
    "windows/windows_crashes.table:windows"
    "windows/services.table:windows"
    "windows/kva_speculative_info.table:windows"
    "windows/patches.table:windows"
    "windows/ie_extensions.table:windows"
    "windows/shared_resources.table:windows"
    "windows/wmi_cli_event_consumers.table:windows"
    "windows/video_info.table:windows"
    "windows/registry.table:windows"
    "windows/drivers.table:windows"
    "windows/disk_info.table:windows"
    "windows/chocolatey_packages.table:windows"
    "windows/logical_drives.table:windows"
    "windows/ntdomains.table:windows"
    "windows/authenticode.table:windows"
    "windows/pipes.table:windows"
    "windows/wmi_filter_consumer_binding.table:windows"
    "windows/wmi_event_filters.table:windows"
    "windows/windows_events.table:windows"
    "windows/windows_eventlog.table:windows"
    "windows/appcompat_shims.table:windows"
    "windows/ntfs_journal_events.table:windows"
    "windows/powershell_events.table:windows"
    "windows/winbaseobj.table:windows"
    "windows/cpu_info.table:windows"
    "windows/wmi_bios_info.table:windows"
    "windows/programs.table:windows"
    "windows/wmi_script_event_consumers.table:windows"
    "windows/physical_disk_performance.table:windows"
    "windows/autoexec.table:windows"
    "windows/default_environment.table:windows"
    "windows/windows_security_products.table:windows"
    "windows/windows_security_center.table:windows"
    "windows/windows_optional_features.table:windows"
    "windows/connectivity.table:windows"
    "windows/userassist.table:windows"
    "windows/dns_cache.table:windows"
    "windows/hvci_status.table:windows"
    "windows/shimcache.table:windows"
    "windows/shellbags.table:windows"
    "windows/prefetch.table:windows"
    "windows/shortcut_files.table:windows"
    "yara/yara_events.table:linux,macos"
    "yara/yara.table:linux,macos,freebsd,windows"
  )

  if(OSQUERY_BUILD_BPF)
    list(APPEND platform_dependent_spec_files
      "linux/bpf_process_events.table:linux"
      "linux/bpf_socket_events.table:linux"
    )
  endif()

  if(OSQUERY_BUILD_AWS)
    list(APPEND platform_independent_spec_files
      "ec2_instance_metadata.table"
      "ec2_instance_tags.table"
    )
  endif()

  if(OSQUERY_BUILD_DPKG)
    list(APPEND platform_dependent_spec_files
      "linux/deb_packages.table:linux"
    )
  endif()

  foreach(spec_descriptor ${platform_dependent_spec_files})
    string(REPLACE ":" ";" spec_descriptor "${spec_descriptor}")
    list(GET spec_descriptor 0 spec_file)

    list(GET spec_descriptor 1 spec_descriptor)
    string(REPLACE "," ";" spec_file_platforms "${spec_descriptor}")

    list(FIND spec_file_platforms "linux" is_linux_compatible)
    list(FIND spec_file_platforms "macos" is_macos_compatible)
    list(FIND spec_file_platforms "freebsd" is_freebsd_compatible)
    list(FIND spec_file_platforms "windows" is_windows_compatible)

    if(DEFINED PLATFORM_LINUX AND NOT ${is_linux_compatible} EQUAL -1)
      set(enable_spec_file true)
    elseif(DEFINED PLATFORM_MACOS AND NOT ${is_macos_compatible} EQUAL -1)
      set(enable_spec_file true)
    elseif(DEFINED PLATFORM_FREEBSD AND NOT ${is_freebsd_compatible} EQUAL -1)
      set(enable_spec_file true)
    elseif(DEFINED PLATFORM_WINDOWS AND NOT ${is_windows_compatible} EQUAL -1)
      set(enable_spec_file true)
    else()
      set(enable_spec_file false)
    endif()

    if(${enable_spec_file})
      list(APPEND spec_file_list
        "${spec_file}"
      )
    else()
      list(APPEND foreign_spec_file_list
        "${spec_file}"
      )
    endif()
  endforeach()

  list(APPEND spec_file_list ${platform_independent_spec_files})

  generateTableCategoryAmalgamation("native" ${spec_file_list})
  set(generateNativeTables_output "${generateTableCategoryAmalgamation_output}" PARENT_SCOPE)
  set(foreign_spec_file_list_output "${foreign_spec_file_list}" PARENT_SCOPE)
endfunction()

specsMain()