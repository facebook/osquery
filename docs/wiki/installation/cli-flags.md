# Command-line flags

The osquery shell and daemon use optional command-line (CLI) flags to control initialization, disable/enable features, and select plugins. These flags are powered by Google Flags and are somewhat complicated. Understanding how flags work in osquery will help with stability and greatly reduce issue debugging time.

Most flags apply to both tools, `osqueryi` and `osqueryd`. The shell contains a few more to help with printing and other helpful one-off modes of operation. Expect Linux, macOS, and Windows to include platform specific flags too. Most platform specific flags will control the OS API and library integrations used by osquery. Warning, this list is still not the 'complete set' of flags. Refer to the techniques below for obtaining ground truth and check other components of this Wiki.

Flags that do not control startup settings may be included as "options" within [configuration](../deployment/configuration.md). Essentially, any flag needed to help osquery determine and discover a configuration must be supplied via command-line arguments. Google Flags enhances this to allow flags to be set within environment variables or via a "master" flag file.

To see a full list of flags for your osquery version use `--help` or select from the `osquery_flags` table:

```sql
$ osqueryi
osquery> SELECT * FROM osquery_flags;
```

To see the flags that have been updated by your configuration, a flag file, or by the shell try:

```sql
osquery> SELECT * FROM osquery_flags WHERE default_value <> value;
```

## Flagfile

A special flag, part of Google Flags, can be used to read additional flags from a line-delimited file. On macOS and Linux this `--flagfile` is the recommended way to add/remove the following CLI-only initialization flags.

`--flagfile /etc/osquery/osquery.flags`

Include line-delimited switches to be interpreted and used as CLI-flags:

```text
--config_plugin=custom_plugin
--logger_plugin=custom_plugin
--distributed_plugin=custom_plugin
--watchdog_level=0
```

If no `--flagfile` is provided, osquery will try to find and use a "default" flagfile at `/etc/osquery/osquery.flags.default`. Both the shell and daemon will discover and use the defaults.

> NOTICE: Flags in a `flagfile` should not be wrapped in quotes, shell-macro/variable expansion is not applied!

## Configuration control flags

`--config_plugin=filesystem`

Config plugin name. The type of configuration retrieval, the default **filesystem** plugin reads a configuration JSON from disk.

Built-in options include: **filesystem**, **tls**

`--config_path=/etc/osquery/osquery.conf`

The **filesystem** config plugin's path to a JSON file.
On macOS the default path is `/var/osquery/osquery.conf`.
If you want to read from multiple configuration paths, create a directory: `/etc/osquery/osquery.conf.d/`. All files within that optional directory will be read and merged in lexical order.

`--config_refresh=0`

An optional configuration refresh interval in seconds. By default a configuration is fetched only at osquery load. If the configuration should be auto-updated, set a "refresh" time to a value in seconds greater than 0. If the configuration endpoint cannot be reached during runtime, the normal retry approach is applied (e.g., the **tls** config plugin will retry 3 times).

`--config_accelerated_refresh=300`

If a configuration refresh is used (`config_refresh > 0`) and the refresh attempt fails, the accelerated refresh will be used. This allows plugins like **tls** to fetch fresh data after having been offline for a while.

`--config_check=false`

Check the format of an osquery config and exit. Arbitrary config plugins may be used. osquery will return a non-0 exit if the parsing failed.

`--config_dump=false`

Request that the configuration JSON be printed to standard out before it is updated, then exit the process. In this case "updated" means applied to the active config. When osquery starts it performs an initial update from the config plugin. To quickly debug the content retrieved by custom config plugins use this in tandem with `--config_check`.

## Daemon control flags

`--force=false`

Force `osqueryd` to kill previously-running daemons. The daemon will check for an existing "pidfile". If found, and if it contains a pid of a process named "osqueryd", the process will be killed.

`--pidfile=/var/osquery/osqueryd.pidfile`

Path to the daemon pidfile mutex. The file is used to prevent multiple osqueryd processes starting.

`--disable_watchdog=false`

Disable userland watchdog process. `osqueryd` uses a watchdog process to monitor the memory and CPU utilization of threads executing the query schedule. If any performance limit is violated, the "worker" process will be restarted.

`--watchdog_level=0`

Performance limit level (`0`=normal, `1`=restrictive, `-1`=disabled). The watchdog process uses a "level" to configure performance limits.

The level limits are as follows:
Memory: default 200M, restrictive 100M
CPU: default 25% (for 9 seconds), restrictive 18% (for 9 seconds)

The normal level allows for 10 restarts if the limits are violated. The restrictive allows for only 4, then the service will be disabled. For both there is a linear backoff of 5 seconds, doubling each retry.

It is better to set the level to disabled (`-1`) rather than disabling the watchdog outright, as the worker/watcher concept is used for extensions auto-loading too.

The watchdog "profiles" can be overridden for Memory and CPU Utilization.

`--watchdog_memory_limit=0`

If this value is >0 then the watchdog level (`--watchdog_level`) for maximum memory is overridden. Use this if you would like to allow the `osqueryd` process to allocate more than 200M, but somewhere less than 1G. This memory limit is expressed as a value representing MB.

`--watchdog_utilization_limit=0`

If this value is >0 then the watchdog level (`--watchdog_level`) for maximum sustained CPU utilization is overridden. Use this if you would like to allow the `osqueryd` process to use more than 30% of a thread for more than 9 seconds of wall time. The length of sustained utilization is not independently configurable.

This value is a maximum number of CPU cycles counted as the `processes` table's `user_time` and `system_time`. The default is 90, meaning less 90 seconds of cpu time per 3 seconds of wall time is allowed.

`--watchdog_delay=60`

A delay in seconds before the watchdog process starts enforcing memory and CPU utilization limits. The default value `60s` allows the daemon to perform resource intense actions, such as forwarding logs, at startup.

`--enable_extensions_watchdog=false`

By default the watchdog monitors extensions for improper shutdown, but NOT for performance and utilization issues. Enable this flag if you would like extensions to use the same CPU and memory limits as the osquery worker. This means that your extensions or third-party extensions may be asked to stop and restart during execution.

`--utc=true`

Attempt to convert all UNIX calendar times to UTC.

`--table_delay=0`

Add a microsecond delay between multiple table calls (when a table is used in a JOIN). A `200` microsecond delay will trade about 20% additional time for a reduced 5% CPU utilization.

`--hash_cache_max=500`

The `hash` table implements a cache that is invalidated when file path inodes are changed. Eviction occurs in chunks if the max-size is reached. This max should remain relatively low since it will persist in the daemon's resident memory.

`--hash_delay=20`

Add a millisecond delay between multiple `hash` attempts (aka when scanning a directory). This adds about 50% additional wall-time for 150 files. This reduces the instantaneous resource need from hashing new files.

`--disable_hash_cache=false`

Set this to true if you would like to disable file hash caching and always regenerate the file hashes every request. The default osquery configuration may report hashes incorrectly if things are editing filesystems outside of the OS's control.

### Windows-only daemon control flags

Windows builds include a `--install` and `--uninstall` that will create a Windows service using the `osqueryd.exe` binary and preserve an optional `--flagfile` if provided.

## Backing storage control flags

`--database_path=/var/osquery/osquery.db`

If using a disk-based backing store, specify a path. osquery will keep state using a "backing store" using RocksDB by default. This state holds event information such that it may be queried later according to a schedule. It holds the results of the most recent query for each query within the schedule. This last-queried result allows query-differential logging.

`--database_dump=false`

Helpful for debugging database problems. This will print a line for each key in the backing store. Note: There could be MBs worth of data in the backing store.

## Extensions control flags

`--disable_extensions=false`

Disable extension API. See the [SDK development](../development/osquery-sdk.md) page for more information on osquery extensions, and the [deployment](../deployment/extensions.md) page for how to use extensions.

`--extensions_socket=/var/osquery/osquery.em`

Path to the extensions UNIX domain socket.
[Extensions](../deployment/extensions.md) use a UNIX domain socket for communication. It is very uncommon to change the location of the file. The osquery shell may use extensions, but the socket location is relative to the user invoking the shell and does not support concurrent shells.

`--extensions_autoload=/etc/osquery/extensions.load`

Optional path to a list of auto-loaded and managed extensions.
If using an extension to provide a proprietary config or logger plugin the extension process can be started by the daemon. Include line-delimited paths to extension executables. See the extensions [deployment](../deployment/extensions.md) page for more details on extension auto-loading.

`--extensions_timeout=3`

Seconds to wait for auto-loaded extensions to register.
osqueryd may depend on a config plugin from an extension. If the requested config plugin name is not registered within the timeout the daemon will exit with a failure.

`--extensions_interval=3`

Seconds delay between extension connectivity checks.
Extensions are loaded as processes. They are expected to start a thrift service thread. The osqueryd process will continue to check this API. If an extension process is incorrectly stopped, osqueryd will detect the connectivity failure and unregister the extension.

`--extensions_require=custom1,custom1`

Optional comma-delimited set of extension names to require before `osqueryi` or `osqueryd` will start. The tool will fail if the extension has not started according to the interval and timeout.

`--extensions_default_index=true`

Enable INDEX (and thereby constraints) on all extension table columns.  Provides backwards compatibility for extensions (or SDKs) that don't correctly define indexes in column options. See issue 6006 for more details.

## Remote settings flags (optional)

When using non-default [remote](../deployment/remote.md) plugins such as the **tls** config, logger and distributed plugins, there are process-wide settings applied to every plugin.

`--tls_hostname=`

When using **tls**-based config or logger plugins, a single TLS host URI is used. Using separate hosts for configuration and logging is not supported among the **tls**-based plugin suite. Provide a host name and optional port, e.g.: `facebook.com` or `facebook.com:443`.

`--tls_session_reuse=true`

Reuse TLS session sockets.

`--tls_session_timeout=3600`

Once a socket is created, the lifetime is governed by this flag. If this value is set to `0`, then transport never times out unless the remote end closes the connection or an error occurs.

`--tls_client_cert=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Optionally provide a path to a PEM-formatted client TLS certificate.

`--tls_client_key=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Optionally provide a path to a decrypted/password-less PEM-formatted client TLS private key.

`--tls_server_certs=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Optionally provide a path to a PEM-formatted server or authority certificate bundle. This path will be used as either an explicit set of accepted certificates or an OpenSSL-verify path directory of well-formed filename certificates.

`--disable_enrollment=false`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Remote plugins use an enrollment process to enable possible server-side implemented authentication and identification/authorization. Config and logger plugins implicitly require enrollment features. It is not recommended to disable enrollment and this option may be removed in the future.

`--enroll_secret_path=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. A very simple authentication/enrollment involves posting a deployment or staged shared secret. This secret should be protected on the host, but potentially shared among an enterprise or fleet. Provide a path for the osquery process to read and use during enrollment phases.

`--config_tls_endpoint=`

The **tls** endpoint path, e.g.: `/api/v1/config` when using the **tls** config plugin. See the other **tls_** related CLI flags.

`--config_tls_max_attempts=3`

The total number of attempts that will be made to the remote config server if a
request fails. If an attempt fails, it will be retried with exponential
backoff, up to the max number of attempts set.

`--logger_tls_endpoint=`

The **tls** endpoint path, e.g.: `/api/v1/logger` when using the **tls** logger plugin. See the other **tls_** related CLI flags.

`--enroll_tls_endpoint=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. An enrollment process will be used to allow server-side implemented authentication and identification/authorization. You must provide an endpoint relative to the `--tls_hostname` URI.

`--tls_enroll_max_attempts=12`

The total number of attempts that will be made to the remote enroll server if a request fails.
If an attempt fails, it will be retried up to the max number of attempts set, with exponential backoff limited by the flag `--tls_enroll_max_interval`.
If the flag is set to 0, the amount of attempts will be infinite.

`--tls_enroll_max_interval=600`

Maximum wait time in seconds between enroll retry attempts. This works in conjuction with `--tls_enroll_max_attempts`, and affects both the limited and the infinite attempts case.

`--logger_tls_period=3`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. This is a number of seconds before checking for buffered logs. Results are sent to the TLS endpoint in intervals, not on demand (unless the period=0).

`--logger_tls_compress=false`

Optionally enable GZIP compression for request bodies when sending. This is optional and disabled by default, as the deployment must explicitly know that the logging endpoint supports GZIP for content encoding.

`--logger_tls_max_linesize=1048576`

It is common for TLS/HTTPS servers to enforce a maximum request body size. The default behavior in osquery is to enforce each log line be under 1MB (`1048576` bytes). This means each result line from a query's results cannot exceed 1M, this is very unlikely. Each log attempt will try to forward up to 1024 lines. If your service is limited request bodies, configure the client to limit the log line size.

Use this only in emergency situations as size violations are dropped. It is extremely uncommon for this to occur, as the `--value_max` for each column would need to be drastically larger, or the offending table would have to implement several hundred columns.

`--logger_tls_max_lines=1024`

This configures the max number of log lines to send every period (meaning every `logger_tls_period`).

`--distributed_tls_read_endpoint=`

The URI path which will be used, in conjunction with `--tls_hostname`, to create the remote URI for retrieving distributed queries when using the **tls** distributed plugin.

`--distributed_tls_write_endpoint=`

The URI path which will be used, in conjunction with `--tls_hostname`, to create the remote URI for submitting the results of distributed queries when using the **tls** distributed plugin.

`--distributed_tls_max_attempts=3`

The total number of attempts that will be made to the remote distributed query server if a request fails when using the **tls** distributed plugin.

## Daemon runtime control flags

`--schedule_splay_percent=10`

Percent to splay config times.
The query schedule often includes several queries with the same interval.
It is often not the intention of the schedule author to run these queries together at that interval. But rather, each query should run at about the interval. A default schedule splay of 10% is applied to each query when the configuration is loaded.

`--schedule_max_drift=60`

Max time drift in seconds.
The scheduler tries to compensate the splay drift until the delta exceeds this value.
If the max drift is exceeded the splay will be reset to zero and the compensation process will start from the beginning.
This is needed to avoid the problem of endless compensation (which is CPU greedy) after a long SIGSTOP/SIGCONT pause or something similar. Set it to zero to disable drift compensation.

`--pack_refresh_interval=3600`

Query Packs may optionally include one or more discovery queries, which allow you to use osquery queries to manage which packs should be loaded at runtime. osquery will natively re-run the discovery queries from time to time, to make sure that all of the correct packs are executing. This flag allows you to specify that interval.

`--pack_delimiter=_`

Control the delimiter between pack name and pack query names. When queries are added to the daemon's schedule they inherit the name of the pack. A query named `info` within the `general_info` pack will become `pack_general_info_info`. Changing the delimiter to "/" turned the scheduled name into: `pack/general_info/info`.

`--disable_caching=false`

"Caching" refers to short cutting the table implementation and returning the same results from the previous query against the table. This is not related to differential results from scheduled queries, but does affect the performance of the schedule. Results are cached when different scheduled queries in a schedule use the same table, without providing query constraints. Caching should NOT affect data freshness since the cache life is determined as the minimum interval of all queries against a table.

`--schedule_default_interval=3600`

Optionally set the default interval value. This is used if you schedule a query which does not define an interval.

`--schedule_timeout=0`

Limit the schedule. Use `0` for no limit. Optionally limit the `osqueryd`'s life by adding a schedule limit in seconds. This should only be used for testing.

`--disable_tables=table_name1,table_name2`

Comma-delimited list of table names to be disabled. This allows osquery to be launched without certain tables.

`--read_max=52428800` (50 MB)

Maximum file read size. The daemon or shell will first 'stat' each file before reading. If the reported size is greater than `read_max` a "file too large" error will be returned.

## Events control flags

`--disable_events=false`

Disable or enable osquery Operating System [eventing publish-subscribe](../development/pubsub-framework.md) APIs. Setting this to `true` (which is the default value) disables tables that report evented data (tables whose names end with `_events`) and querying them will generate a warning.

`--events_expiry=3600`

Expiration age for evented data (in seconds), applied once the data is queried. Until an evented table is queried, its collected events are cached in backing-store. *Events are only expired (i.e., removed from the table) when the evented table is queried.* For example, if `--events_expiry=1`, then events older than 1 second will only appear in the next `SELECT` from the subscriber. If no `SELECT` occurs, those events will be saved in the backing store *indefinitely* or until the `events_max` limit is reached (see below). If, on the other hand, the table contains recent events that have not yet reached expiration age, the same table can be queried repeatedly in quick succession and the same data will continue to be present unless it had reached the expiration age when it was last queried, at which point it will be removed. `3600` seconds is the default, but if querying on an interval shorter than `3600`, you may wish to lower this value to avoid retrieving duplicate events.

`--events_optimize=true`

Since event rows are only "added" it does not make sense to emit "removed" results. An optimization can occur within the osquery daemon's query schedule. Every time the `SELECT` query runs on a subscriber, the current time is saved. Subsequent `SELECT`s will use the previously saved time as the lower bound. This optimization is removed if any constraints on the "time" column are included.

`--events_max=50000`

Maximum number of events to buffer in the backing store while waiting for a query to "drain" them (if and only if the events are old enough to be expired out, see above). For example, the default value indicates that a maximum of the `50000` most recent events will be stored. The right value for *your* osquery deployment, if you want to avoid missed/dropped events, should be considered based on the combination of your host's event occurrence frequency and the interval of your scheduled queries of those tables.

`--events_enforce_denylist=false`

This controls whether watchdog denylisting is enforced on queries using "*_events" (event-based) tables. As these these queries operate on meta-generated table logic, performance issues are unavoidable. It does not make sense to denylist. Enforcing this may lead to adverse and opposite effects because events will buffer longer and impact RocksDB storage.

This only considers queries that are entirely event-based. For example `SELECT * FROM process_events` is considered, but `SELECT * FROM process_events join time` is not.

It is not recommended to set this to `true`.

### Windows-only events control flags

`--enable_ntfs_event_publisher           Enables the NTFS event publisher`

`--enable_powershell_events_subscriber   Enables Powershell events`

`--enable_windows_events_publisher       Enables the Windows events publisher`

`--enable_windows_events_subscriber      Enables Windows Event Log events`

On Windows, in addition to the `--disable_events=false` flag mentioned above, each category of evented data must also be enabled individually, by enabling the corresponding osquery publisher and osquery subscriber. By default, all are disabled, and the corresponding evented tables will be empty. Note that an event publisher within osquery subscribes to events *from the OS* and then publishes them to an osquery event subscriber. For the current complete list of event sources usable by osquery, see `osqueryi.exe --help | findstr -i Event`.

`--windows_event_channels=System,Application,Setup,Security`

List of Windows Event Log channels for osquery to subscribe to. By default, osquery's Windows Event Log publisher will deliver some of the more common major event log channels. However, you can select additional channels using the `Log Name` field value in the Windows event viewer. Note the lack of quotes around the channel names. For example, to subscribe to Windows PowerShell script block logging, one would first enable the feature in Windows itself, and then subscribe to the channel with `--windows_event_channels=Microsoft-Windows-PowerShell/Operational`

### Linux-only events control flags

`--hardware_disabled_types=partition`

This is a comma-separated list of UDEV types to drop. On machines with flash-backed storage it is likely you'll encounter lots of noise from `disk` and `partition` types.

### macOS-only events control flags

`--disable_endpointsecurity=true`

Setting to `false` (in combination with `--disable_events=false`) turns on EndpointSecurity-based event collection within osquery (supported in macOS 10.15 and newer), and enables the use of the `process_events_es` table. This feature requires running osquery as root. It also requires that the osquery executable be code-signed and notarized to have the Endpoint Security client entitlement; official release builds of osquery will be appropriately code-signed. Lastly, it requires that the host give Full Disk Access permission to the osqueryd executable; for more information see the [process auditing section of osquery's deployment documentation](../deployment/process-auditing.md) as well as [installing osquery on macOS](./install-macos.md).

## Logging/results flags

`--logger_plugin=filesystem`

Logger plugin name. The default logger is **filesystem**. This writes the various log types as JSON to specific file paths.

Multiple logger plugins may be used simultaneously, effectively copying logs to each interface. Separate plugin names with a comma when specifying the configuration (`--logger_plugin=filesystem,syslog`).

Built-in options include: **filesystem**, **tls**, **syslog**, and several Amazon/AWS options.

`--disable_logging=false`

Disable `ERROR`/`WARNING`/`INFO` (a.k.a. status logs) and query result [logging](../deployment/logging.md).

`--logger_event_type=true`

Log scheduled results as events.

`--logger_snapshot_event_type=false`

Log scheduled snapshot results as events, similar to differential results. If this is set to `true` then each row from a snapshot query will be logged individually.

`--logger_min_status=0`

The minimum level for status log recording. Use the following values: `INFO = 0, WARNING = 1, ERROR = 2`. To disable all status messages use `3` or higher. When using `--verbose`, this value is ignored.

`--logger_min_stderr=0`

The minimum level for status logs written to stderr. Use the following values: `INFO = 0, WARNING = 1, ERROR = 2`. To disable all status messages use `3` or higher. It does **not** limit or control the types sent to the logger plugin. When using `--verbose` this value is ignored.

`--logger_stderr=true`

The default behavior is to also write status logs to stderr. Set this flag to false to disable writing (copying) status logs to stderr. In this case `--verbose` is respected.

`--logger_path=/var/log/osquery/`

Directory path for `ERROR`/`WARN`/`INFO` and query result logging by the **filesystem** plugin.

`--logger_mode=420`

File mode for output log files by the **filesystem** plugin (provided as an octal string). Note that this affects both the query result log and the status logs. **Warning**: If run as root, log files may contain sensitive information!

`--logger_rotate=false`

When enabled, the **filesystem** plugin will rotate logs based on size. An example includes `/var/log/osquery/osqueryd.results.log` being rotated to `/var/log/osquery/osqueryd.results.log.1` when the trigger size is reached. Files after the first rotation will be Zstandard-compressed and will use the `.zst` file extension. A max number of log files will be maintained and logs overflowing this count will be deleted after rotation.

`--logger_rotate_size=26214400` (25MB)

A size, specified in bytes, to trigger rotation when enabled with `--logger_rotate`. A result or snapshot log will be rotated when it grows past this size. The size is checked before each new write to the logfile.

`--logger_rotate_max_files=25`

The max number of result and snapshot rotation files. The count applies to each individually, meaning by default osquery will maintain 25 results files and 25 snapshot files. If a rotation happens after hitting this max, the oldest file will be removed.

`--logger_syslog_facility`

Set the syslog facility (number) `0`-`23` for the results log by the **syslog** plugin. When using the **syslog** logger plugin, the default facility is `19` at the `LOG_INFO` level, which does not log to `/var/log/system`.

`--logger_syslog_prepend_cee`

Prepend a `@cee:` cookie to JSON-formatted messages sent to the **syslog** logger plugin. Several syslog parsers use this cookie to indicate that the message payload is parseable JSON. The default value is false.

`--logger_kafka_brokers`

A comma-delimited list of Kafka brokers to connect to.  Format can be `protocol://host:port`, `host:port` or just `host` with the port number falling back to the default value of `9092`.  `protocol` can be `plaintext` (default) or `ssl`.  When protocol is `ssl`, `--tls_server_certs` value is used as certificate trust store.  Optionally `--tls_client_cert` and `--tls_client_key` can be provided for TLS client authentication with Kafka brokers.

`--logger_kafka_topic`

The Kafka topic to publish logs to.  When using multiple topics this configuration becomes the base topic that unconfigured queries fall back to. Please see the Kafka section of the [logging wiki](../deployment/logging.md) for more details.

`--logger_kafka_acks`

The number of acknowledgments the Kafka leader has to receive before a publish is considered successful. Valid options are (0, 1, "all").

`--logger_kafka_compression`

Compression codec to use for compressing message sets. Valid options are ("none", "gzip").  Default is "none".

`--buffered_log_max=1000000`

There are multiple logger plugins that use a "buffered logging" implementation. The TLS and AWS loggers use this approach. This flag sets the maximum number of logs to buffer before dropping new logs. If the buffered logs have not been shuttled to the logger destination they will be purged in order of their timestamp. The oldest logs are purged first.

Setting this to value to `0` means unlimited logs will be buffered.

`--host_identifier=hostname`

Field used to identify the host running osquery: `hostname`, `uuid`, `ephemeral`, `instance`, `specified`.

DHCP may assign variable hostnames, if this is the case, you may need a consistent logging label. Four options are available to you:

- `uuid` uses the platform (DMTF) host UUID, fetched at process start.
- `instance` uses an instance-unique UUID generated at process start, persisted in the backing store.
- `ephemeral` uses an instance-unique UUID generated at process start, not persisted.
- `specified` uses an ID provided by the `--specified_identifier` flag.

`--specified_identifier=this.is.the.identifier`

If `--host_identifier=specified` is set, use this value as the host identifier.

`--verbose=false`

Enable verbose informational messages.

`--thrift_verbose=false`

Enable thrift global output.

`--value_max=512`

Maximum returned row value size.

## Distributed query service flags

`--distributed_plugin=tls`

Distributed plugin name. The default distributed plugin is not set. You must set `--disable_distributed=false --distributed_plugin=tls` (or whatever plugin you'd rather use instead of TLS) to enable the distributed feature.

`--disable_distributed=true`

Disable distributed queries functionality. By default, this is set to `true` (the distributed feature is disabled). Set this to `false` to enable distributed queries.

`--distributed_interval=60`

In seconds, the amount of time that osqueryd will wait between periodically checking in with a distributed query server to see if there are any queries to execute.

## Syslog consumption flags

There is a `syslog` virtual table that uses Events and a **rsyslog** configuration to capture results *from* syslog. Please see the [Syslog Consumption](../deployment/syslog.md) deployment page for more information.

`--enable_syslog=false`

Turn on the syslog ingestion event publisher. This is an 'explicit'-enable because it requires external configuration of **rsyslog**.

`--syslog_pipe_path=/var/osquery/syslog_pipe`

Path to the named pipe used for forwarding **rsyslog** events.

`--syslog_rate_limit=100`

Maximum number of logs to ingest per run (~200ms between runs). Use this as a fail-safe to prevent osquery from becoming overloaded when syslog is spammed.

## Augeas flags

`--augeas_lenses=/usr/share/osquery/lenses`

Augeas lenses are bundled with osquery distributions. On Linux they are installed in `/usr/share/osquery/lenses`. On macOS, lenses are installed in the `/private/var/osquery/lenses` directory. Specify the path to the directory containing custom or different version lenses files.

## Docker flags

`--docker_socket=/var/run/docker.sock`

Docker information for containers, networks, volumes, images etc is available in different tables. osquery uses docker's UNIX domain socket to invoke docker API calls. Provide the path to Docker's domain socket file. User running `osqueryd` / `osqueryi` should have permission to read the socket file.

## Shell-only flags

Most of the shell flags are self-explanatory and are adapted from the SQLite shell. Refer to the shell's `.help` command for details and explanations.

There are several flags that control the shell's output format: `--json`, `--list`, `--line`, `--csv`. For all of the output types there is `--nullvalue` and `--separator` that can be used appropriately.

`--planner=false`

When prototyping new queries, the planner enables verbose decisions made by the SQLite virtual table API. This is customized by osquery code so it is very helpful to learn what predicate constraints are selected and what full-table scans are required for `JOIN` and nested queries.

`--header=true`

Set this value to `false` to disable column name (header) output. If using the shell in an automation or script the header line in `line` or `csv` mode may not be needed.

## Numeric monitoring flags

`--enable_numeric_monitoring=false`

Enable numeric monitoring system. By default it is disabled.

`--numeric_monitoring_plugins=filesystem`

Comma-separated numeric monitoring plugins. By default there is only one: `filesystem`.

`--numeric_monitoring_pre_aggregation_time=60`

Time period in _seconds_ for numeric monitoring pre-aggregation buffer. During this period of time, monitoring points will be pre-aggregated and accumulated in a buffer. At the end of this period, the aggregated points will be flushed to `--numeric_monitoring_plugins`. `0` means to work without a buffer at all. For most monitoring data, some aggregation will be applied on the user side. In these cases, particular points don't mean much. To reduce disk usage and network traffic, some pre-aggregation is applied on the osquery side.

`--numeric_monitoring_filesystem_path=OSQUERY_LOG_HOME/numeric_monitoring.log`

File to dump numeric monitoring records one per line. The format of the line is `<PATH><TAB><VALUE><TAB><TIMESTAMP>`. File will be opened in append mode.

## Enable and Disable flags

`--disable_tables=table1,table2`

Comma separated list of tables to disable. By default no tables are disabled.

`--enable_tables=table1,table2`

Comma separated list of tables to enable. By default every table is enabled. If a specific table is set in both `--enable_tables` and `--disable_tables`, disabling take precedence. If `--enable_tables` is defined and `--disable_tables` is not set, every table but the one defined in `--enable_tables` become disabled.
