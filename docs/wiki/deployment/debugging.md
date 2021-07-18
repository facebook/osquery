# Debugging osquery

Here are some debugging tips and tricks related to the daemon and shell from a deployment and usage perspective. Please see the development documentation in the next section for debugging code changes.

Almost every situation requiring debugging should ultimately be solved with bug fixes or better documentation. In these cases, the documentation usually surfaces in the form of verbose messages in the tools.

Please feel encouraged to add additional messages in the code, or create GitHub issues documenting your experience and suggestions for documentation or code improvements.

## Running the shell or daemon in verbose mode

This is pretty simple! Just append `--verbose` as a switch.

```shell
$ osqueryi --verbose
I0412 08:04:56.012428 3056837568 init.cpp:380] osquery initialized [version=2.4.0]
I0412 08:04:56.014837 168243200 interface.cpp:317] Extension manager service starting: /Users/$USER/.osquery/shell.em
I0412 08:04:56.015383 3056837568 init.cpp:615] Error reading config: config file does not exist: /var/osquery/osquery.conf
Using a virtual database. Need help, type '.help'
osquery>
```

To see the daemon's verbose messages you'll need to run it in the foreground, see the next section. Be aware that verbose messages are treated like others and sent to your downstream logger plugin. If you are collecting these logs, the verbose messages will be collected too!

## Running the daemon in the foreground

The daemon has some restrictions that make verbose debugging difficult, let's walk through how to run it in the foreground.

```shell
osqueryd --ephemeral --disable_database --disable_logging
```

The `ephemeral` flag tells the daemon that it may co-exist with other persistent daemons. The `disable_database` must be present or `database_path` must be overridden as the default database location is not writable/readable by a non-privileged user. The same applies for `disable_logging`, and if you use the default logger plugin `filesystem` then alternatively `--logger_path` may be overridden. Now we can append `--verbose`:

```shell
$ osqueryd --ephemeral --disable_database --disable_logging --verbose
I0412 08:03:59.664191 3056837568 init.cpp:380] osquery initialized [version=2.4.0]
I0412 08:03:59.666533 196194304 watcher.cpp:465] osqueryd watcher (35549) executing worker (35550)
I0412 08:03:59.688765 3056837568 init.cpp:377] osquery worker initialized [watcher=35549]
I0412 08:03:59.690062 3056837568 rocksdb.cpp:205] Opening RocksDB handle: /tmp/osquery.db
```

Also note the daemon expects to be owned by the superuser if executed as the superuser. It also resists running in a tmpfs or sticky-bit directory. For special testing and debugging cases use `--allow_unsafe`.

If you are using a `--flagfile` to define additional command line switches then it should be readable by your user. In cases where the Remote API is used, an enroll secret or TLS client private key is needed. If these are read-restricted to the superuser you may need to also debug as the superuser.

## Checking the config sanity

The daemon will not start with an invalid configuration. And no configuration is provided by default. See the [configuration](../deployment/configuration.md) guide for details on how to move the example config to an active config.

To check your configuration with the shell (or daemon):

```shell
$ osqueryi --config_path ./build/testing/invalid_osquery.conf --config_check || echo 'config has an error'
Error reading config: Error parsing the config JSON
config has an error
```

This works for all the configuration plugins.

You can print/dump the config using `--config_dump` to be double-extra sure:

```shell
osqueryi --config_path ./build/testing/invalid_osquery.conf --config_dump
{"./build/testing/osquery.conf": /* I PUT THIS JSON ERROR HERE, NOOOOO! */
{
 "packs": {}
}
```

The daemon and shell should exit after printing the config.

This example contains a C-style comment which was allowed in boost 1.58, but is deprecated and removed in 1.59. To be future-proof, stick to the JSON specification and do not include comments.

### Scheduled query failures and the watchdog

The osquery watchdog is only used in the daemon. It is enabled by default and can be disabled with `--disable_watchdog=true`. The watchdog enforces limits on a forked 'worker' process to protect systems from CPU expensive and memory-intensive queries. If the watchdog observes limit violations it will emit errors similar to:

```text
Scheduled query may have failed: pack_threat_detectors_launch_daemons
```

This line is created when a worker starts and finds a 'dirty bit' toggled for the currently-executing-query. If a daemon is stopped abruptly and a query does not finish, a similar line may be emitted spuriously.

Lines that indicate the watchdog has taken action include either of the following:

```text
osqueryd worker (92234) system performance limits exceeded
osqueryd worker (8368) memory limits exceeded: 99573760
```

The pid of the offending worker is included in parenthesis.

If the worker finds itself in a re-occurring error state or the watchdog continues to stop the worker, additional lines like the following are created:

```text
osqueryd worker respawning too quickly: 1 times
```

The watchdog implements an exponential backoff when respawning workers and the associated 'dirty' query is denylisted from running for 24 hours.

### Inspecting daemon state using the shell

The `osqueryi` shell can "connect" to another osquery extension socket. Queries within that shell will be forwarded to the remote socket. This feature is especially helpful to inspect a daemon's `osquery_schedule` and `osquery_flags` configuration. The `osquery_schedule` table maintains runtime statistics for schedule execution. Keep in mind that this runtime data is transient, and only available to a daemon.

Please consider the following example that demonstrates this functionality:

```shell
$ osqueryi
osquery> .socket
/home/$USER/.osquery/shell.em
osquery> select pid from osquery_info;
+------+
| pid  |
+------+
| 1533 |
+------+
osquery>
```

Then in another shell, the `.connect` method is used:

```shell
osquery> select pid from osquery_info;
+-------+
| pid   |
+-------+
| 20123 |
+-------+
osquery> .connect /home/$USER/.osquery/shell.em
[*]osquery> select pid from osquery_info;
+------+
| pid  |
+------+
| 1533 |
+------+
[*]osquery>
```

### Checking the database sanity

The osquery backing store is almost always RocksDB. This is built-in to osquery when using [our packages](https://osquery.io/downloads). Most errors with RocksDB are caused by read and write permissions on the `--database_path` and spurious processes wanting to lock access to that directory.

The database path can only be used by a **single** daemon, concurrency is implemented at the API level, not the process level.

```shell
$ ps aux | grep osquery
# pgrep osquery
```

If osquery daemons or shells are using the database path wanted by a daemon you're attempting to start, it will fail and exit non-0. There is one unfortunate caveat introduced by the lock, consider the following flow:

```shell
$ sudo osqueryctl start
$ sudo osqueryctl config-check
E0118 17:10:09.520731 1913696256 init.cpp:421] [Ref #1629] osqueryd initialize failed: Could not open RocksDB
$ sudo osqueryctl status
com.osquery.osqueryd is running. pid: 81943
$ sudo osqueryctl stop
$ sudo osqueryctl config-check || echo 'config has an error'
```

The first `config-check` fails because it attempts to verify the sanity of the RocksDB directory while a daemon is running. The second attempt succeeds and should be the actual indicator!

While not expected, the backing store may be corrupted by problems with the filesystem, incorrect shutdowns, or running out of disk space. If any corruption is detect via the startup sanity checks or during runtime osquery may backup the database and attempt a recovery. The most basic recovery is just to move the database content to the backup location and start 'fresh'.

If your `--database_path` is `/var/osquery/osquery.db` then the backup is `/var/osquery/osquery.db.backup`. The database is always a folder and the backup location is the suffix ".backup" appended.

### Inspecting TLS/HTTPS body request and responses

When using the TLS-related plugins the hidden flag `--tls_dump` can be used with `--verbose`. This flag will print all of the HTTPS body content (usually JSON data) to `stderr`.

### Using event publishers and tables in the shell

Remember! The `osqueryi` shell and the `osqueryd` daemon do not communicate. The daemon is intended to be run as a privileged process and the shell may be run by any user. The daemon is intended to subscribe to operating system events that require non-default configurations and impose potential performance concerns. That said, the shell can mimic this behavior for testing and debugging.

If you try to select from an events-based table in the shell you will see something similar to the following warning:

```
osquery> select * from file_events;
virtual_table.cpp:542] Table file_events is event-based but events are disabled
virtual_table.cpp:549] Please see the table documentation: https://osquery.io/schema/current/#file_events
```

If you start the shell using `osqueryi --disable_events=0` you will no longer get this warning. BUT! It is most likely the case that the events you are trying to inspect require future configuration. `file_events` requires a [file integrity monitoring](file-integrity-monitoring.md) configurations, `process_events` requires either additional flags or OpenBSM configuration, these situations are described in [process auditing](process-auditing.md).

On Linux and macOS the `hardware_events` table is enabled for-free, so try to plug in a USB and run `select * from hardware_events`.

### Testing event subscribers

Each event subscriber, tables that end with `_events`, includes a `HIDDEN` column called `eid`. This is an internal incrementing ID assigned by osquery to every event row added to a subscriber table. Each table maintains its own counter. The `eid` can be used to check for drops and duplicates occurring via an optimization or indexing bug.

Consider the query:

```sql
SELECT *, eid FROM file_events;
```

If this query is in your schedule then the first `eid` should be `000000001` or similar. Each time the query runs the following should hold: `count(0) == max(eid) - min(eid)` and `min(eid) + 1 == max(eid from last run)`.

### Table exception handling

The osquery virtual table code will catch and log (then ignore) any exceptions in table implementations. You may see a log line similar to the following:

```text
Exception while executing table TABLE_NAME: EXCEPTION_MESSAGE
```

If you would like to debug the exception and view the stacktrace you may disable the exception catching with the `--table_exceptions` flag.
