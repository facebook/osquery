# Configuring an osquery deployment

An osquery deployment consists of:

* Installing the tools for [Windows](../installation/install-windows.md), [macOS](../installation/install-macos.md), or [Linux](../installation/install-linux.md)
* Reviewing the [osqueryd](../introduction/using-osqueryd.md) introduction
* Configuring and starting the `osqueryd` service (this page)
* Managing and [collecting](log-aggregation.md) the query results

## Configuration components

The osquery "configuration" is read from a config plugin. This plugin is a data
retrieval method and is set to **filesystem** by default.  Other retrieval and
run-time updating methods may include an HTTP/TLS request using the **tls**
config plugin. In all cases the response data must be JSON-formatted.

There are several components contributing to a configuration:

* Daemon options and feature settings
* Query Schedule: the set of SQL queries and intervals
* File Change Monitoring: categories and paths of monitored files and directories
* (insert new feature that requires a configuration here!)

There are also "initialization" parameters that control how `osqueryd` is
launched.  These parameters only make sense as command-line arguments since
they are used before a configuration plugin is selected. See the [command line
flags](../installation/cli-flags.md) overview for a complete list of these
parameters.

The default config plugin, **filesystem**, reads from a file and optional
directory ".d" based on the filename. The included initscripts set the default
config path as follows:

* Windows: **C:\Program Files\osquery\osquery.conf**
* Linux: **/etc/osquery/osquery.conf** and **/etc/osquery/osquery.conf.d/**
* macOS: **/var/osquery/osquery.conf** and **/var/osquery/osquery.conf.d/**

You may override the **filesystem** plugin's path using
`--config_path=/path/to/osquery.conf`. You may also use the ".d/" directory
search path based on that custom location.

Here is an example config that includes options and the query schedule:

```json
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "macos_kextstat": {
      "query": "SELECT * FROM kernel_extensions;",
      "interval": 10
    },
    "foobar": {
      "query": "SELECT foo, bar, pid FROM foobar_table;",
      "interval": 600
    }
  }
}
```

This config tells osqueryd to schedule two queries, **macos_kextstat** and
**foobar**:

* the schedule keys must be unique
* the `interval` specifies query frequency, in seconds. It has a
  maximum value of 604,800 (1 week)

The first query will log changes to the macOS host's kernel extensions,
with a query interval of 10 seconds. Consider using osquery's [performance
tooling](performance-safety.md) to understand the performance impact for each
query.

The results of your query are cached on disk using
[RocksDB](https://rocksdb.org). On the first query run, all of the results are
stored in RocksDB. On subsequent runs, only result-set-difference (changes) are logged to RocksDB.

Scheduled queries can also set: `"removed":false` and `"snapshot":true`. See
the next section on [logging](../deployment/logging.md), and the below configuration specification to learn how query options affect the output.

> NOTICE: that the `interval` time in seconds is how many seconds the _daemon_
itself has been running before the scheduled query will be executed. If the
system is suspended or put to sleep the progression of time "freezes" and
resumes when the system comes back online. For example a scheduled query with
an interval of `84600`, or 24 hours, running on a laptop system could take
a few days before the query executes if the system is suspended at night.

## Query Packs

Configuration supports sets, called packs, of queries that help define your
schedule. Packs are distributed with osquery and labeled based on broad
categories of information and visibility. For example, a "compliance" pack will
include queries that check for changes in locked down operating system features
and user settings. A "vulnerability management" pack may perform general asset
management queries that build event logs around package and software install
changes.

In an osquery configuration JSON, packs are defined as a top-level-key and
consist of pack name to pack content JSON data structures.

```json
{
  "schedule": {...},
  "packs": {
    "internal_stuff": {
      "discovery": [
        "SELECT pid FROM processes WHERE name = 'ldap';"
      ],
      "platform": "linux",
      "version": "1.5.2",
      "queries": {
        "active_directory": {
          "query": "SELECT * FROM ad_config;",
          "interval": "1200",
          "description": "Check each user's active directory cached settings."
        }
      }
    },
    "testing": {
      "shard": "10",
      "queries": {
        "suid_bins": {
          "query": "SELECT * FROM suid_bins;",
          "interval": "3600"
        }
      }
    }
  }
}
```

The pack value may also be a string, such as:

```json
{
  "packs": {
    "external_pack": "/path/to/external_pack.conf",
    "internal_stuff": {
      [...]
    }
  }
}
```

If using a string instead of an inline JSON dictionary the configuration plugin will be asked to "generate" that resource. In the case of the default **filesystem** plugin, these strings are considered paths.

The **filesystem** plugin supports another convention for adding a directory of packs:

```json
{
  "packs": {
    "*": "/path/to/*",
  }
}
```

Here the name `*` asks the plugin to *glob* the value and construct a multi-pack. The name of each pack will correspond to the filename *leaf* without the final extension, e.g. `/path/to/external_pack.conf` will be named `external_pack`.

Queries added to the schedule from packs inherit the pack name as part of the scheduled query name identifier. For example, consider the embedded `active_directory` query above, it is in the `internal_stuff` pack so the scheduled query name becomes: `pack_internal_stuff_active_directory`. The delimiter can be changed using the `--pack_delimiter=_`, see the [CLI Options](../installation/cli-flags.md) for more details.

### Discovery queries

Discovery queries are a feature of query packs that make it much easier to monitor services at scale. Consider that there are some groups of scheduled
queries which should only be run on a host when a condition is true. For
example, perhaps you want to write some queries to monitor MySQL. You've made a
pack called "mysql" and now you only want the queries in that pack to execute
if the `mysqld` program is running on the host.

Without discovery queries, you could have your configuration management write a
different configuration file for your MySQL tier. Unfortunately, however, this
requires you to know the complete set of hosts in your environment which are
running MySQL. This is problematic, especially if engineers in your environment
can install arbitrary software on arbitrary hosts. If MySQL is installed on a
non-standard host, you have no way to know. Therefore, you cannot schedule your MySQL pack on those hosts through configuration management logic.

One solution to this problem is discovery queries.

Query packs allow you to define a set of osquery queries which control whether
or not the pack will execute. Discovery queries are represented by the
top-level "discovery" key-word in a pack. The value should be a list of osquery
queries. If all of the queries return more than zero rows, then the queries are
added to the query schedule. This allows you to distribute configurations for
many services and programs, while ensuring that only relevant queries will be
executing on your host.

You don't need to define any discovery queries for a pack. If no discovery
queries are defined, then the pack will always execute.

Discovery queries look like:

```json
{
  "discovery": [
    "SELECT pid FROM processes WHERE name = 'foobar';",
    "SELECT 1 FROM users WHERE username like 'www%';"
  ],
  "queries": {}
}
```

In the above example, the pack will only execute on hosts which are running
processes called "foobar" and has users that start with "www".

Discovery queries are refreshed for all packs every 60 minutes. You can
change this value via the `pack_refresh_interval` configuration option.

Finally, if you have multiple discovery queries they will short-circuit
(stop after the first query with no results). This is useful if you are selecting
from a table provided by an extension because you can verify it is loaded before
running further queries.

### Packs FAQs

**Where do packs go?**

The default way to define a query pack is in the main configuration file.
Consider the following example:

```json
{
  "packs": {
    "foo": {
      "queries": {}
    },
    "bar": {
      "queries": {}
    }
  }
}
```

Alternatively, however, you can also define the value of a pack as a raw
string. Consider the following example:

```json
{
  "packs": {
    "foo": "/tmp/foo.json",
    "bar": "/tmp/bar.json"
  }
}
```

In the above example, the packs are defined using a local filesystem path.
When osquery's config parser is provided a string instead of inline dictionary the active config plugin is called to resolve what should be done to go from `/tmp/foo.json` to the actual content of the pack. See [configuration plugin](../development/config-plugins.md) development for more information on packs.

**Where can I get more packs?**

We release (and bundle alongside RPMs/DEBs/PKGs/etc.) query packs that emit high signal events as well as event data that is worth storing in the case of future incidents and security events. The queries within each pack will be performance tested and well-formed (JOIN, select-limited, etc.). But it is always an exercise for the user to make sure queries are useful and are not impacting performance critical hosts. You can find the query packs that are released by the osquery team in [**/packs**](https://github.com/osquery/osquery/blob/master/packs) within the osquery repository.

**How do I modify the default options in the provided packs?**

We don't offer a built-in way to modify the default intervals / options in the
supplied query packs. Fortunately, however, packs are just JSON. Therefore, it
would be rather trivial to write a tool which reads in pack JSON, modifies it
in some way, then re-writes the JSON.

## Configuration specification

This section details all (read: most) of the default configuration keys, called the default specification. We mention 'default' as the configuration can be extended using `ConfigParser` plugins.

### Options

The `options` key defines a map of option name to option value pairs. The names must be a CLI flag in the "osquery configuration options" set; running `osqueryd --help` will enumerate the list.

Example:

```json
{
  "options": {
    "read_max": 100000,
    "events_max": 100000,
    "host_identifier": "uuid"
  }
}
```

If a flag value is specified on the CLI as a switch, or specified in the Gflags `--flagfile` file it will be overridden if the equivalent "options" key exists in the config.

There are LOTs of CLI flags that CANNOT be set with the `options` key. These flags determine the start and initialization of osquery and configuration loading usually depends on these CLI-only flags. Refer to the `--help` list to determine the appropriateness of options.

It is possible to set "custom" options that do not exist as flags. These will not do anything without adding appropriate code. Options using the prefix `custom_` can be accessed via `osquery::Flag::updateValue("custom_NAME", value)` and `osquery::Flag::getValue("custom_NAME");`.

### Schedule

The `schedule` key defines a map of scheduled query names to the query details. You will see mention of the schedule throughout osquery's documentation. It is the focal point of osqueryd's capabilities.

Example:

```json
{
  "schedule": {
    "users_browser_plugins": {
      "query": "SELECT * FROM users JOIN browser_plugins USING (uid);",
      "interval": 60
    },
    "hashes_of_bin": {
      "query": "SELECT path, hash.sha256 FROM file JOIN hash USING (path) WHERE file.directory = '/bin/';",
      "interval": 3600,
      "removed": false,
      "platform": "darwin",
      "version": "1.4.5",
      "shard": 1
    }
  }
}
```

Each of `schedule`'s value's is also a map, we call these scheduled queries and their key is the `name` which shows up in your results log. In the example above the schedule includes two queries: **users_browser_plugins** and **hashes_of_bin**. While it is common to schedule a `SELECT * FROM your_favorite_table`, one of the powers of osquery is SQL expression and the combination of several table concepts please use `JOIN`s liberally.

The basic scheduled query specification includes:

- `query`: the SQL query to run
- `interval`: an interval in seconds to run the query (subject to splay/smoothing)
- `removed`: a boolean to determine if "removed" actions should be logged, default true
- `snapshot`: a boolean to set 'snapshot' mode, default false
- `platform`: restrict this query to a given platform, default is 'all' platforms; you may use commas to set multiple platforms
- `version`: only run on osquery versions greater than or equal-to this version string
- `shard`: restrict this query to a percentage (1-100) of target hosts
- `denylist`: a boolean to determine if this query may be denylisted (when stopped by the Watchdog for excessive resource consumption), default true

The `platform` key can be:

- `darwin` for macOS hosts
- `freebsd` for FreeBSD hosts
- `linux` for any RedHat or Debian-based hosts
- `posix` for `darwin`, `freebsd`, and `linux` hosts
- `windows` for any Windows desktop or server hosts
- `any` or `all` for all, alternatively no platform key selects all

The `shard` key works by hashing the hostname then taking the quotient 255 of the first byte. This allows us to select a deterministic 'preview' for the query, this helps when slow-rolling or testing new queries.

Note that queries are still constrained by the Watchdog when the `denylist` key is set to false. This means that setting `denylist` to false is _not_ sufficient to ensure a query will be run without resource constraints. Queries stopped by the Watchdog should be addressed by modifying the query SQL and/or Watchdog configuration until the limits are not exceeded.

The schedule and associated queries generate a timeline of events through the defined intervals. There are several tables `*_events` which natively yield a time series, all other tables are subjected to execution on an interval. When the results from a table differ from the results when the query was last executed, logs are emitted with `{"action": "removed"}` or `{"action": "added"}` for the appropriate action.

Snapshot queries, those with `snapshot: true` will not store differentials and will not emulate an event stream. Snapshots always return the entire results from the query on the given interval. See
the next section on [logging](../deployment/logging.md) for examples of each log output.

Queries may be "denylisted" if they cause osquery to use excessive system resources. A denylisted query returns to the schedule after a cool-down period of 1 day. Some queries may be very important and you may request that they continue to run even if they are latent. Set the `denylist: false` to prevent a query from being denylisted.

### Packs

The above section on packs almost covers all you need to know about query packs. The specification contains a few caveats since packs are designed for distribution. Packs use the `packs` key, a map where the key is a pack name and the value can be either a string or a dictionary (object). When a string is used the value is passed back into the config plugin and acts as a "resource" request.

```json
{
  "packs": {
    "pack_name_1": "/path/to/pack.json",
    "pack_name_2": {
      "queries": {},
      "shard": 10,
      "version": "1.7.0",
      "platform": "linux",
      "discovery": [
        "SELECT * FROM processes WHERE name = 'osqueryi';"
      ]
    }
  }
}
```

As with scheduled queries, described above, each pack borrows the `platform`, `version`, and `shard` selectors and restrictions. These work the exact same way, but apply to the entire pack. This is a short-hand for applying selectors and restrictions to large sets of queries.

The `queries` key mimics the configuration's `schedule` key.

The `discovery` query set feature is described in detail in the above packs section. This array should include queries to be executed in an `AND` manner.

### File Paths

The `file_paths` key defines a map of file integrity monitoring (FIM) categories to sets of filesystem globbing lines. Please refer to the [FIM](../deployment/file-integrity-monitoring.md) guide for details on how to use osquery as a FIM tool.

Example:

```json
{
  "file_paths": {
    "custom_category": [
      "/etc/**",
      "/tmp/.*"
    ],
    "device_nodes": [
      "/dev/*"
    ]
  },
  "file_accesses": [
    "custom_category"
  ]
}
```

The file paths set has a sister key: `file_accesses` which contains a set of categories names that opt-in for filesystem access monitoring.

### YARA

The `yara` key uses two subkeys to configure YARA signatures: `signatures`, and to define a mapping for signature sets to categories of `file_paths` defined in the "file paths" configuration. Please refer to the much more detailed [YARA](../deployment/yara.md) deployment guide.

Example:

```json
{
  "yara": {
    "signatures": {
      "signature_group_1": [
        "/path/to/signature.sig"
      ]
    },
    "file_paths": {
      "custom_category": [
        "signature_group_1"
      ]
    }
  }
}
```

There is a strict relationship between the top-level `file_paths` key, and `yara`'s equivalent subkey.

### Prometheus

The `prometheus_targets` key can be used to configure Prometheus targets to be queried. The metric timestamp of millisecond precision is taken when the target response is received.  The `prometheus_targets` parent key consists of a child key `urls`, which contains a list target urls to be scraped, and an optional child key `timeout` which contains the request timeout duration in seconds (defaults to 1 second if not provided).

Example:

```json
{
  "prometheus_targets": {
    "timeout": 5,
    "urls": [
      "http://localhost:9100/metrics",
      "http://localhost:9101/metrics"
    ]
  }
}
```

### Views

Views are saved queries expressed as tables. Large subqueries or complex joining logic can often be moved into views allowing you to make your queries more concise.

Example:

```json
{
  "views": {
    "kernel_hashes" : "SELECT hash.path AS kernel_binary, version, hash.sha256 AS sha256, hash.sha1 AS sha1, hash.md5 AS md5 FROM (SELECT path || '/Contents/MacOS/' AS directory, name, version FROM kernel_extensions) JOIN hash USING (directory);"
  }
}
```

```SQL
SELECT * FROM kernel_hashes WHERE kernel_binary NOT LIKE "%apple%";
```

### EC2

There are two tables that provide EC2 instance related information. On non-EC2 instances these tables return empty results. `ec2_instance_metadata` table contains instance meta data information. `ec2_instance_tags` returns tags for the EC2 instance osquery is running on. Retrieving tags for EC2 instance requires authentication and appropriate permission. There are multiple ways credentials can be provided to osquery. See [AWS logging configuration](../deployment/aws-logging.md#configuration) for configuring credentials. AWS region (`--aws_region`) argument is not required and will be ignored by `ec2_instance_tags` implementation. The credentials configured should have permission to perform `ec2:DescribeTags` action.

### Azure

Like EC2, there are two tables that provide Azure instance related information. These tables query a REST endpoint that may or may not exist outside of Azure, so querying them outside of Azure is not recommended. The `azure_instance_metadata` table contains general metadata for the instance. The `azure_instance_tags` table contains tags for the Azure instance that osquery is running on. These tables don't require any special Azure permissions or credentials.

### Decorator queries

Decorator queries exist in osquery versions 1.7.3+ and are used to add additional "decorations" to results and snapshot logs. There are three types of decorator queries based on when and how you want the decoration data.

```json
{
  "decorators": {
    "load": [
      "SELECT version FROM osquery_info;",
      "SELECT uuid AS host_uuid FROM system_info;"
    ],
    "always": [
      "SELECT user AS username FROM logged_in_users WHERE user <> '' ORDER BY time LIMIT 1;"
    ],
    "interval": {
      "3600": [
        "SELECT total_seconds AS uptime FROM uptime;"
      ]
    }
  }
}
```

The types of decorators are:

* `load`: run these decorators when the configuration loads (or is reloaded)
* `always`: run these decorators before each query in the schedule
* `interval`: a special key that defines a map of interval times, see below

Each decorator query should return at most 1 row. A warning will be generated if more than 1 row is returned as they will be forcefully ignored and constitute undefined behavior. Each decorator query should be careful not to emit column collisions, this is also undefined behavior.

The columns, and their values, will be appended to each log line as follows. Assuming the above set of decorators is used, and the schedule is execution for over an hour (3600 seconds):

```json
{"decorations": {"user": "you", "uptime": "10000", "version": "1.7.3"}}
```

Expect the normal set of log keys to be included and note that `decorations` is a top-level key in the log line whose value is an embedded map.

The configuration flag `decorations_top_level` can be set to `true` to make decorator data populate as top level key/value objects instead of being contained as a child of `decorations`.  When using this feature, you must be weary of key collisions in existing, reserved, top-level keys.  When collisions do occur, existing key/value data will likely be overwritten by the decorator key/value.  The following example shows the results of collisions on various top-level keys:

Example configuration:

````json
{
  "decorators": {
    "load": [
      "SELECT 'collision' AS name;",
      "SELECT 'collision' AS hostIdentifier;",
      "SELECT 'collision' AS calendarTime;",
      "SELECT 'collision' AS unixTime;",
      "SELECT 'collision' AS columns;",
      "SELECT 'collision' AS action;"
    ]
  }
}
````

Example output:

````json
{
  "name": "collision",
  "hostIdentifier": "collision",
  "calendarTime": "collision",
  "unixTime": "collision",
  "action": "added",
  "columns": {
    "cpu_brand": "Intel(R) Core(TM) i7-4980HQ CPU @ 2.80GHz",
    "hostname": "osquery.example.com",
    "physical_memory": "1234567890"
  }
}
````

The `interval` type uses a map of interval 'periods' as keys, and the set of decorator queries for each value. Each of these intervals MUST be minute-intervals. Anything not divisible by 60 will generate a warning, and will not run.

### Automatic Table Construction

Osquery can be configured to expose local SQLite databases as tables without having to write custom extensions. This means you can construct queries with information from like [Munki](https://github.com/munki/munki) application usage statistics at `/Library/Managed Installs/application_usage.sqlite`, TCC permissions, or quarantined files downloaded through a web browser.

Example:

```
{
  "auto_table_construction": {
    "tcc_system_entries": {
      "query": "SELECT service, client, allowed, prompt_count, last_modified FROM access;",
      "path": "/Library/Application Support/com.apple.TCC/TCC.db",
      "columns": [
        "service",
        "client",
        "allowed",
        "prompt_count",
        "last_modified"
      ],
      "platform": "darwin"
    }
  }
}
```

When targeting Windows you'll need to escape the `\` character `\\Users\\%\\AppData\\Local\\foo\\Settings`.

You'll need to do some legwork if you don't know the structure of the SQLite database.
Taking the `tcc_system_entries` ATC table as an example, which controls which permissions are granted to specific macOS applications, the first step is to open the TCC database. From your terminal, open the database with `sqlite3`:

`$ sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db`

The SQLite shell might feel familiar if you're used to `osqueryi`. That's because osquery uses syntax derived from SQLite for queries.

Let's see what tables exist in our local SQLite database.

```
sqlite> .tables
access            active_policy     expired
access_overrides  admin             policies
```

If you run `select * from access`, you'll see this table contains permissions granted to different applications, which is exactly what we want to query. Looking at the schema for the `access` table gives us the column names which we can use to define our ATC table.

```
sqlite> .schema access
CREATE TABLE access (    service        TEXT        NOT NULL,     client         TEXT        NOT NULL,     client_type    INTEGER     NOT NULL,     allowed        INTEGER     NOT NULL,     prompt_count   INTEGER     NOT NULL,     csreq          BLOB,     policy_id      INTEGER,     indirect_object_identifier_type    INTEGER,     indirect_object_identifier         TEXT,     indirect_object_code_identity      BLOB,     flags          INTEGER,     last_modified  INTEGER     NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),     PRIMARY KEY (service, client, client_type, indirect_object_identifier),    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE ON UPDATE CASCADE);
```

Open a text editor and create a file named `atc_tables.json` using the columns, path, and SQLite table you discovered:

```
{
  "auto_table_construction": {
    "tcc_system_entries": {
      "query": "SELECT service, client, allowed, prompt_count, last_modified FROM access;",
      "path": "/Library/Application Support/com.apple.TCC/TCC.db",
      "columns": [
        "service",
        "client",
        "allowed",
        "prompt_count",
        "last_modified"
      ],
      "platform": "darwin"
    },
    "tcc_user_entries": {
      "query": "SELECT service, client, allowed, prompt_count, last_modified FROM access;",
      "path": "/Users/%/Library/Application Support/com.apple.TCC/TCC.db",
      "columns": [
        "service",
        "client",
        "allowed",
        "prompt_count",
        "last_modified"
      ],
      "platform": "darwin"
    }
  }
}
```

You can test this locally before deploying to your fleet and add more columns as necessary: `/usr/local/bin/osqueryi --verbose --config_path atc_tables.json`

### Events

"Events" refers to the event-based tables.
Events are published into osquery by operating system or application specific APIs; and within osquery certain tables "subscribe" to these publishers.
There is usually a 1-to-many relationship between publishers and subscribers.
See the [development documentation](../development/pubsub-framework.md) for more information on event publishing and subscribing.
Events are almost always tweaked via CLI flags and _options_ referenced above.

The configuration supports a method to explicitly allow and deny events subscribers.
If you choose to explicitly allow subscribers, then all will be disabled except for those specificied in the allow list.
If you choose to explicitly deny subscribers, then all will be enabled except for those specificied in the deny list.

You may want to explicitly disable subscribers if you are only interested in a single type of data produced by a general publisher.

Here is an example configuration:

```json
{
  "schedule": {...},
  "events": {
    "disable_subscribers": ["yara_events"]
  }
}
```

You can inspect the list of subscribers using the query `SELECT * FROM osquery_events where type = 'subscriber';`.
This table will show `1` for the `active` column if a subscriber is enabled.
Note that publishers are more complex and cannot be disabled and enabled this way, please look for a specific CLI flag to control specific publishers.
Also note that different platforms such as Windows and Linux have different sets of subscriber tables. 

## Chef Configuration

Here are example Chef cookbook recipes and files for macOS and Linux deployments. Consider improving the recipes using node attributes to further control what nodes and clients enable osquery. It helps to create a canary or a testing set that implements a separate "testing" configuration. These recipes assume you are deploying the macOS package or the Linux package separately.

### Chef macOS

Consider the default recipe:

```ruby
# Domain used by the macOS LaunchDaemon.
domain = 'com.osquery.osqueryd'
config_path = '/var/osquery/osquery.conf'
pid_path = '/var/osquery/osquery.pid'
flagfile = '/var/osquery/osquery.flags'

directory '/var/osquery' do
  recursive true
  mode 0755
end

template "/Library/LaunchDaemons/#{domain}.plist" do
  source 'launchd.plist.erb'
  mode '0444'
  owner 'root'
  group 'wheel'
  variables(domain: domain,
            config_path: config_path,
            pid_path: pid_path,
            flagfile: flagfile
           )
  notifies :restart, "service[#{domain}]"
end

cookbook_file "/etc/newsyslog.d/#{domain}.conf" do
  source "#{domain}.conf"
  mode 0644
  owner 'root'
  group 'wheel'
end

['osquery.flags', 'osquery.conf'].each do |file|
  cookbook_file "/var/osquery/#{file}" do
    source file
    mode 0444
    owner 'root'
    group 'wheel'
    notifies :restart, "service[#{domain}]"
  end
end

service domain do
  action [:enable, :start]
end
```

And the following files/templates used by the recipe:

**templates/default/launchd.plist.erb**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string><%= @domain %></string>
  <key>ProgramArguments</key>
  <array>
      <string>/usr/local/bin/osqueryd</string>
      <string>--config_path</string>
      <string><%= @config_path %></string>
      <string>--pidfile</string>
      <string><%= @pid_path %></string>
      <string>--flagfile</string>
      <string><%= @flagfile %></string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>Disabled</key>
  <false/>
  <key>ThrottleInterval</key>
  <integer>60</integer>
</dict>
</plist>
```

**files/default/com.osquery.osqueryd.conf**

```shell
# logfilename                         [owner:group]  mode count size   when  flags [/pid_file] [sig_num]
/var/log/osquery/osqueryd.results.log root:wheel     600  2     10000  *     NZ
```

**files/default/osquery.conf**

```json
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "macosx_kextstat": {
      "query": "SELECT * FROM kernel_extensions;",
      "interval": 10
    }
  }
}
```

### Chef Linux

Consider the default recipe:

```ruby
# Service name installed by the osquery package.
service_name = 'osqueryd'

cookbook_file '/etc/osquery/osquery.conf' do
  source 'osquery.conf'
  mode 0444
  owner 'root'
  group 'wheel'
  notifies :restart, "service[#{service_name}]"
end

service service_name do
  action [:enable, :start]
end
```

And the same configuration file from the macOS example is appropriate.

## osqueryctl helper

To test a deploy or configuration we include a short helper script called `osqueryctl`. There are several actions including `start`, `stop`, and `config-check` that apply to both macOS and Linux.
