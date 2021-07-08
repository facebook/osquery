# Using user tracers on Linux

## Introduction and requirements

When running on a compatible Linux system, osquery can be configured to create simple tables that trace functions and system calls. The requirements are the same as the BPF tables, and are documented in the [Process auditing](process-auditing.md) page.

# Relevant flag options

 * **--disable_events**: Set to **false** to enable events
 * **--enable_bpf_user_tracers**: Set to **true** to enable user tracers
 * **--bpf_max_user_tracer_rows**: Maximum amount of rows that each table should keep in memory

# Configuration

Configuration happens through the main configuration file. The `user_tracers` array contains one object per user tracer, containing informations such as the function name, the function parameters and the table name.

Sample configurations can be found in the repository under the following path: `tools/example_user_tracers`.

# Example usage: Tracing bash

## Configuration

Bash uses the `readline()` function from the libreadline library to retrieve user input, so we'll attempt to create a user tracer to extract what is being entered in the shell.


```
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "utc": "true"
  },

  "schedule": {
    "system_info": {
      "query": "SELECT * FROM libcurl_events;",
      "interval": 5
    }
  },

  // User tracers
  "user_tracers": [
    {
      "table_name": "bash_events",
      "path": "/usr/bin/bash",
      "function_name": "readline",
      "parameter_list": [
        {
          "name": "prompt",
          "type": "String",
          "mode": "In"
        },
        {
          "name": "EXIT_CODE",
          "type": "String",
          "mode": "Out"
        }
      ]
    }
  ]
}
```

On Ubuntu, the `libreadline` library is linked statically into the shell's binary, so we'll set the path of the user tracer to `/usr/bin/bash`.

The first (and only) parameter that we want to capture is the prompt; this is a string and can be recorded when execution enters the function.

User input is returned by the function as a character pointer. The exit code is always automatically captured by the table and provided as a numeric value. In our case however, we want to re-capture it as a string. A special parameter, named **EXIT_CODE**, can be used for this purpose, which will generate a special column named `return_value`.

## Table output

```
osquery> SELECT pid, uid, gid, prompt, return_value FROM bash_events;
+-------+------+------+------------------------------------------------+--------------+
| pid   | uid  | gid  | prompt                                         | return_value |
+-------+------+------+------------------------------------------------+--------------+
| 51211 | 1000 | 1000 | alessandro@ubuntu2104-rincewind:/etc/osquery$  | apt update   |
+-------+------+------+------------------------------------------------+--------------+
```
