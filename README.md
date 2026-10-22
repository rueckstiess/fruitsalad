# fruitsalad

A script to redact text and structured JSON log files from MongoDB. 

This script reads a MongoDB log file and writes a redacted copy to stdout. It covers the legacy text format and the JSON format used by default since 4.4.

Four kinds of data are removed:

- **ip.** IPv4 addresses move into `192.168.0.0/16`. IPv6 addresses move under `fd00::/8` (a unique-local prefix). `127.0.0.1`, `0.0.0.0` and `::1` stay, because they name this machine. The port is kept.
- **namespace.** Database and collection names become stable stand-in words (adjectives, colours, fruit), which is where the tool gets its name. The same name stays the same for one `--seed`, and a stand-in never contains `.`, so a name does not gain an extra component. `admin`, `local`, `config`, `$cmd`, and catalog namespaces such as `admin.system.users` and `local.oplog.rs` stay.
- **query.** Filters, pipelines, documents, updates, SCRAM payloads, and error strings become one keyed digest each. Two identical queries still look identical, so the frequency of each query is preserved. Field names inside the payload go with it.
- **user.** `principalName`, `appName`, and hostnames. `__system` stays, so replication heartbeats are not mistaken for application traffic.

Digests are HMAC-SHA256, truncated to 32 hex characters, keyed by `--seed`. The same seed reproduces a file. A different seed produces different digests, so a value cannot be reversed from a public MD5 table. Older releases used bare MD5, which is the same function for every operator.

`security.redactClientLogData` on the server redacts command bodies as they are logged. This script is for files that were already written, and for addresses, namespaces, and application names, which that setting does not cover.

Shell-syntax text logs digest quoted strings, including `ObjectId('...')`. Bare words and numbers in those documents (`key: 1.0`) are left as they are. JSON logs are walked, so the same document is digested there. Read the output before sharing it.

### Usage

```
python3 fruitsalad.py [--seed S] [--only ip,namespace,query,user] [--keep-comment] [--debug] <logfile>
```

Redirect stdout to keep the redacted file, for example `python3 fruitsalad.py mongod.log > redacted.log`.

`--seed` reproduces stand-in names and digests. Without it, every run uses a fresh key. `--only` limits which of the four categories above are redacted; the default is all of them. `--only ip,namespace` leaves query text in place. `--keep-comment` leaves `comment` and `$comment` strings readable so a query can be traced to the job that sent it. The rest of that payload is still digested.

A line that cannot be redacted is replaced with a short placeholder. The original line is not written to stderr, because that stream is often stored next to the redacted file. Pass `--debug` to include it while investigating a failure. The process exits with status 1 if any line failed or the file is empty, and with status 2 if `--only` names an unknown category.

### Tests

The tests use the standard library. From the repository root:

```
python3 -m unittest fruitsalad_test -v
```

nose was the runner named here previously. Its last release does not import on Python 3.10 or newer (`collections.Callable` was removed), and the tests have been `unittest` cases for years. pytest can collect the same file if you prefer it; it is listed as a development extra in `pyproject.toml` and is not required to run the script.

Python 3.11 or newer is required.

### DISCLAIMER

This software is not supported by [MongoDB, Inc.](http://www.mongodb.com) under any of their commercial support subscriptions or otherwise. Any usage of _fruitsalad_ is at your own risk. 
Bug reports, feature requests and questions can be posted in the [Issues](https://github.com/rueckstiess/fruitsalad/issues?state=open) section here on github. 
