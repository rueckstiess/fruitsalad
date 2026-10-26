# fruitsalad

A script to redact text and structured JSON log files from MongoDB. 

This script reads a MongoDB log file and outputs a redacted version of the log file, replacing IP addresses, namespaces and query/update data. Namespace details are replaced with generic adjectives, colours and fruit names (hence the name "fruitsalad"). IP addresses are mapped to a private range starting with `192.168.`. The query values are hashed with a standard MD5 algorithm, so that the distribution of data remains unchanged, while the actual data will be lost.

Note: This is still in beta. It is advised to perform a manual check on the output to ensure any sensitive data has been redacted.

### Usage

```
python3 fruitsalad.py <logfile>
```

to output the scrambled version to _stdout_, or redirect the output to a file by adding `> redacted.log` to the end of the command.

A line that cannot be redacted is replaced with a short placeholder. The original line is not written to stderr, because that stream is often stored next to the redacted file. Pass `--debug` to include it while investigating a failure. The process exits with status 1 if any line failed, or if the file is empty. `--seed` is optional; without it the stand-in names change on every run.

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
