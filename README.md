# fruitsalad

A script to redact log files from MongoDB <= 4.2.X. fruitsalad is incompatible with logs from MongoDB 4.4+. 

This script reads a MongoDB log file and outputs a redacted version of the log file, replacing IP addresses, namespaces and query/update data. Namespace details are replaced with generic adjectives, colours and fruit names (hence the name "fruitsalad"). IP addresses are mapped to a private range starting with `192.168.`. The query values are hashed with a standard MD5 algorithm, so that the distribution of data remains unchanged, while the actual data will be lost. Note: The **field names** of the queries are currently left **unchanged**.

This is a very early beta version. 

### Usage

```
python fruitsalad.py <logfile>
```

to output the scrambled version to _stdout_, or redirect the output to a file by adding `> redacted.log` to the end of the command.

### Tests

`fruitsalad` uses [nose](https://github.com/nose-devs/nose) for testing. Please follow the instructions in the [nose documentation page](https://nose.readthedocs.io/en/latest/) for the recommended method to install nose. After nose is installed, testing could be done by running:

```
nosetests -v
```

in `fruitsalad`'s root directory. The `-v` is optional, and is only used to display a more verbose testing messages.

### DISCLAMER

This software is not supported by [MongoDB, Inc.](http://www.mongodb.com) under any of their commercial support subscriptions or otherwise. Any usage of _fruitsalad_ is at your own risk. 
Bug reports, feature requests and questions can be posted in the [Issues](https://github.com/rueckstiess/fruitsalad/issues?state=open) section here on github. 
