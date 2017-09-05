# fruitsalad

A script to redact MongoDB log files. 

This script reads a MongoDB log file and outputs a redacted version of the log file, replacing IP addresses, namespaces and query/update data. Namespace details are replaced with generic adjectives, colours and fruit names (hence the name "fruitsalad"). IP addresses are mapped to a private range starting with `192.168.`. The query values are hashed with a standard MD5 algorithm, so that the distribution of data remains unchanged, while the actual data will be lost. Note: The **field names** of the queries are currently left **unchanged**.

This is a very early beta version. 

### Usage

```
python fruitsalad.py <logfile>
```

to output the scrambled version to _stdout_, or redirect the output to a file by adding `> redacted.log` to the end of the command.


### DISCLAMER

This software is not supported by [MongoDB, Inc.](http://www.mongodb.com) under any of their commercial support subscriptions or otherwise. Any usage of _fruitsalad_ is at your own risk. 
Bug reports, feature requests and questions can be posted in the [Issues](https://github.com/rueckstiess/fruitsalad/issues?state=open) section here on github. 