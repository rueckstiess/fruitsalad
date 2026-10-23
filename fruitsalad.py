#!/usr/bin/env python3
"""Redact MongoDB log files.

Text logs (the format used through 4.2, and still available as
systemLog.logFormat) are rewritten with regular expressions. JSON logs
(4.4 and later, and the default since then) are parsed and walked.

What is redacted
----------------
ip
    IPv4 and IPv6 addresses, including the address half of a host:port
    field such as attr.remote. 127.0.0.1, 0.0.0.0 and ::1 stay: they
    name this machine, not a client. Other IPv4 addresses are moved
    into 192.168.0.0/16. IPv6 addresses are moved under fd00::/8,
    which is a unique-local prefix and not the customer's.
namespace
    Database and collection names. Within one file, the same name and
    the same --seed produce the same stand-in, so the file can still
    be followed. Two names never share a word, so a name takes the
    next word when its first choice was already used earlier in that
    file. admin, local and config stay, and so do catalog namespaces
    such as admin.system.users and local.oplog.rs. $cmd stays.
    Stand-in words do not contain '.', so the number of namespace
    components does not change.
query
    Command payloads: filters, pipelines, documents, updates, the
    findAndModify update document, SCRAM payloads, and error strings.
    One payload becomes one keyed digest. Two identical queries still
    look identical, which keeps the frequency of each query. Field
    names inside the payload disappear with it.
user
    principalName, appName, and hostnames. __system is the internal
    user on replication and sharding heartbeats and stays, so those
    lines are not mistaken for application traffic.

Digests are HMAC-SHA256 truncated to 128 bits, keyed by --seed. The
same seed reproduces the file. A different seed produces different
digests, so a value cannot be reversed by looking it up in a public
MD5 table. The old code hashed with bare MD5, which is the same
function for every operator in the world.

--only turns categories off. --keep-comment leaves comment and
$comment strings in place so a query can be traced to the job that
sent it; the rest of that payload is still digested.

The server setting security.redactClientLogData redacts command
bodies as they are logged. This script is for files already written,
and for the identifiers that setting does not cover (addresses,
namespaces, application names). A person should still read the output
before sharing it. Shell-syntax text logs leave bare words and
numbers in place (``key: 1.0``); only quoted strings are digested.
"""

from enum import Enum
import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sys
import traceback

from wordlists import ADJECTIVES, COLORS, FRUITS


class LogType(Enum):
    TEXT = 0
    JSON = 1


# Categories --only accepts. The default is all of them.
CATEGORIES = ('ip', 'namespace', 'query', 'user')

# Catalog databases. The name is not customer data. A collection that
# a user created inside one of them is still redacted.
_SYSTEM_DBS = frozenset({'admin', 'local', 'config'})

# Whole namespaces that are server internals rather than user data.
# local.oplog.rs is matched here because its second component is
# "oplog", so the admin.system.* rule below does not cover it.
_KEEP_NAMESPACES = frozenset({
    'local.oplog.rs',
    'oplog.rs',
})

# Left in place when they appear as their own dotted component, so
# mail.example.com is still recognisable as a DNS name and test.$cmd
# is still recognisable as a command namespace.
_KEPT_LABELS = frozenset({
    '$cmd', 'com', 'net', 'org', 'edu', 'gov',
})

# The log envelope. These are written by the server, not the client.
_ENVELOPE_KEYS = frozenset({'t', 's', 'c', 'id', 'ctx', 'msg', 'tags'})

# A string value under one of these keys is a collection name, but
# only when it is a string. See _walk for the non-string cases.
_COLLECTION_KEYS = frozenset({
    'find', 'insert', 'update', 'delete', 'aggregate', 'findAndModify',
    'count', 'distinct', 'create', 'drop', 'createIndexes', 'dropIndexes',
    'listIndexes', 'collMod', 'compact', 'mapReduce', 'killCursors',
    'renameCollection', 'filemd5', 'convertToCapped', 'collStats',
    'createSearchIndexes', 'dropSearchIndex',
})

# A full namespace (db.coll) or a single collection-or-namespace label
# the server already joined.
_NAMESPACE_KEYS = frozenset({
    'ns', 'namespace', 'sourceNamespace', 'targetNamespace',
    'fromName', 'toName', 'collection',
})

# Always a database name, including the one-label form. A one-label
# value under _NAMESPACE_KEYS is treated as a collection, because that
# is what fromName / toName / a bare ns component is. $db is not.
_DATABASE_KEYS = frozenset({'$db', 'authenticationDatabase'})

# Replaced as a whole. Hashing the whole value is what hides field
# names, and what makes two identical queries share one digest.
_QUERY_KEYS = frozenset({
    'filter', 'query', 'q', 'u', 'pipeline', 'documents', 'updates',
    'deletes', 'projection', 'let', 'arrayFilters', 'predicate',
    'indexBounds', 'multiKeyPaths', 'payload', 'pwd', 'digest',
    'errmsg', 'indexes', 'options', 'o', 'o2',
    # findAndModify calls its projection "fields". create/collMod
    # store the JSON Schema under "validator". explain names the
    # predicate "parsedQuery". None of those are in the list above,
    # and walking them kept the field names and the numbers.
    'fields', 'validator', 'parsedQuery',
})

# Key patterns: the keys are field names, the values are directions
# (1, -1, "text", "2dsphere") or numbers. Keep the values, replace
# the keys. hint is handled beside these because it is sometimes an
# index-name string instead of a document.
_KEY_PATTERN_KEYS = frozenset({'sort', 'keyPattern'})

_ENDPOINT_KEYS = frozenset({'remote', 'client', 'me'})
_USER_KEYS = frozenset({'principalName', 'user', 'appName'})

# Operational strings. Anything string-valued that is not listed here
# and is not claimed by a rule above is digested. That is the safe
# direction for a field a later server adds.
_KEEP_STRING_KEYS = frozenset({
    'type', 'protocol', 'codeName', 'mechanism', 'uuidDisposition',
    'op', 'stage', 'provenance', 'planNodeType',
    '$uuid', '$oid', '$date', 'subType',
})

_POOLS = {
    'database': COLORS,
    'collection': FRUITS,
    'field': ADJECTIVES,
    'host': ADJECTIVES,
}

# Four dotted decimals with each octet in 0..255. The alternatives are
# ordered so 255 is not parsed as 25 and a leftover 5.
_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)'
# Lookarounds rather than a consumed character on each side.
# "Accepted from 10.9.8.7" ends on the address, and a text line can
# start with one. A required delimiter on both sides left those in
# the output. \w keeps the match off the tail of a longer token.
_IPV4_IN_TEXT = re.compile(
    rf'(?<!\w)(?P<ip>{_OCTET}(?:\.{_OCTET}){{3}})(?!\w)'
)
_IPV6_IN_TEXT = re.compile(r'\[([0-9A-Fa-f:]+)\]')
_DOUBLE_QUOTED = re.compile(r'"(?:\\.|[^"\\])*"')
_SINGLE_QUOTED = re.compile(r"'(?:\\.|[^'\\])*'")
# A dotted identifier: namespaces, hostnames, and field paths such as
# arr.element. Requires a dot, so a bare word is left for the host=
# pass and for the known gap around unquoted shell values.
_DOTTED = re.compile(
    r'[a-zA-Z$][^ \t\n\r\f\v:\'"]+(?:\.[a-zA-Z$][^ \t\n\r\f\v:\'"]+)+'
)
# MMAPv1 names its files "<db>.<n>" (test.0, test.1). _DOTTED misses
# them because it wants a letter after every dot. A version such as
# v3.4.7 has a digit in the label, and 10.8.0 starts with a digit, so
# neither matches. The lookbehind keeps this off a stand-in that
# _DOTTED already rewrote (color.fruit.0 is not a data file).
_DATAFILE = re.compile(
    r'(?<![\w.])(?P<db>[A-Za-z][A-Za-z_-]*)\.(?P<n>\d+)(?!\d)'
)
# Single-label host= only. A dotted host was already rewritten by
# _DOTTED; matching dots here would rewrite the stand-in a second time.
_HOST_EQ = re.compile(r'\bhost=(?P<host>[A-Za-z0-9_-]+)\b')
# Dotted index keys (user.email) are one path. A pattern that stops
# at the first dot leaves the prefix "user" in the planSummary.
_PLAN_KEY = re.compile(
    r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*:'
)


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _split_endpoint(value):
    """Return (host, port-including-colon, was-bracketed).

    Bracketed IPv6 keeps the port outside the brackets. A trailing
    :port is split only when the head is an address, so localhost:27017
    stays in one piece for the hostname path and ::ffff:10.1.2.3:27017
    does not. A bare ::1 has no port: rsplit would see host ":" and
    port "1", which is not an address, so the whole value is kept.
    """
    if value.startswith('['):
        end = value.find(']')
        if end <= 1:
            return None
        rest = value[end + 1:]
        if rest and not re.fullmatch(r':\d+', rest):
            return None
        return value[1:end], rest, True
    if ':' in value:
        host, port = value.rsplit(':', 1)
        if host and port.isdigit() and _is_ip(host):
            return host, ':' + port, False
    return value, '', False


def _decode_log_line(raw):
    """One log line as text, with the newline normalised to \\n.

    Reading the file as text raises UnicodeDecodeError from the
    iterator, outside the per-line handler, so one bad byte dropped
    the rest of the file. Bytes let that line become a placeholder.
    The newline fold matches what a text-mode open used to do, which
    is what the CRLF fixtures were generated with.
    """
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if text.endswith('\r\n'):
        return text[:-2] + '\n'
    if text.endswith('\r'):
        return text[:-1] + '\n'
    return text


def _canonical(value):
    """Stable JSON for a digest.

    Key order in the log is not part of the query. sort_keys makes
    {"b": 1, "a": 2} and {"a": 2, "b": 1} share a digest, which is the
    distribution the README talks about. Compact separators keep the
    digest independent of how the log line was pretty-printed.
    """
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False)


def _strip_comments(value):
    """Remove comment strings from a payload before it is digested.

    Returns (comments in encounter order, payload with those strings
    replaced by a placeholder). The placeholder keeps the digest stable
    for a given query regardless of the comment text, so --keep-comment
    does not make two runs of the same query look unrelated.
    """
    found = []

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, item in node.items():
                if key in ('comment', '$comment') and isinstance(item, str):
                    found.append(item)
                    out[key] = '<comment>'
                else:
                    out[key] = walk(item)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return found, walk(value)


class FruitSaladTool(object):
    """Replace addresses, namespaces, and query values in one log file."""

    def __init__(self, arg_logfile, arg_seed=None, debug=False,
                 categories=None, keep_comment=False):
        # None stays None. The previous code did str(None), which is the
        # string "None", and then seeded the RNG with it on every run.
        self.seed = arg_seed
        self.logfile = arg_logfile
        self.debug = debug
        self.keep_comment = keep_comment
        if categories is None:
            self.categories = frozenset(CATEGORIES)
        else:
            self.categories = frozenset(categories)
        # Keyed digest, not random.choice. Which code path notices a
        # name does not matter. A linear probe then keeps two names in
        # one role from sharing a word, so the word a name gets can
        # depend on names already seen in this file. The same file and
        # the same seed stay stable. The old shared map made the first
        # sighting win, so test.test became one repeated word instead
        # of a database stand-in plus a collection stand-in.
        if arg_seed is None:
            self._key = secrets.token_bytes(32)
        else:
            self._key = hashlib.sha256(
                f'fruitsalad:{arg_seed}'.encode('utf-8')).digest()
        self._tokens = {role: {} for role in _POOLS}
        self._ipv4 = {}
        self._ipv6 = {}
        self.failures = 0
        self.logtype = self._get_logtype()

    def _hmac(self, text):
        return hmac.new(self._key, text.encode('utf-8'), hashlib.sha256).digest()

    def _digest(self, text, purpose):
        """128-bit keyed digest, as 32 hex characters.

        Truncation is for the width of a log line. 128 bits is enough
        that a single file will not collide. purpose is part of the
        input so a username does not share a stand-in with a query
        whose canonical JSON happens to equal that username.
        """
        return self._hmac(f'{purpose}:{text}')[:16].hex()

    def _token(self, original, role):
        cache = self._tokens[role]
        if original in cache:
            return cache[original]
        pool = _POOLS[role]
        used = set(cache.values())
        start = int.from_bytes(self._hmac(f'token:{role}:{original}')[:8], 'big')
        for step in range(len(pool)):
            candidate = pool[(start + step) % len(pool)]
            # Linear probe so two different names in one role do not
            # share a stand-in. A shared stand-in would glue two
            # collections together for anyone reading the log.
            if candidate not in used:
                cache[original] = candidate
                return candidate
        # More distinct names than the word list. The fallback cannot
        # contain '.' (see the wordlists module).
        fallback = 'n' + self._digest(original, f'overflow-{role}')[:10]
        cache[original] = fallback
        return fallback

    def _map_ipv4(self, ip):
        if 'ip' not in self.categories:
            return ip
        if ip in ('127.0.0.1', '0.0.0.0'):
            return ip
        cached = self._ipv4.get(ip)
        if cached:
            return cached
        used = set(self._ipv4.values())
        for attempt in range(65534):
            raw = self._hmac(f'ip4:{ip}:{attempt}')
            first, second = raw[0], raw[1]
            # 192.168.0.0 is the network address, not a host.
            if (first, second) == (0, 0):
                continue
            candidate = f'192.168.{first}.{second}'
            if candidate not in used:
                self._ipv4[ip] = candidate
                return candidate
        raise RuntimeError('exhausted 192.168.0.0/16 stand-ins')

    def _map_ipv6(self, ip):
        if 'ip' not in self.categories:
            return ip
        try:
            address = ipaddress.IPv6Address(ip)
        except ValueError:
            address = None
        if address is not None and address == ipaddress.IPv6Address('::1'):
            # ::0001 and 0:0:0:0:0:0:0:1 are the same loopback. The
            # string compare missed every spelling except two of them.
            return '::1'
        if address is not None and address.ipv4_mapped is not None:
            # ::ffff:a.b.c.d is an IPv4 client. Map that half. Leaving
            # the prefix keeps the value obviously IPv6-mapped.
            return '::ffff:' + self._map_ipv4(str(address.ipv4_mapped))
        folded = address.compressed if address is not None else ip.lower()
        if folded in ('::1', '0:0:0:0:0:0:0:1'):
            return '::1'
        cached = self._ipv6.get(folded)
        if cached:
            return cached
        raw = self._hmac(f'ip6:{folded}')
        # Four hextets under fd00::/8. RFC 4193 unique-local, so the
        # stand-in is not a routable address and is not the prefix the
        # customer was using.
        hextets = [raw[i:i + 2].hex() for i in range(0, 8, 2)]
        candidate = 'fd00::' + ':'.join(hextets)
        self._ipv6[folded] = candidate
        return candidate

    def _database(self, name):
        if 'namespace' not in self.categories:
            return name
        if name in _SYSTEM_DBS:
            return name
        return self._token(name, 'database')

    def _collection(self, name):
        if 'namespace' not in self.categories:
            return name
        if name == '$cmd':
            return name
        return self._token(name, 'collection')

    def _namespace(self, ns):
        """Redact a dotted namespace, keeping catalog structure.

        A one-label value is a collection. Callers that know the value
        is a database ($db, authenticationDatabase) use _database,
        because a one-label namespace and a database would otherwise
        be forced through the same word list.
        """
        if 'namespace' not in self.categories or not isinstance(ns, str):
            return ns
        if ns in _KEEP_NAMESPACES:
            return ns
        parts = ns.split('.')
        if len(parts) >= 2 and parts[0] in _SYSTEM_DBS and parts[1] == 'system':
            # admin.system.users, config.system.sessions, and the rest
            # of the catalog. A user collection in a system database
            # (admin.myusers) does not have "system" as the second
            # component, so its collection name is still replaced.
            return ns
        if len(parts) == 1:
            return self._collection(parts[0])
        replaced = []
        last = len(parts) - 1
        for index, part in enumerate(parts):
            if part in _KEPT_LABELS or (index == 0 and part in _SYSTEM_DBS):
                replaced.append(part)
                continue
            if index == last:
                role = 'collection'
            elif index == last - 1:
                role = 'database'
            else:
                role = 'field'
            replaced.append(self._token(part, role))
        return '.'.join(replaced)

    def _hostname(self, host):
        rewritten = self._rewrite_ip(host)
        if rewritten is not None:
            return rewritten
        if 'user' not in self.categories:
            return host
        if host in ('localhost', 'localhost.localdomain'):
            return host
        if '.' in host:
            return self._redact_dotted(host)
        return self._token(host, 'host')

    def _redact_dotted(self, text):
        """Stand-ins for a dotted name in a text log.

        Text logs do not say whether the name is a namespace or a
        hostname. Either the namespace category or the user category
        turns this on. DNS suffixes in _KEPT_LABELS stay so the result
        is still recognisable as a hostname.
        """
        if 'namespace' not in self.categories and 'user' not in self.categories:
            return text
        # admin.system.* and local.oplog.rs are catalog names, not
        # hostnames. Leave them alone even when this pass ran because
        # the user category is on and the namespace category is off.
        parts = text.split('.')
        if text in _KEEP_NAMESPACES or (
            len(parts) >= 2 and parts[0] in _SYSTEM_DBS and parts[1] == 'system'
        ):
            return text
        if 'namespace' in self.categories:
            return self._namespace(text)
        return self._dot_labels(parts)

    def _dot_labels(self, parts):
        """Hostname labelling when namespaces are not being redacted.

        Hostnames do not split into a database and a collection. DNS
        suffixes in _KEPT_LABELS stay, so the stand-in still looks
        like a hostname.
        """
        return '.'.join(
            part if part in _KEPT_LABELS else self._token(part, 'host')
            for part in parts
        )

    def _rewrite_ip(self, host):
        """Stand-in for an address, or None when host is a name.

        ipaddress accepts the spellings the endpoint regexes reject:
        ::1 written as ::0001, and IPv4 mapped into IPv6
        (::ffff:10.1.2.3), which is how a dual-stack listener logs
        an IPv4 client.
        """
        if 'ip' not in self.categories or not isinstance(host, str):
            return None
        try:
            return self._map_ipv4(str(ipaddress.IPv4Address(host)))
        except ValueError:
            pass
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            return None
        if address.ipv4_mapped is not None:
            return '::ffff:' + self._map_ipv4(str(address.ipv4_mapped))
        return self._map_ipv6(host)

    def _endpoint(self, value):
        """Redact the address in a remote/client field and keep the port.

        JSON logs put the client in attr.remote as "ip:port",
        "[ipv6]:port", or "hostname:port". The port is not identifying
        on its own and is useful when following a connection.
        A bare ::1 has no brackets and more than one colon, so the
        hostname fallback used to replace it with a word.
        """
        if not isinstance(value, str):
            return value
        if 'ip' in self.categories:
            parsed = _split_endpoint(value)
            if parsed is not None:
                host, port, bracketed = parsed
                rewritten = self._rewrite_ip(host)
                if rewritten is not None:
                    if bracketed:
                        return '[' + rewritten + ']' + port
                    return rewritten + port
        # Hostnames in this field are a user identifier, so they are
        # still rewritten when the ip category is off and the user
        # category is on. An address that was not recognised above
        # is left alone when the user category is off: tokenising it
        # as a hostname is how --only ip used to keep ::ffff:10.1.2.3.
        if 'user' in self.categories:
            return self._endpoint_host(value)
        return value

    def _endpoint_host(self, value):
        if value.count(':') == 1:
            host, port = value.rsplit(':', 1)
            if port.isdigit():
                return self._hostname(host) + ':' + port
        return self._hostname(value)

    def _user(self, name):
        if 'user' not in self.categories or not isinstance(name, str):
            return name
        # __system is the internal user. Replacing it makes heartbeat
        # and oplog lines look like application traffic.
        if name == '__system':
            return name
        return self._digest(name, 'user')

    def _maybe_query(self, value):
        """Digest a payload, or return it unchanged when query is off.

        An empty document or list is "match everything" or "no
        documents". Digesting it would hide an unfiltered delete.
        There is no user data in it.
        """
        if 'query' not in self.categories:
            return value
        if value in ({}, [], ''):
            return value
        if self.keep_comment:
            comments, stripped = _strip_comments(value)
            digest = self._digest(_canonical(stripped), 'query')
            if comments:
                # The comments are outside the digest. Readers who
                # passed --keep-comment asked to see them; everyone
                # else gets the digest only.
                return {'_redacted': digest, 'comment': comments}
            return digest
        return self._digest(_canonical(value), 'query')

    def _key_pattern(self, document):
        if 'namespace' not in self.categories:
            return document
        # Directions and index types are operational. Any other string,
        # and any nested document, can carry user data.
        index_types = ('text', '2dsphere', '2d', 'geoHaystack', 'hashed')
        replaced = {}
        for key, value in document.items():
            stand_in = self._token(key, 'field')
            if isinstance(value, (dict, list)):
                replaced[stand_in] = self._maybe_query(value)
            elif isinstance(value, str) and value not in index_types:
                replaced[stand_in] = self._maybe_query(value)
            else:
                replaced[stand_in] = value
        return replaced

    def _plan_summary(self, text):
        """Replace field names inside planSummary braces.

        The stage names (IXSCAN, COLLSCAN, OR, EXPRESS_IXSCAN) are how
        you tell what the planner did, so they stay. The names inside
        the braces are the customer's fields. Classic planSummary does
        not nest braces; a nested SBE fragment still has each `{...}`
        span rewritten, because we scan brace contents rather than
        parse the plan grammar.
        """
        if 'namespace' not in self.categories or not isinstance(text, str):
            return text
        pieces = []
        cursor = 0
        while cursor < len(text):
            opening = text.find('{', cursor)
            if opening == -1:
                pieces.append(text[cursor:])
                break
            closing = text.find('}', opening)
            if closing == -1:
                pieces.append(text[cursor:])
                break
            pieces.append(text[cursor:opening + 1])
            body = text[opening + 1:closing]

            def replace_key(match, self=self):
                labels = match.group(1).split('.')
                return '.'.join(
                    self._token(part, 'field') for part in labels
                ) + ':'

            pieces.append(_PLAN_KEY.sub(replace_key, body))
            pieces.append('}')
            cursor = closing + 1
        return ''.join(pieces)

    def _name_field(self, value, parent):
        """The key "name" means several different things.

        driver.name and os.name are the driver and the operating
        system ("PyMongo", "Ubuntu"). application.name is chosen by
        the client and often identifies a service or a person. Any
        other name is an index name or a role name; those repeat
        field names, except the mandatory _id_ index.
        """
        if parent == 'driver':
            return value
        if parent == 'os':
            return value
        if parent == 'application':
            return self._user(value)
        if value == '_id_':
            return value
        return self._maybe_query(value)

    def _drop_target(self, value):
        # dropTarget is the string "no" / "yes" in older logs and a
        # boolean or a collection name in others. Only the collection
        # name is customer data.
        if value in ('no', 'yes', True, False, None):
            return value
        if isinstance(value, str):
            if '.' in value:
                return self._namespace(value)
            return self._collection(value)
        return value

    def _scrub_kept_string(self, text):
        """Replace addresses inside a string we are otherwise keeping."""
        if 'ip' not in self.categories or not isinstance(text, str):
            return text
        text = _IPV6_IN_TEXT.sub(
            lambda match: '[' + self._map_ipv6(match.group(1)) + ']', text)
        return _IPV4_IN_TEXT.sub(self._replace_ipv4_text, text)

    def _walk(self, value, key, parent):
        """Rewrite one JSON value.

        The key's meaning wins over the value's shape. That is what
        makes findAndModify and db.aggregate() work: both reuse a key
        the other commands use for a collection name.

        findAndModify puts the update document under "update". The
        update command puts the collection name there. The type is
        the difference. A document is a payload. A string is a name.

        db.aggregate() sends {aggregate: 1}. The integer 1 is a
        sentinel meaning "this database, no collection". It is not a
        collection named "1", and there is nothing to split.
        """
        if key in ('comment', '$comment'):
            # --keep-comment is the string a job puts on a query so the
            # line can be traced. A document is legal BSON there and
            # can carry an email; digesting it is the same as any
            # other payload.
            if self.keep_comment and isinstance(value, str):
                return value
            return self._maybe_query(value)

        if key == 'update' and isinstance(value, dict):
            return self._maybe_query(value)

        if key == 'hint':
            if isinstance(value, dict):
                return self._key_pattern(value)
            if isinstance(value, str):
                return self._maybe_query(value)
            return value

        if key in _KEY_PATTERN_KEYS and isinstance(value, dict):
            return self._key_pattern(value)

        if key in _QUERY_KEYS or key == 'signature':
            # signature is the cluster HMAC on $clusterTime. It is not
            # needed to read a query, and it is cluster key material.
            return self._maybe_query(value)

        if key == 'error' and isinstance(value, str):
            # The object form of an error has code and codeName, which
            # are kept, and errmsg, which is a query field. The string
            # form ("not authorized on db to execute command {...}")
            # embeds the command, so the whole string is a payload.
            return self._maybe_query(value)

        if key in _COLLECTION_KEYS and isinstance(value, str):
            return self._collection(value)

        if key in _NAMESPACE_KEYS and isinstance(value, str):
            return self._namespace(value)

        if key in _DATABASE_KEYS and isinstance(value, str):
            return self._database(value)

        if key in _ENDPOINT_KEYS and isinstance(value, str):
            return self._endpoint(value)

        if key in ('host', 'hostname') and isinstance(value, str):
            return self._hostname(value)

        if key in _USER_KEYS and isinstance(value, str):
            return self._user(value)

        if key == 'planSummary' and isinstance(value, str):
            return self._plan_summary(value)

        if key in ('index', 'indexName') and isinstance(value, str):
            # explain reports the same index as indexName. _id_ is the
            # mandatory index, not a name the customer chose.
            if value == '_id_':
                return value
            return self._maybe_query(value)

        if key == 'name' and isinstance(value, str):
            return self._name_field(value, parent)

        if key == 'dropTarget':
            return self._drop_target(value)

        if isinstance(value, dict):
            return {
                child: self._walk(item, child, key)
                for child, item in value.items()
            }
        if isinstance(value, list):
            return [self._walk(item, key, parent) for item in value]
        if isinstance(value, str):
            # driver.version and os.version are the client build, which
            # is what you keep a log for. application.name is not, and
            # is handled with the other user fields above.
            if key in _KEEP_STRING_KEYS or (
                key == 'version' and parent in ('driver', 'os')
            ):
                return self._scrub_kept_string(value)
            # A string we do not have a specific rule for. Digesting it
            # is the safe direction: a field added by a later server is
            # hidden until it is deliberately added to a keep-list.
            return self._digest(value, 'string') if 'query' in self.categories else value
        return value

    def _redact_record(self, document):
        redacted = {}
        for key, value in document.items():
            if key in _ENVELOPE_KEYS:
                if key == 'msg':
                    redacted[key] = self._scrub_kept_string(value)
                else:
                    redacted[key] = value
            elif key == 'size':
                # Byte counts of truncated sections. Not user data.
                redacted[key] = value
            else:
                # attr holds the event. truncated holds the parts of
                # attr the server cut off; those parts are the same
                # kind of data and go through the same walk. Any other
                # top-level key a later server adds is walked too.
                redacted[key] = self._walk(value, key, None)
        return redacted

    def _replace_ipv4_text(self, match):
        return self._map_ipv4(match.group('ip'))

    def _replace_datafile(self, match):
        db = match.group('db')
        # local.0 is the local database's data file. The database
        # name is kept; only a customer database is replaced.
        if db in _SYSTEM_DBS or db in _KEPT_LABELS:
            return match.group(0)
        return self._database(db) + '.' + match.group('n')

    def _redact_text_line(self, line):
        # Quoted strings first. An address or a namespace inside quotes
        # is part of the payload (a document, a path, an application
        # name) and is covered by the digest. Doing addresses first
        # would fold the real address into the digest and make two
        # seeds disagree about a quoted value for no reason.
        if 'query' in self.categories:
            line = _DOUBLE_QUOTED.sub(
                lambda match: '"' + self._digest(match.group(0), 'query') + '"',
                line)
            # Mongo shell values are single quoted: ObjectId('...'),
            # and strings inside a logged document. The double-quote
            # pass does not see them, which is why those ObjectIds used
            # to survive in the redacted text logs.
            line = _SINGLE_QUOTED.sub(
                lambda match: "'" + self._digest(match.group(0), 'query') + "'",
                line)
        if 'ip' in self.categories:
            line = _IPV6_IN_TEXT.sub(
                lambda match: '[' + self._map_ipv6(match.group(1)) + ']',
                line)
            line = _IPV4_IN_TEXT.sub(self._replace_ipv4_text, line)
        if 'namespace' in self.categories:
            # Before the dotted pass. A rewritten stand-in plus ".0"
            # must not be treated as another data file.
            line = _DATAFILE.sub(self._replace_datafile, line)
        if 'namespace' in self.categories or 'user' in self.categories:
            line = _DOTTED.sub(
                lambda match: self._redact_dotted(match.group(0)), line)
        if 'user' in self.categories:
            line = _HOST_EQ.sub(
                lambda match: 'host=' + self._hostname(match.group('host')),
                line)
        # rstrip drops the original newline and any trailing spaces,
        # then one newline is written back. Matches the historical
        # text output, which compared equal to the stripped fixtures.
        return line.rstrip() + '\n'

    def run(self):
        """Write the redacted file to stdout. Return the failure count."""
        self.failures = 0
        with open(self.logfile, 'rb') as handle:
            for line_number, raw in enumerate(handle, start=1):
                line = _decode_log_line(raw)
                if line is None:
                    self._report_failure(
                        line_number,
                        'invalid UTF-8',
                        raw.decode('utf-8', errors='backslashreplace'),
                    )
                    continue
                try:
                    if self.logtype == LogType.TEXT:
                        sys.stdout.write(self._redact_text_line(line))
                    elif not line.strip():
                        # Keep the blank line so a failure's line number
                        # still matches the source file. JSON parsers
                        # skip it.
                        sys.stdout.write(line if line.endswith('\n') else line + '\n')
                    else:
                        document = json.loads(line)
                        sys.stdout.write(json.dumps(
                            self._redact_record(document),
                            ensure_ascii=False) + '\n')
                except json.JSONDecodeError as exc:
                    self._report_failure(
                        line_number, f'invalid JSON ({exc.msg})', line)
                except Exception as exc:
                    # A half-rewritten document must not be printed.
                    self._report_failure(
                        line_number, f'could not redact ({exc})', line)
        return self.failures

    def _report_failure(self, line_number, reason, raw_line):
        """Count a line we could not redact, without echoing it.

        The raw line is what the caller asked us to hide. Writing it
        to stderr puts it in the terminal and in any collector that
        ships stderr next to the redacted file. --debug opts back in.
        The placeholder keeps a line in the output so a following line
        does not silently slide up.
        """
        self.failures += 1
        sys.stderr.write(
            f'fruitsalad: {self.logfile}:{line_number}: {reason}\n')
        if self.debug:
            traceback.print_exc()
            sys.stderr.write(raw_line)
            if not raw_line.endswith('\n'):
                sys.stderr.write('\n')
        if self.logtype == LogType.JSON:
            placeholder = json.dumps({
                'fruitsalad': 'redaction-failed',
                'line': line_number,
            })
        else:
            placeholder = f'fruitsalad redaction-failed line {line_number}'
        sys.stdout.write(placeholder + '\n')

    def _get_logtype(self):
        # Same byte-wise read as run(). A locale encoding here and
        # UTF-8 in run() would split a multi-byte character on a
        # non-UTF-8 machine. Blank lines are skipped so a leading
        # spacer does not decide the format, and so an empty file is
        # an error instead of IndexError on the first character. An
        # undecodable line is skipped while deciding: a JSON log's
        # first real line is ASCII "{". A file that is only bad bytes
        # is still scanned, so each of those lines can be placeholdered.
        saw_bytes = False
        saw_bad = False
        with open(self.logfile, 'rb') as handle:
            for raw in handle:
                saw_bytes = True
                line = _decode_log_line(raw)
                if line is None:
                    saw_bad = True
                    continue
                if not line.strip():
                    continue
                if line.lstrip().startswith('{'):
                    return LogType.JSON
                return LogType.TEXT
        if saw_bytes and saw_bad:
            return LogType.TEXT
        raise ValueError(f'{self.logfile}: empty log file')


def main(argv=None):
    """Command-line entry point. Installed scripts call this directly."""
    argparser = argparse.ArgumentParser(
        description='Redact IP addresses, namespaces, and query data '
                    'in a MongoDB log file.')
    argparser.add_argument(
        '--seed', '-s', action='store', metavar='S', default=None,
        help='reproduce stand-in names and digests from S. '
             'Without this, every run uses a fresh key.')
    argparser.add_argument(
        '--only', metavar='CATEGORIES', default=None,
        help='comma-separated categories to redact: '
             + ', '.join(CATEGORIES)
             + '. The default is all of them. '
             'Example: --only ip,namespace leaves query text in place.')
    argparser.add_argument(
        '--keep-comment', action='store_true',
        help='leave comment and $comment strings readable so a query '
             'can be traced to the job that sent it. The rest of the '
             'payload is still digested.')
    argparser.add_argument(
        '--debug', action='store_true',
        help='on a line that cannot be redacted, write that line and a '
             'traceback to stderr. Off by default: the line is the data '
             'this tool exists to hide.')
    argparser.add_argument('logfile', type=str)
    args = argparser.parse_args(argv)

    categories = None
    if args.only is not None:
        categories = frozenset(
            part.strip() for part in args.only.split(',') if part.strip())
        unknown = categories.difference(CATEGORIES)
        if not categories or unknown:
            known = ', '.join(CATEGORIES)
            sys.stderr.write(
                f'fruitsalad: --only expects a subset of {known}\n')
            return 2

    try:
        tool = FruitSaladTool(
            arg_seed=args.seed,
            arg_logfile=args.logfile,
            debug=args.debug,
            categories=categories,
            keep_comment=args.keep_comment,
        )
    except (OSError, ValueError) as exc:
        sys.stderr.write(f'fruitsalad: {exc}\n')
        return 1
    # Non-zero when any line was skipped. A redacted file that quietly
    # dropped a line would look complete.
    return 1 if tool.run() else 0


if __name__ == '__main__':
    sys.exit(main())
