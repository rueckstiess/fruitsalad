import json
import os
import tempfile
import unittest
import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from fruitsalad import FruitSaladTool, main

class TestFruitSalad(unittest.TestCase):
    ''' Basic tests of fruit salad MongoDB log redacter '''

    def setUp(self):
        self.saved_stdout = sys.stdout
        self.stdout = io.StringIO()
        sys.stdout = self.stdout

    def tearDown(self):
        sys.stdout = self.saved_stdout

    def _assert_matches_fixture(self, expected_path):
        """Compare the whole redacted file.

        zip() stops at the shorter side, so a missing or extra tail
        line used to pass. Both sides are stripped, then compared in
        full, including length.
        """
        actual = [line.strip() for line in self.stdout.getvalue().splitlines()]
        with open(expected_path, encoding='utf-8') as handle:
            expected = [line.strip() for line in handle.read().splitlines()]
        self.assertEqual(expected, actual)

    def test_milliseconds(self):
        ''' Timestamps should be printed unmodified '''
        tool = FruitSaladTool(arg_logfile='test/sample.ts.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        self.assertEqual(output[0], '2017-08-25T22:23:49.097+0000 I COMMAND [conn0]')
        self.assertEqual(output[1], '2017-08-25T22:23:49.007+1000 I COMMAND [conn0]')

    def test_namespace(self):
        ''' Namespaces should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.ts.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        # The database half of test.$cmd is a stand-in. $cmd stays, so
        # the line is still recognisable as a command namespace. The
        # quoted collection name is a digest, not the word test.
        self.assertNotIn('test.$cmd', output[2])
        self.assertNotIn('"test"', output[2])
        self.assertRegex(output[2], r'run command [a-z0-9-]+\.\$cmd \{ find: "[0-9a-f]{32}"')

    def test_ip_public_is_redacted(self):
        ''' A client address is moved into 192.168.0.0/16. The port stays. '''
        tool = FruitSaladTool(arg_logfile='test/sample.ts.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        # sample.ts.log lines 8 and 9 (1-based) are 10.0.0.1. The old test
        # indexed the loopback lines and never looked at these.
        self.assertRegex(
            output[7],
            r'connection accepted from 192\.168\.\d{1,3}\.\d{1,3}:57139 #6 ')
        self.assertRegex(
            output[8],
            r'end connection 192\.168\.\d{1,3}\.\d{1,3}:57139 ')
        self.assertNotIn('10.0.0.1', output[7])
        self.assertNotIn('10.0.0.1', output[8])
        # The same client keeps the same stand-in on both lines.
        accepted = output[7].split('from ', 1)[1].split(' ', 1)[0]
        ended = output[8].split('connection ', 1)[1].split(' ', 1)[0]
        self.assertEqual(accepted, ended)

    def test_ip_loopback_is_kept(self):
        ''' 127.0.0.1 is the local machine, not a client, so it stays. '''
        tool = FruitSaladTool(arg_logfile='test/sample.ts.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        self.assertEqual(output[9], '2017-09-04T16:12:47.997+1000 I NETWORK  [thread1] connection accepted from 127.0.0.1:57139 #6 (1 connection now open)')
        self.assertEqual(output[10], '2017-09-04T16:12:48.001+1000 I -        [conn6] end connection 127.0.0.1:57139 (2 connections now open)')

    def test_2_4(self):
        ''' MongoDB 2.4 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.2.4.log', arg_seed=0)
        tool.run()
        self._assert_matches_fixture('test/sample_redacted.2.4.log')

    def test_2_6(self):
        ''' MongoDB 2.6 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.2.6.log', arg_seed=0)
        tool.run()
        self._assert_matches_fixture('test/sample_redacted.2.6.log')

    def test_3_0(self):
        ''' MongoDB 3.0 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.3.0.log', arg_seed=0)
        tool.run()
        self._assert_matches_fixture('test/sample_redacted.3.0.log')

    def test_3_2(self):
        ''' MongoDB 3.2 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.3.2.log', arg_seed=0)
        tool.run()
        self._assert_matches_fixture('test/sample_redacted.3.2.log')

    def test_3_4(self):
        ''' MongoDB 3.4 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.3.4.log', arg_seed=0)
        tool.run()
        self._assert_matches_fixture('test/sample_redacted.3.4.log')

    def test_4_4(self):
        ''' MongoDB 4.4 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.4.4.log', arg_seed=0)
        tool.run()
        self._assert_matches_fixture('test/sample_redacted.4.4.log')


class TestFailures(unittest.TestCase):
    """Lines we cannot redact must not leak, and must not look successful."""

    def _write(self, text):
        handle = tempfile.NamedTemporaryFile(
            'w', encoding='utf-8', delete=False, suffix='.log')
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def _run(self, text, *extra):
        path = self._write(text)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main([*extra, path])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_empty_file_exits_nonzero(self):
        code, out, err = self._run('')
        self.assertEqual(code, 1)
        self.assertEqual(out, '')
        self.assertIn('empty log file', err)
        self.assertNotIn('IndexError', err)

    def test_bad_json_does_not_echo_the_line(self):
        secret = 'super-secret-value'
        # The file has to look like a JSON log. A line that does not
        # start with "{" is treated as the legacy text format, which
        # has no parse step to fail.
        text = (
            '{not-json "secret":"%s"}\n'
            '{"t":{"$date":"2024-01-01T00:00:00.000+00:00"},"s":"I",'
            '"c":"NETWORK","id":22943,"ctx":"listener",'
            '"msg":"Connection accepted","attr":{"remote":"127.0.0.1:1"}}\n'
        ) % secret
        code, out, err = self._run(text)
        self.assertEqual(code, 1)
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, err)
        self.assertIn('redaction-failed', out)
        # The good line after the bad one is still redacted and emitted.
        self.assertIn('Connection accepted', out)

    def test_debug_opts_in_to_the_raw_line(self):
        secret = 'super-secret-value'
        text = '{not-json "secret":"%s"}\n' % secret
        code, out, err = self._run(text, '--debug')
        self.assertEqual(code, 1)
        self.assertNotIn(secret, out)
        self.assertIn(secret, err)

    def test_find_and_modify_update_document_is_hashed(self):
        # "update" is a collection name on the update command and the
        # update document on findAndModify. The document used to raise
        # AttributeError and abort the file.
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {
                'ns': 'app.users',
                'command': {
                    'findAndModify': 'users',
                    'query': {'email': 'a@b.c'},
                    'update': {'$set': {'name': 'Ada Lovelace'}},
                    '$db': 'app',
                },
            },
        }) + '\n'
        code, out, err = self._run(text, '--seed', '0')
        self.assertEqual(code, 0, err)
        self.assertNotIn('Ada Lovelace', out)
        self.assertNotIn('a@b.c', out)
        self.assertNotIn('"users"', out)
        doc = json.loads(out)
        self.assertIsInstance(doc['attr']['command']['update'], str)

    def test_aggregate_sentinel_is_not_a_collection_name(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {
                'ns': 'admin.aggregate',
                'command': {
                    'aggregate': 1,
                    'pipeline': [{'$currentOp': {'allUsers': True}}],
                    '$db': 'admin',
                },
            },
        }) + '\n'
        code, out, err = self._run(text, '--seed', '0')
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        # The integer 1 means "no collection". It must survive as a number.
        self.assertEqual(doc['attr']['command']['aggregate'], 1)
        self.assertNotIn('allUsers', out)

    def test_insert_documents_and_sasl_payload_are_hashed(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {
                'ns': 'app.users',
                'command': {
                    'insert': 'users',
                    'documents': [{
                        'email': 'ada@example.com',
                        'ssn': '123-45-6789',
                    }],
                    'updates': [{
                        'q': {'email': 'ada@example.com'},
                        'u': {'$set': {'x': 1}},
                    }],
                    'payload': 'secretpayloadbase64',
                    '$db': 'app',
                },
            },
        }) + '\n'
        code, out, err = self._run(text, '--seed', '0')
        self.assertEqual(code, 0, err)
        self.assertNotIn('ada@example.com', out)
        self.assertNotIn('123-45-6789', out)
        self.assertNotIn('secretpayloadbase64', out)

    def test_stats_filter_is_digested_and_no_none_line_is_injected(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {
                'ns': 'db.coll',
                'stats': {
                    'stage': 'COLLSCAN',
                    'nReturned': 1,
                    'filter': {'email': 'ada@example.com'},
                },
            },
        }) + '\n'
        code, out, err = self._run(text, '--seed', '0')
        self.assertEqual(code, 0, err)
        # A missing explain path used to print a literal "none" line
        # and then the original predicate.
        self.assertEqual(len(out.splitlines()), 1)
        self.assertNotIn('ada@example.com', out)
        self.assertIn('COLLSCAN', out)

    def test_ipv6_is_moved_under_the_unique_local_prefix(self):
        def remote(value):
            return json.dumps({
                't': {'$date': '2024-01-01T00:00:00.000+00:00'},
                's': 'I', 'c': 'NETWORK', 'id': 22943, 'ctx': 'listener',
                'msg': 'Connection accepted',
                'attr': {'remote': value, 'connectionId': 1},
            }) + '\n'

        code, out, err = self._run(remote('[2001:db8::1]:27017'), '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('2001:db8', out)
        self.assertIn('fd00::', out)
        self.assertIn(':27017', out)
        code, loopback, err = self._run(remote('[::1]:27017'), '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertIn('[::1]:27017', loopback)

    def test_keep_comment_leaves_the_comment_and_digests_the_rest(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {
                'ns': 'app.users',
                'command': {
                    'find': 'users',
                    'filter': {
                        'email': 'ada@example.com',
                        '$comment': 'nightly-job',
                    },
                    '$db': 'app',
                },
            },
        }) + '\n'
        code, kept, err = self._run(text, '--seed', '1', '--keep-comment')
        self.assertEqual(code, 0, err)
        self.assertIn('nightly-job', kept)
        self.assertNotIn('ada@example.com', kept)
        code, hidden, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('nightly-job', hidden)
        self.assertNotIn('ada@example.com', hidden)

    def test_only_ip_leaves_the_query_and_the_namespace(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {
                'ns': 'app.users',
                'remote': '10.1.2.3:27017',
                'command': {
                    'find': 'users',
                    'filter': {'email': 'ada@example.com'},
                    '$db': 'app',
                },
            },
        }) + '\n'
        code, out, err = self._run(text, '--only', 'ip', '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertIn('ada@example.com', out)
        self.assertIn('app.users', out)
        self.assertNotIn('10.1.2.3', out)
        self.assertIn('192.168.', out)
        code, out, err = self._run(text, '--only', 'not-a-category')
        self.assertEqual(code, 2)
        self.assertIn('--only', err)

    def test_same_query_changes_digest_when_the_seed_changes(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {
                'ns': 'app.users',
                'command': {
                    'find': 'users',
                    'filter': {'email': 'ada@example.com'},
                    '$db': 'app',
                },
            },
        }) + '\n'
        first = json.loads(self._run(text, '--seed', '1')[1])
        second = json.loads(self._run(text, '--seed', '1')[1])
        other = json.loads(self._run(text, '--seed', '2')[1])
        self.assertEqual(
            first['attr']['command']['filter'],
            second['attr']['command']['filter'])
        self.assertNotEqual(
            first['attr']['command']['filter'],
            other['attr']['command']['filter'])
        # The database stand-in and the collection stand-in come from
        # different word lists, and $db uses the database one, so the
        # two halves of app.users agree with the command fields.
        ns = first['attr']['ns']
        database, collection = ns.split('.')
        self.assertEqual(first['attr']['command']['$db'], database)
        self.assertEqual(first['attr']['command']['find'], collection)
        self.assertNotIn('.', database)
        self.assertNotIn('.', collection)

    def test_client_metadata_hides_the_app_and_the_host(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'NETWORK', 'id': 51800, 'ctx': 'conn1',
            'msg': 'client metadata',
            'attr': {
                'remote': '10.1.2.3:50000',
                'appName': 'billing-worker',
                'doc': {
                    'application': {'name': 'payroll-svc'},
                    'driver': {'name': 'PyMongo', 'version': '4.9.0'},
                    'os': {'hostname': 'payments-prod-7.internal',
                           'type': 'Linux'},
                },
            },
        }) + '\n'
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('billing-worker', out)
        self.assertNotIn('payroll-svc', out)
        self.assertNotIn('payments-prod-7', out)
        self.assertNotIn('10.1.2.3', out)
        # The driver name is how you tell which client misbehaved.
        self.assertIn('PyMongo', out)
        self.assertIn('4.9.0', out)
        self.assertIn('Linux', out)

    def test_internal_user_is_kept(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'ACCESS', 'id': 20250, 'ctx': 'conn1',
            'msg': 'Authentication succeeded',
            'attr': {
                'mechanism': 'SCRAM-SHA-256',
                'principalName': '__system',
                'authenticationDatabase': 'local',
            },
        }) + '\n'
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual(document['attr']['principalName'], '__system')
        self.assertEqual(document['attr']['authenticationDatabase'], 'local')

    def test_text_log_digests_quoted_shell_values_and_leaves_bare_ones(self):
        # Shell documents quote strings and ObjectIds, and leave
        # identifiers and numbers bare. A full shell parser is
        # intentionally not part of this script; the bare `key: 1.0`
        # is the gap that remains.
        text = (
            '2017-01-01T00:00:00.000+0000 I WRITE [conn1] insert test.test '
            "query: { _id: ObjectId('59aceec3c250e507159808f0'), "
            "name: 'Ada Lovelace', key: 1.0 }\n"
        )
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('59aceec3c250e507159808f0', out)
        self.assertNotIn('Ada Lovelace', out)
        self.assertNotIn('test.test', out)
        self.assertIn('key: 1.0', out)

    def test_checked_in_samples_do_not_contain_their_secrets(self):
        with open('test/sample_redacted.4.4.log', encoding='utf-8') as handle:
            redacted_4_4 = handle.read()
        for secret in (
            'Connection reset by peer', '1.2.3.4', '1.2.5.6', 'secret_user',
            'test.collection', 'hidden_field', 'sekrit', 'coll_1', 'coll_2',
            'some_field', '/secret/', 'MongoDB Shell',
        ):
            self.assertNotIn(secret, redacted_4_4, secret)
        self.assertIn('HostUnreachable', redacted_4_4)
        self.assertIn('IXSCAN', redacted_4_4)
        self.assertIn('"_id_"', redacted_4_4)
        with open('test/sample_redacted.3.4.log', encoding='utf-8') as handle:
            redacted_3_4 = handle.read()
        self.assertNotIn('59aceec3c250e507159808f0', redacted_3_4)
        self.assertNotIn('10.0.0.1', redacted_3_4)
        self.assertNotIn('host=local', redacted_3_4)
        self.assertIn('admin.system.version', redacted_3_4)
        self.assertIn('key: 1.0', redacted_3_4)

    def test_seed_is_stable_and_optional(self):
        text = json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': 'Slow query',
            'attr': {'ns': 'app.users', 'remote': '10.9.8.7:27017'},
        }) + '\n'
        first = self._run(text, '--seed', '1')[1]
        second = self._run(text, '--seed', '1')[1]
        other = self._run(text, '--seed', '2')[1]
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        # No --seed means a fresh RNG stream. Five draws all matching
        # would mean None was still being turned into the string "None".
        unseeded = {self._run(text)[1] for _ in range(5)}
        self.assertGreater(len(unseeded), 1)

    def _json_line(self, attr, msg='Slow query'):
        return json.dumps({
            't': {'$date': '2024-01-01T00:00:00.000+00:00'},
            's': 'I', 'c': 'COMMAND', 'id': 51803, 'ctx': 'conn1',
            'msg': msg,
            'attr': attr,
        }) + '\n'

    def test_ipv4_at_the_edge_of_a_line_is_redacted(self):
        text = self._json_line({}, msg='Accepted from 10.9.8.7')
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('10.9.8.7', out)
        self.assertIn('192.168.', out)
        code, out, err = self._run('10.9.8.7 connected\n', '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('10.9.8.7', out)
        self.assertIn('192.168.', out)
        # Loopback at the same position stays. It names this machine.
        code, out, err = self._run('127.0.0.1 connected\n', '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertIn('127.0.0.1', out)

    def test_ipv4_mapped_and_bare_loopback(self):
        mapped = self._json_line({'remote': '[::ffff:10.1.2.3]:27017'})
        code, out, err = self._run(mapped, '--only', 'ip', '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('10.1.2.3', out)
        self.assertIn('192.168.', out)
        self.assertIn(':27017', out)
        self.assertIn('::ffff:', out)
        bare = self._json_line({'remote': '::1'})
        code, out, err = self._run(bare, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertIn('"remote": "::1"', out)
        expanded = self._json_line({'remote': '[::0001]:27017'})
        code, out, err = self._run(expanded, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertIn('[::1]:27017', out)

    def test_plan_summary_dotted_field_is_tokenised(self):
        text = self._json_line({
            'planSummary': 'IXSCAN { user.email: 1, ssn: 1 }',
        })
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        summary = json.loads(out)['attr']['planSummary']
        self.assertNotIn('user', summary)
        self.assertNotIn('email', summary)
        self.assertNotIn('ssn', summary)
        self.assertIn('IXSCAN', summary)
        self.assertIn(': 1', summary)
        # Both labels of the dotted path are stand-ins, so the literal
        # prefix is gone and the braces still hold a path.
        inside = summary.split('{', 1)[1]
        self.assertRegex(inside, r'[a-z0-9-]+\.[a-z0-9-]+: 1')

    def test_projection_validator_and_parsed_query_are_digested(self):
        text = self._json_line({
            'command': {
                'findAndModify': 'users',
                'fields': {'ssn': 1, 'name': 1},
                'query': {'email': 'ada@example.com'},
                '$db': 'app',
            },
            'validator': {
                'properties': {'ssn': {'bsonType': 'string'}},
            },
            'parsedQuery': {'age': {'$gt': 30}},
        })
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertNotIn('ssn', out)
        self.assertNotIn('ada@example.com', out)
        document = json.loads(out)
        self.assertIsInstance(document['attr']['parsedQuery'], str)
        self.assertNotIn('age', document['attr']['parsedQuery'])
        self.assertIsInstance(document['attr']['validator'], str)
        self.assertIsInstance(
            document['attr']['command']['fields'], str)

    def test_mmap_datafile_hides_the_database_and_keeps_versions(self):
        text = (
            'db version v3.4.7\n'
            'Darwin Kernel Version 10.8.0\n'
            'allocating new datafile /data/db/production.0, filling\n'
            'allocating new datafile /data/db/local.0, filling\n'
            'allocating new datafile /data/db/production.1, filling\n'
        )
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        self.assertIn('v3.4.7', out)
        self.assertIn('10.8.0', out)
        self.assertIn('/data/db/local.0', out)
        self.assertNotIn('production', out)
        self.assertRegex(out, r'/data/db/[a-z0-9-]+\.0')
        self.assertRegex(out, r'/data/db/[a-z0-9-]+\.1')

    def test_keep_comment_digests_a_document_comment(self):
        text = self._json_line({
            'command': {
                'find': 'users',
                'filter': {'a': 1},
                'comment': {'email': 'ada@example.com'},
                '$db': 'app',
            },
        })
        code, out, err = self._run(text, '--seed', '1', '--keep-comment')
        self.assertEqual(code, 0, err)
        self.assertNotIn('ada@example.com', out)
        self.assertNotIn('email', out)
        # A string comment is still readable, and still stays out of
        # the digest of the rest of the filter.
        commented = self._json_line({
            'command': {
                'find': 'users',
                'filter': {'a': 1, '$comment': 'nightly-job'},
                '$db': 'app',
            },
        })
        code, kept, err = self._run(commented, '--seed', '1', '--keep-comment')
        self.assertEqual(code, 0, err)
        self.assertIn('nightly-job', kept)

    def test_id_index_name_is_kept(self):
        text = self._json_line({
            'index': '_id_',
            'indexName': '_id_',
            'name': '_id_',
        })
        code, out, err = self._run(text, '--seed', '1')
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual(document['attr']['index'], '_id_')
        self.assertEqual(document['attr']['indexName'], '_id_')
        self.assertEqual(document['attr']['name'], '_id_')

    def test_invalid_utf8_does_not_drop_the_rest_of_the_file(self):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
        handle.write(
            b'{"t":{"$date":"2024-01-01T00:00:00.000+00:00"},'
            b'"s":"I","c":"N","id":1,"ctx":"c","msg":"before"}\n'
        )
        handle.write(b'\xff not-valid-utf8\n')
        handle.write(
            b'{"t":{"$date":"2024-01-01T00:00:00.000+00:00"},'
            b'"s":"I","c":"N","id":1,"ctx":"c","msg":"after"}\n'
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main([handle.name])
        out, err = stdout.getvalue(), stderr.getvalue()
        self.assertEqual(code, 1)
        self.assertIn('before', out)
        self.assertIn('after', out)
        self.assertIn('redaction-failed', out)
        self.assertNotIn('Traceback', err)
        self.assertIn('invalid UTF-8', err)


if __name__ == '__main__':
    unittest.main()