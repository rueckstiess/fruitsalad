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

        zip() stops at the shorter side, so a dropped line or an extra
        'none' line used to pass. Both sides are stripped the way the
        original assertions were, then compared in full, including length.
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
        self.assertEqual(output[2], '2017-09-04T12:07:36.596+1000 D COMMAND  [conn6] run command mistyrose.$cmd { find: "303b5c8988601647873b4ffd247d83cb", filter: { key: 1.0 } }')

    def test_ip_public_is_redacted(self):
        ''' A client address is moved into 192.168.0.0/16. The port stays. '''
        tool = FruitSaladTool(arg_logfile='test/sample.ts.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        # sample.ts.log lines 8 and 9 (1-based) are 10.0.0.1. The old test
        # indexed the loopback lines and never looked at these.
        self.assertEqual(
            output[7],
            '2017-09-04T16:12:47.997+1000 I NETWORK  [thread1] connection accepted from 192.168.214.96:57139 #6 (1 connection now open)')
        self.assertEqual(
            output[8],
            '2017-09-04T16:12:48.001+1000 I -        [conn6] end connection 192.168.214.96:57139 (2 connections now open)')
        self.assertNotIn('10.0.0.1', output[7])
        self.assertNotIn('10.0.0.1', output[8])

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

    def test_stats_does_not_inject_a_none_line(self):
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
        self.assertEqual(out.splitlines(), [out.strip()])
        self.assertNotEqual(out.strip(), 'none')

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


if __name__ == '__main__':
    unittest.main()