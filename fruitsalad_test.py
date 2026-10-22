import unittest
import io
import sys
from fruitsalad import FruitSaladTool

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


if __name__ == '__main__':
    unittest.main()