import unittest
import io
import sys
from fruitsalad import FruitSaladTool

class TestFruitSalad(unittest.TestCase):
    ''' Basic tests of fruit salad MongoDB log redacter '''

    def setUp(self):
        self.saved_stdout = sys.stdout
        self.stdout = io.BytesIO()
        sys.stdout = self.stdout

    def tearDown(self):
        sys.stdout = self.saved_stdout

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
        self.assertEqual(output[2], '2017-09-04T12:07:36.596+1000 D COMMAND  [conn6] run command sandybrown.$cmd { find: "303b5c8988601647873b4ffd247d83cb", filter: { key: 1.0 } }')

    def test_ip_1(self):
        ''' IP addresses not 127.0.0.1 should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.ts.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        self.assertEqual(output[7], '2017-09-04T16:12:47.997+1000 I NETWORK  [thread1] connection accepted from 192.168.148.231:57139 #6 (1 connection now open)')
        self.assertEqual(output[8], '2017-09-04T16:12:48.001+1000 I -        [conn6] end connection 192.168.148.231:57139 (2 connections now open)')

    def test_ip_2(self):
        ''' IP addresses 127.0.0.1 should not be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.ts.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        self.assertEqual(output[9], '2017-09-04T16:12:47.997+1000 I NETWORK  [thread1] connection accepted from 127.0.0.1:57139 #6 (1 connection now open)')
        self.assertEqual(output[10], '2017-09-04T16:12:48.001+1000 I -        [conn6] end connection 127.0.0.1:57139 (2 connections now open)')

    def test_2_4(self):
        ''' MongoDB 2.4 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.2.4.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        for sample in zip([line.strip() for line in open('test/sample_redacted.2.4.log', 'r')], output):
            self.assertEqual(sample[0], sample[1])

    def test_2_6(self):
        ''' MongoDB 2.6 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.2.6.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        for sample in zip([line.strip() for line in open('test/sample_redacted.2.6.log', 'r')], output):
            self.assertEqual(sample[0], sample[1])

    def test_3_0(self):
        ''' MongoDB 3.0 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.3.0.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        for sample in zip([line.strip() for line in open('test/sample_redacted.3.0.log', 'r')], output):
            self.assertEqual(sample[0], sample[1])

    def test_3_2(self):
        ''' MongoDB 3.2 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.3.2.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        for sample in zip([line.strip() for line in open('test/sample_redacted.3.2.log', 'r')], output):
            self.assertEqual(sample[0], sample[1])

    def test_3_4(self):
        ''' MongoDB 3.4 log file should be redacted '''
        tool = FruitSaladTool(arg_logfile='test/sample.3.4.log', arg_seed=0)
        tool.run()
        output = self.stdout.getvalue().split('\n')
        for sample in zip([line.strip() for line in open('test/sample_redacted.3.4.log', 'r')], output):
            self.assertEqual(sample[0], sample[1])