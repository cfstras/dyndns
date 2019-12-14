from dyndns.dns_updates import update_dns_record
from dyndns.exceptions import ParameterError
import os
import unittest
from unittest import mock
import _helper


class TestFunctionUpdateDnsRecord(unittest.TestCase):

    def setUp(self):
        os.environ['dyndns_CONFIG_FILE'] = _helper.config_file

    def assertRaisesMsg(self, kwargs, error, msg):
        with self.assertRaises(error) as cm:
            update_dns_record(**kwargs)
        self.assertEqual(str(cm.exception), msg)

    def test_not_all_three_fqdn_etc(self):
        self.assertRaisesMsg(
            {'secret': '12345678', 'fqdn': 'a', 'zone_name': 'b',
             'record_name': 'c'},
            ParameterError,
            'Specify "fqdn" or "zone_name" and "record_name".'
        )

    def test_ip_1_invalid(self):
        self.assertRaisesMsg(
            {'secret': '12345678', 'fqdn': 'www.example.com',
             'ip_1': 'lol'},
            ParameterError,
            'Invalid ip address "lol"',
        )

    def test_ip_2_invalid(self):
        self.assertRaisesMsg(
            {'secret': '12345678', 'fqdn': 'www.example.com',
             'ip_2': 'lol'},
            ParameterError,
            'Invalid ip address "lol"',
        )

    def test_both_ip_same_version(self):
        self.assertRaisesMsg(
            {'secret': '12345678', 'fqdn': 'www.example.com',
             'ip_1': '1.2.3.4', 'ip_2': '1.2.3.4'},
            ParameterError,
            'The attribute "ipv4" is already set and has the value "1.2.3.4".',
        )

    @mock.patch('dns.query.tcp')
    @mock.patch('dns.update.Update')
    @mock.patch('dns.resolver.Resolver')
    def test_ipv4_update(self, Resolver, Update, tcp):
        resolver = Resolver.return_value
        resolver.query.side_effect = [['1.2.3.4'], ['1.2.3.5']]
        update = Update.return_value
        result = update_dns_record(secret='12345678', fqdn='www.example.com',
                                   ip_1='1.2.3.5')
        self.assertEqual(
            result,
            'UPDATED: fqdn: www.example.com. old_ip: 1.2.3.4 new_ip: '
            '1.2.3.5\n',
        )
        update.delete.assert_has_calls([
            mock.call('www.example.com.', 'a'),
            mock.call('www.example.com.', 'aaaa'),
        ])
        update.add.assert_called_with('www.example.com.', 300, 'a', '1.2.3.5')

    @mock.patch('dns.query.tcp')
    @mock.patch('dns.update.Update')
    @mock.patch('dns.resolver.Resolver')
    def test_ipv4_update_user(self, Resolver, Update, tcp):
        resolver = Resolver.return_value
        resolver.query.side_effect = [['1.2.3.4'], ['1.2.3.5']]
        update = Update.return_value
        result = update_dns_record(secret='secret1',
                                   fqdn='user1.with-users.com',
                                   ip_1='1.2.3.5')
        self.assertEqual(
            result,
            'UPDATED: fqdn: user1.with-users.com. old_ip: 1.2.3.4 new_ip: '
            '1.2.3.5\n',
        )
        update.delete.assert_has_calls([
            mock.call('user1.with-users.com.', 'a'),
            mock.call('user1.with-users.com.', 'aaaa'),
        ])
        update.add.assert_called_with(
            'user1.with-users.com.', 300, 'a', '1.2.3.5')

    def test_users_wrong_secret(self):
        self.assertRaisesMsg(
            {'secret': 'secret11', 'fqdn': 'user1.with-users.com',
             'ip_1': '1.2.3.4'},
            ParameterError,
            'You specified a wrong secret key for the zone.',
        )
        self.assertRaisesMsg(
            {'secret': None, 'fqdn': 'user1.with-users.com',
             'ip_1': '1.2.3.4'},
            ParameterError,
            'You specified a wrong secret key for the zone.',
        )
        self.assertRaisesMsg(
            {'secret': '1234', 'fqdn': 'usernotexist.with-users.com',
             'ip_1': '1.2.3.4'},
            ParameterError,
            'You specified a wrong secret key for the zone.',
        )
        self.assertRaisesMsg(
            {'secret': None, 'fqdn': 'usernotexist.with-users.com',
             'ip_1': '1.2.3.4'},
            ParameterError,
            'You specified a wrong secret key for the zone.',
        )

    def test_users_no_global(self):
        self.assertRaisesMsg(
            {'secret': '12345678', 'fqdn': 'usernotexist.with-users.com',
             'ip_1': '1.2.3.4'},
            ParameterError,
            'You specified a wrong secret key for the zone.',
        )
        self.assertRaisesMsg(
            {'secret': '12345678', 'fqdn': 'user1.with-users.com',
             'ip_1': '1.2.3.4'},
            ParameterError,
            'You specified a wrong secret key for the zone.',
        )


if __name__ == '__main__':
    unittest.main()
