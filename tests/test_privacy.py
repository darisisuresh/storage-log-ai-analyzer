import json
import unittest

from storage_log_analyzer.privacy import Redactor


class PrivacyTests(unittest.TestCase):
    def test_nested_schema_preserves_json_and_correlation(self):
        redactor = Redactor()
        record = {
            'hostName': 'private-server',
            'nested': {'device_name': 'private-server', 'tenant-id': 'Acme Corp'},
            'users': [{'userName': 'alice', 'customerName': 'Acme Corp'}],
            'filePath': r'C:\Customers\Acme Corp\file.txt',
            'smbShare': r'\\private-server\Acme Corp',
            'count': 7, 'healthy': True,
        }
        result = json.loads(redactor.redact(json.dumps(record)))
        self.assertEqual(result['hostName'], result['nested']['device_name'])
        self.assertEqual(result['nested']['tenant-id'], result['users'][0]['customerName'])
        self.assertEqual(result['count'], 7)
        self.assertIs(result['healthy'], True)
        for secret in ('private-server', 'Acme Corp', 'alice', 'Customers'):
            self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result['hostName'], json.loads(redactor.redact(json.dumps(record)))['hostName'])

    def test_credentials_cannot_be_allowlisted(self):
        redactor = Redactor(allowed_values=['hunter2', 'private-server'])
        result = redactor.redact_value({
            'host': 'private-server', 'password': 'hunter2',
            'secretAccessKey': 'hunter2', 'access_token': 'hunter2',
            'nested': {'authorization': 'Bearer hunter2'},
        })
        self.assertEqual(result['host'], 'private-server')
        self.assertNotIn('hunter2', json.dumps(result))
        self.assertNotIn('hunter2', redactor.redact('password=hunter2 Authorization: Bearer hunter2'))

    def test_vendor_fields_and_unlabelled_identifiers(self):
        redactor = Redactor(sensitive_fields=['storageCluster'])
        result = redactor.redact_value({'storage_cluster': 'prod-west', 'serialNumber': 'CZ12345', 'wwnn': '20:00:00:25:b5:11:22:33'})
        for secret in ('prod-west', 'CZ12345', '20:00:00:25:b5:11:22:33'):
            self.assertNotIn(secret, json.dumps(result))
        for secret in ('naa.6000097000012345', 'iqn.1993-08.org.debian:private-server', '20:00:00:25:b5:11:22:33', '2001:db8::1', 'fe80::1234%eth0', 'private.example.net'):
            self.assertNotIn(secret, redactor.redact('connected to ' + secret))

    def test_sessions_do_not_publish_reusable_identity_hashes(self):
        self.assertNotEqual(Redactor().redact('host=private-server'), Redactor().redact('host=private-server'))

    def test_jsonl_session_retains_aliases_and_line_boundaries(self):
        redactor = Redactor()
        lines = [redactor.redact(json.dumps({'host': 'server-a', 'token': 'secret'}) + '\n') for _ in range(2)]
        self.assertEqual(lines[0], lines[1])
        self.assertEqual(len(''.join(lines).splitlines()), 2)
        self.assertNotIn('secret', ''.join(lines))
