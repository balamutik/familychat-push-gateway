import importlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    acme = importlib.import_module('acme')
except ModuleNotFoundError:
    acme = None


def config(root, **changes):
    return dict(install_dir=str(root), domain='push.example.com', email='owner@example.com', port=9443,
                client='certbot', challenge='standalone', webroot=None, dns_provider=None,
                dns_env=None, certbot_dns_args=None, acme_binary=str(root / 'client/acme.sh')) | changes


def pem_pair(root, name='one', host='push.example.com'):
    cert, key = root / (name + '.crt'), root / (name + '.key')
    san = 'IP:' + host if host[0].isdigit() else 'DNS:' + host
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-days', '2', '-subj', '/CN=' + host, '-addext', 'subjectAltName=' + san,
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    return cert, key


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(acme, 'ACME installer support has not been implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_existing_relative_acme_path_is_rejected_before_it_is_saved(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            binary = Path(directory)/'acme.sh'
            binary.write_text('#!/bin/sh\nexit 0\n')
            cfg = config(self.root, client='acme.sh', acme_binary=os.path.relpath(binary))
            with self.assertRaises(ValueError):
                acme.validate(cfg)
            with self.assertRaises(ValueError):
                acme.ensure_acme(cfg)

    def test_public_ip_uses_required_shortlived_profile_but_dns_does_not(self):
        for client in ('certbot', 'acme.sh'):
            ip = config(self.root, domain='8.8.8.8', client=client)
            acme.validate(ip)
            args = acme.issue_command(ip)
            self.assertIn('shortlived', args)
            if client == 'certbot':
                self.assertEqual(args[args.index('--ip-address') + 1], '8.8.8.8')
                self.assertIn('--required-profile', args)
            else:
                self.assertEqual(args[args.index('--days') + 1], '3')
            dns = acme.issue_command(config(self.root, client=client))
            self.assertNotIn('shortlived', dns)
            self.assertEqual(dns[dns.index('-d') + 1], 'push.example.com')

    def test_invalid_identifiers_and_ip_dns_challenge_are_rejected(self):
        for host in ('127.0.0.1', '10.0.0.1', '100.64.0.1', '224.0.0.1', '8.8.8.08',
                     '2606:4700:4700::1111', 'https://push.example.com', 'a..example.com',
                     'bad.example.com\nENV=value', '--bad.example.com'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                acme.validate(config(self.root, domain=host))
        with self.assertRaisesRegex(ValueError, 'DNS-01'):
            acme.validate(config(self.root, domain='8.8.8.8', challenge='dns', client='acme.sh', dns_provider='dns_cf'))

    def test_certificate_publication_checks_identity_and_key_before_replacement(self):
        cert, key = pem_pair(self.root)
        cfg = config(self.root)
        with mock.patch.object(acme.os, 'chown'):
            acme.publish_pair(cfg, cert, key)
        bundle = self.root / 'secrets/tls.pem'
        previous = bundle.read_bytes()
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(bundle)
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o400)
        wrong_cert, wrong_key = pem_pair(self.root, 'wrong', 'other.example.com')
        for candidate, private_key in ((wrong_cert, wrong_key), (cert, wrong_key)):
            with self.subTest(cert=candidate), mock.patch.object(acme.os, 'chown'), self.assertRaises(ValueError):
                acme.publish_pair(cfg, candidate, private_key)
            self.assertEqual(bundle.read_bytes(), previous)

    def test_ipv4_san_is_checked_as_ip_not_dns(self):
        cert, key = pem_pair(self.root, host='8.8.8.8')
        with mock.patch.object(acme.os, 'chown'):
            acme.publish_pair(config(self.root, domain='8.8.8.8'), cert, key)
        self.assertTrue((self.root / 'secrets/tls.pem').exists())
        with mock.patch.object(acme.os, 'chown'), self.assertRaises(ValueError):
            acme.publish_pair(config(self.root, domain='1.1.1.1'), cert, key)

    def test_acme_issue_and_not_due_renewal_use_private_home_and_keep_profile(self):
        cert, key = pem_pair(self.root, host='8.8.8.8')
        binary = self.root / 'client/acme.sh'
        binary.parent.mkdir()
        trace = self.root / 'trace.jsonl'
        binary.write_text(f'#!{sys.executable}\n' + f'''import json, os, pathlib, shutil, sys
args = sys.argv[1:]
assert not any(k.startswith('SUDO_') for k in os.environ)
home = pathlib.Path(args[args.index('--config-home') + 1])
assert home.is_dir() and home.stat().st_mode & 0o077 == 0
with open({str(trace)!r}, 'a') as out: out.write(json.dumps(args) + '\\n')
if '--install-cert' in args:
 shutil.copyfile({str(cert)!r}, args[args.index('--fullchain-file')+1])
 shutil.copyfile({str(key)!r}, args[args.index('--key-file')+1])
sys.exit(2 if '--renew' in args else 0)
''')
        binary.chmod(0o700)
        cfg = config(self.root, client='acme.sh', domain='8.8.8.8')
        with mock.patch.dict(os.environ, {'SUDO_COMMAND': 'sudo bash install.sh --client acme.sh'}), \
                mock.patch.object(acme.os, 'geteuid', return_value=0), mock.patch.object(acme.os, 'chown'), mock.patch.object(acme.os, 'fchown'), \
                mock.patch.object(acme, 'ensure_port_available'):
            acme.certificate(cfg)
            acme.certificate(cfg, renew=True)
        calls = [json.loads(line) for line in trace.read_text().splitlines()]
        self.assertEqual(len(calls), 5)
        for args in calls:
            self.assertNotIn('--force', args)
            if '--issue' in args or '--renew' in args:
                self.assertIn('shortlived', args)
                self.assertEqual(args[args.index('--days') + 1], '3')
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(self.root / 'secrets/tls.pem')

    def test_old_certbot_fails_before_ip_issuance(self):
        with mock.patch.object(acme.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='old certbot')):
            with self.assertRaisesRegex(RuntimeError, 'IP'):
                acme.require_ip_support(config(self.root, domain='8.8.8.8'))

    def test_port_conflict_preserves_existing_listener(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with self.assertRaises(RuntimeError):
                acme.ensure_port_available(port)
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                pass

    def test_dns_credentials_are_data_and_must_be_private(self):
        path = self.root / 'dns.env'
        path.write_text('CF_Token=$(do-not-run)\n')
        path.chmod(0o600)
        self.assertEqual(acme.read_dns_env(path)['CF_Token'], '$(do-not-run)')
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            acme.read_dns_env(path)


if __name__ == '__main__':
    unittest.main()
