import argparse
import http.server
import importlib
import json
import os
from pathlib import Path
import stat
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from test_acme import config, pem_pair
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    manage = importlib.import_module('manage')
except ModuleNotFoundError:
    manage = None

SOURCE = Path(__file__).resolve().parents[2]


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(manage, 'Gateway installer has not been implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.install = self.root / 'installed'
        self.cert, self.key = pem_pair(self.root)
        self.key.chmod(0o600)

    def args(self, *extra):
        return manage.parser().parse_args(['install', '--domain', 'push.example.com', '--email', 'owner@example.com',
            '--client', 'acme.sh', '--challenge', 'webroot', '--webroot', str(self.root),
            '--install-dir', str(self.install), '--source', str(SOURCE),
            '--apns-key', str(self.key), '--apns-key-id', 'KEY1234567', '--apns-team-id', 'TEAM123456',
            '--apns-topic', 'com.example.chat', *extra])

    def test_provider_keys_are_validated_and_copied_with_private_modes(self):
        self.install.mkdir()
        args = self.args()
        with mock.patch.object(manage.os, 'chown'):
            settings = manage.configure_providers(vars(args), self.install)
        installed = self.install / 'secrets/apns.p8'
        self.assertEqual(installed.read_bytes(), self.key.read_bytes())
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o400)
        self.assertEqual(settings['APNS_KEY_FILE'], '/run/gateway-secrets/apns.p8')
        self.assertEqual(settings['APNS_TOPIC'], 'com.example.chat')
        self.key.write_text('invalid private key')
        with self.assertRaises(ValueError):
            manage.configure_providers(vars(args), self.install)
        self.assertNotEqual(installed.read_bytes(), self.key.read_bytes())

    def test_fcm_project_mismatch_never_installs_credentials(self):
        credentials = self.root / 'fcm.json'
        credentials.write_text(json.dumps({'project_id':'wrong','client_email':'test@example.com','private_key':'fake'}))
        credentials.chmod(0o600)
        with self.assertRaises(ValueError):
            manage.configure_providers({'fcm_credentials':str(credentials), 'fcm_project_id':'wanted',
                                        'fcm_application_id':'com.example.chat'}, self.install)
        self.assertFalse((self.install / 'secrets/fcm.json').exists())

    def test_both_platforms_import_valid_provider_keys(self):
        key = subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048'],
                             check=True, capture_output=True).stdout.decode()
        account = {'type':'service_account','project_id':'familychat-test','client_email':'test@example.com','private_key':key}
        credentials = self.root/'fcm.json'
        credentials.write_text(json.dumps(account))
        credentials.chmod(0o600)
        args = self.args('--fcm-credentials', str(credentials), '--fcm-project-id','familychat-test',
                         '--fcm-application-id','com.example.chat')
        with mock.patch.object(manage.os, 'chown'):
            settings = manage.configure_providers(vars(args), self.install)
        self.assertEqual(settings['FCM_CREDENTIALS_FILE'], '/run/gateway-secrets/fcm.json')
        self.assertEqual(json.loads((self.install/'secrets/fcm.json').read_text()), account)
        self.assertEqual(stat.S_IMODE((self.install/'secrets/fcm.json').stat().st_mode), 0o400)
        self.assertEqual((self.install/'secrets/apns.p8').read_bytes(), self.key.read_bytes())

    def test_bad_dns_credentials_do_not_leave_partial_provider_install(self):
        args = self.args('--dns-env', str(self.root/'missing.env'))
        with mock.patch.object(manage.acme, 'ensure_docker'), mock.patch.object(manage.acme, 'ensure_acme'), \
                mock.patch.object(manage.acme, 'ensure_port_available'), mock.patch.object(manage.os, 'chown'):
            with self.assertRaises(OSError):
                manage.install(args)
        self.assertFalse((self.install/'secrets/apns.p8').exists())

    def test_explicit_zero_port_is_rejected(self):
        with self.assertRaises(ValueError):
            manage.collect_config(self.args('--port','0'))

    def test_install_root_inside_source_is_rejected_before_writing(self):
        args = self.args()
        args.source = str(self.root/'checkout')
        args.install_dir = str(self.root/'checkout/scripts/managed')
        with mock.patch.object(manage.acme, 'ensure_docker', side_effect=AssertionError('Unsafe layout was accepted')):
            with self.assertRaises(ValueError):
                manage.install(args)
        self.assertFalse(Path(args.install_dir).exists())

    def test_health_uses_local_service_with_domain_certificate_verification(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            def log_message(self, *_):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.dict(os.environ, {'CURL_CA_BUNDLE':str(self.cert), 'SSL_CERT_FILE':str(self.cert)}), \
                    mock.patch.object(manage.time, 'sleep'):
                manage.health_check(config(self.install, port=server.server_port))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_install_and_reinstall_preserve_state_and_use_managed_tls(self):
        calls = []
        commands = []
        def certificate(cfg, renew=False):
            with mock.patch.object(manage.acme.os, 'chown'):
                manage.acme.publish_pair(cfg, self.cert, self.key if self.key.exists() else self.install/'secrets/apns.p8')
        with mock.patch.object(manage.acme, 'ensure_docker'), mock.patch.object(manage.acme, 'ensure_acme'), \
                mock.patch.object(manage.acme, 'command', side_effect=lambda args,**kwargs: commands.append(tuple(args))), \
                mock.patch.object(manage.acme, 'ensure_port_available'), mock.patch.object(manage.acme.os, 'chown'), \
                mock.patch.object(manage.acme, 'certificate', side_effect=certificate), \
                mock.patch.object(manage, 'compose', side_effect=lambda root,*args: calls.append(args)), \
                mock.patch.object(manage, 'install_timer'), mock.patch.object(manage, 'health_check'):
            manage.install(self.args())
            state = self.install / 'data/state.json'
            state.write_text('{"clients":{"existing":"keep"},"devices":{"phone":"keep"}}')
            previous = state.read_bytes()
            # Migrate a previous source-build installation while preserving provider settings.
            env_path = self.install/'.env'
            old_env = [line for line in env_path.read_text().splitlines() if not line.startswith('PUSH_GATEWAY_IMAGE=')]
            env_path.write_text('PUSH_BUILD_CONTEXT=./app\n'+'\n'.join(old_env)+'\n')
            # Retry without needing the original external provider key file.
            self.key.unlink()
            args = manage.parser().parse_args(['install', '--install-dir', str(self.install), '--source', str(SOURCE)])
            manage.install(args)
            self.assertEqual(state.read_bytes(), previous)
        env = (self.install / '.env').read_text()
        self.assertFalse(any('build' in call for call in calls), 'Installation must never compile an image on the VPS')
        pulls = [call for call in commands if call[:2] == ('docker','pull')]
        self.assertEqual(len(pulls),2)
        self.assertRegex(pulls[0][2], r'^ghcr\.io/balamutik/familychat-push-gateway@sha256:[a-f0-9]{64}$')
        self.assertIn('PUSH_GATEWAY_IMAGE='+pulls[0][2],env)
        self.assertNotIn('PUSH_BUILD_CONTEXT',env)
        self.assertIn('PUSH_HTTPS_PORT=9443', env)
        self.assertIn('PUSH_TLS_CERT=/run/gateway-secrets/tls.pem', env)
        self.assertIn('PUSH_TLS_KEY=/run/gateway-secrets/tls.pem', env)
        self.assertTrue((self.install / 'app/install.sh').is_file())
        self.assertTrue((self.install / 'app/scripts/renew.sh').is_file())
        self.assertEqual(json.loads((self.install / 'deploy.json').read_text())['domain'], 'push.example.com')
        self.assertFalse(any('down' in call for call in calls))

    def test_failed_certificate_can_be_retried_without_deleting_state(self):
        with mock.patch.object(manage.acme, 'ensure_docker'), mock.patch.object(manage.acme, 'ensure_acme'), \
                mock.patch.object(manage.acme, 'command'), \
                mock.patch.object(manage.acme, 'ensure_port_available'), mock.patch.object(manage.acme.os, 'chown'), \
                mock.patch.object(manage.acme, 'certificate', side_effect=RuntimeError('CA unavailable')), \
                mock.patch.object(manage, 'compose'), mock.patch.object(manage, 'install_timer'):
            with self.assertRaisesRegex(RuntimeError, 'CA unavailable'):
                manage.install(self.args())
        self.assertTrue((self.install / 'pending.json').is_file())
        self.assertFalse((self.install / 'deploy.json').exists())
        self.assertTrue((self.install / 'secrets/apns.p8').is_file())
        provider = (self.install/'secrets/apns.p8').read_bytes()
        state = self.install/'data/state.json'
        state.write_text('{"pending":"keep"}')
        self.key.unlink()
        env = self.install/'.env'
        env.write_text('PUSH_BUILD_CONTEXT=./app\n'+'\n'.join(line for line in env.read_text().splitlines() if not line.startswith('PUSH_GATEWAY_IMAGE='))+'\n')
        args = manage.parser().parse_args(['install','--install-dir',str(self.install),'--source',str(SOURCE)])
        with mock.patch.object(manage.acme,'ensure_docker'), mock.patch.object(manage.acme,'ensure_acme'), \
                mock.patch.object(manage.acme,'command'), mock.patch.object(manage.acme,'certificate'), \
                mock.patch.object(manage,'compose'), mock.patch.object(manage,'health_check'), \
                mock.patch.object(manage,'install_timer'):
            manage.install(args)
        self.assertEqual((self.install/'secrets/apns.p8').read_bytes(),provider)
        self.assertEqual(state.read_text(),'{"pending":"keep"}')
        self.assertFalse((self.install/'pending.json').exists())
        self.assertEqual(json.loads((self.install/'deploy.json').read_text())['image'],manage.image_reference(SOURCE))
        self.assertNotIn('PUSH_BUILD_CONTEXT',env.read_text())

    def test_managed_compose_ignores_inherited_image_override(self):
        with mock.patch.dict(os.environ, {'PUSH_GATEWAY_IMAGE':'busybox:latest'}), \
                mock.patch.object(manage.acme, 'command') as command:
            manage.compose(self.install, 'config', '--quiet')
        self.assertNotIn('PUSH_GATEWAY_IMAGE', command.call_args.kwargs['env'])
        self.assertEqual(command.call_args.kwargs['env']['PATH'], os.environ['PATH'])

    def test_failed_image_pull_keeps_previous_configuration_and_data(self):
        self.install.mkdir()
        manage.acme.private_json(self.install/'deploy.json', config(self.install))
        (self.install/'.env').write_text('PUSH_BUILD_CONTEXT=./app\nAPNS_TOPIC=com.example.chat\n')
        (self.install/'compose.yaml').write_text('existing compose configuration\n')
        (self.install/'data').mkdir()
        (self.install/'data/state.json').write_text('{"preserve":"existing registrations"}')
        previous = {name:(self.install/name).read_bytes() for name in ('.env','compose.yaml','data/state.json','deploy.json')}
        args = manage.parser().parse_args(['update','--install-dir',str(self.install),'--source',str(SOURCE)])
        with mock.patch.object(manage.acme,'ensure_docker'), mock.patch.object(manage.acme,'ensure_acme'), \
                mock.patch.object(manage.acme,'command',side_effect=RuntimeError('registry unavailable')), \
                mock.patch.object(manage.acme,'certificate'), mock.patch.object(manage,'compose'), \
                mock.patch.object(manage,'health_check'), mock.patch.object(manage,'install_timer'):
            with self.assertRaisesRegex(RuntimeError,'registry unavailable'):
                manage.install(args)
        for name,data in previous.items():
            self.assertEqual((self.install/name).read_bytes(),data,name)

    def test_only_official_digest_pinned_image_manifest_is_accepted(self):
        self.assertTrue(hasattr(manage,'image_reference'),'Pinned image manifest loader is missing')
        manifest = self.root/'image.json'
        official = 'ghcr.io/balamutik/familychat-push-gateway@sha256:'+'a'*64
        for image in ('ghcr.io/balamutik/familychat-push-gateway:latest', 'evil.example/image@sha256:'+'a'*64, official+'\nENV=bad'):
            manifest.write_text(json.dumps({'image':image,'revision':'b'*40}))
            with self.assertRaises(ValueError):
                manage.image_reference(self.root)
        manifest.write_text(json.dumps({'image':official,'revision':'b'*40}))
        self.assertEqual(manage.image_reference(self.root),official)

    def test_new_provider_and_address_on_reinstall_are_not_silently_ignored(self):
        self.install.mkdir()
        manage.acme.private_json(self.install/'deploy.json', config(self.install))
        args = self.args()
        args.domain = '8.8.8.8'
        with self.assertRaises(ValueError):
            manage.install(args)

    def test_timer_keeps_custom_install_path_and_daily_renewal(self):
        units = self.root / 'units'
        units.mkdir()
        with mock.patch.object(manage, 'SYSTEMD_DIR', units), mock.patch.object(manage, 'systemd_available', return_value=True), \
                mock.patch.object(manage.acme, 'command'):
            manage.install_timer(self.install)
        services = list(units.glob('*.service'))
        timers = list(units.glob('*.timer'))
        self.assertEqual(len(services), 1)
        self.assertEqual(len(timers), 1)
        self.assertIn(str(self.install / 'app/scripts/renew.sh'), services[0].read_text())
        self.assertIn('OnCalendar=daily', timers[0].read_text())


if __name__ == '__main__':
    unittest.main()
