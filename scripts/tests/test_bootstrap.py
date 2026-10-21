import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import tarfile
import tempfile
import threading
import unittest

from test_acme import pem_pair

ROOT = Path(__file__).resolve().parents[2]
REVISION = '446c99a88dd40ebe7ea29f1689729e2a9c25a099'
CHECKSUM = 'c44d9a764c2f65ea1a0c5d9053a203331d3d2819e9c1b008cc06480bf0bd8072'


def payload(extra=None):
    # Only the controller boundary is fake; download, checksum, extraction,
    # argument forwarding and cleanup run through the actual standalone script.
    files = {'scripts/manage.py': b'import json,sys\nfrom pathlib import Path\nprint(json.dumps({"args":sys.argv[1:],"root":str(Path(__file__).resolve().parents[1])}))\n',
             'scripts/acme.py': b'# fixture\n',
             'go.mod': b'module github.com/balamutik/familychat-push-gateway\n'}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, data in files.items():
            member = tarfile.TarInfo('familychat-push-gateway-'+REVISION+'/'+name)
            member.size = len(data)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
        if extra is not None:
            archive.addfile(extra)
    return stream.getvalue()


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        cert, key = pem_pair(self.root, host='127.0.0.1')
        self.body = payload()
        self.redirect = None
        self.requests = []
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(self.path)
                if owner.redirect:
                    self.send_response(302)
                    self.send_header('Location', owner.redirect)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header('Content-Length',str(len(owner.body)))
                self.end_headers()
                self.wfile.write(owner.body)
            def log_message(self, *_):
                pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert,key)
        self.server.socket = context.wrap_socket(self.server.socket,server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.env = dict(os.environ, SSL_CERT_FILE=str(cert), TMPDIR=str(self.root))
        self.url = f'https://127.0.0.1:{self.server.server_port}/archive/'

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def run_installer(self, *args, checksum=None):
        script = (ROOT/'install.sh').read_text().replace(
            'https://github.com/balamutik/familychat-push-gateway/archive/', self.url).replace(
            CHECKSUM, checksum or hashlib.sha256(self.body).hexdigest())
        installer = self.root/'install.sh'
        installer.write_text(script)
        return subprocess.run(['bash',str(installer),*args],cwd=self.root,env=self.env,capture_output=True,text=True,timeout=15)

    def test_single_script_downloads_verifies_forwards_arguments_and_cleans_up(self):
        result = self.run_installer('install','--domain','push.example.com','--apns-key','/root/key with spaces.p8')
        self.assertEqual(result.returncode,0,result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['args'],['install','--domain','push.example.com','--apns-key','/root/key with spaces.p8'])
        self.assertFalse(Path(value['root']).exists(),'Temporary payload must be removed after the controller exits')
        self.assertEqual(self.requests,['/archive/'+REVISION+'.tar.gz'])

    def test_bad_checksum_never_executes_payload(self):
        result = self.run_installer(checksum='0'*64)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('SHA-256',result.stderr)
        self.assertFalse(result.stdout)

    def test_links_and_traversal_are_rejected_before_extraction(self):
        for name, kind, link in (('../escaped',tarfile.REGTYPE,''),
                                 ('familychat-push-gateway-'+REVISION+'/link',tarfile.SYMTYPE,'/etc')):
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, link
                self.body = payload(member)
                result = self.run_installer()
                self.assertNotEqual(result.returncode,0)
                self.assertIn('Небезопасный архив',result.stderr)
                self.assertFalse(result.stdout)
                self.assertFalse((self.root/'escaped').exists())

    def test_https_cannot_redirect_to_http(self):
        self.redirect = f'http://127.0.0.1:{self.server.server_port}/insecure'
        result = self.run_installer()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('HTTPS',result.stderr)
        self.assertEqual(len(self.requests),1)


if __name__ == '__main__':
    unittest.main()
