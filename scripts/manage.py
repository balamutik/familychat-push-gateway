#!/usr/bin/env python3
"""Install and renew a dedicated FamilyChat push gateway on Ubuntu/Debian."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

import acme

SOURCE = Path(__file__).resolve().parents[1]
DEFAULT_INSTALL = '/opt/familychat-push-gateway'
SYSTEMD_DIR = Path('/etc/systemd/system')
PROVIDER_OPTIONS = ('apns_key', 'apns_key_id', 'apns_team_id', 'apns_topic', 'apns_sandbox',
                    'fcm_credentials', 'fcm_project_id', 'fcm_application_id')


def atomic_write(path, data, mode=0o600, owner=None):
    fd, temporary = tempfile.mkstemp(prefix='.install-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        if owner is not None:
            os.chown(temporary, owner, owner)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def configure_providers(values, root):
    settings, files = {}, []
    if any(values.get(name) for name in PROVIDER_OPTIONS[:5]):
        key, key_id, team, topic = (values.get(name) for name in PROVIDER_OPTIONS[:4])
        if not key or not re.fullmatch(r'[A-Z0-9]{10}', key_id or '') or not re.fullmatch(r'[A-Z0-9]{10}', team or ''):
            raise ValueError('Для APNs нужны приватный .p8 и Key ID / Team ID из 10 букв или цифр')
        if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', topic or '') or len(topic) > 255:
            raise ValueError('Укажите корректный APNs Bundle ID')
        source = acme.restricted_file(key)
        if source.stat().st_size > 16384:
            raise ValueError('APNs ключ слишком большой')
        data = source.read_bytes()
        try:
            public = subprocess.run(['openssl', 'pkey', '-passin', 'pass:', '-pubout', '-outform', 'DER'],
                                    input=data, check=True, capture_output=True).stdout
        except subprocess.CalledProcessError:
            raise ValueError('Некорректный APNs приватный ключ') from None
        prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')
        if not data.startswith(b'-----BEGIN PRIVATE KEY-----') or len(public) != 91 or not public.startswith(prefix):
            raise ValueError('APNs требует незашифрованный ключ PKCS#8 EC P-256')
        files.append(('apns.p8', data))
        settings.update(APNS_KEY_FILE='/run/gateway-secrets/apns.p8', APNS_KEY_ID=key_id,
                        APNS_TEAM_ID=team, APNS_TOPIC=topic, APNS_SANDBOX='true' if values.get('apns_sandbox') else 'false')
    if any(values.get(name) for name in PROVIDER_OPTIONS[5:]):
        credentials, project, application = (values.get(name) for name in PROVIDER_OPTIONS[5:])
        if not credentials or not re.fullmatch(r'[a-z][a-z0-9-]{4,62}', project or '') or not re.fullmatch(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+', application or ''):
            raise ValueError('Для FCM нужны credentials JSON, Project ID и Android application ID')
        source = acme.restricted_file(credentials)
        if source.stat().st_size > 65536:
            raise ValueError('FCM credentials слишком большой')
        data = source.read_bytes()
        try:
            account = json.loads(data)
            private = account['private_key'].encode()
            if account.get('type') != 'service_account' or account.get('project_id') != project or not account.get('client_email'):
                raise ValueError()
            result = subprocess.run(['openssl', 'rsa', '-passin', 'pass:', '-check', '-noout'],
                                    input=private, check=True, capture_output=True)
            public = subprocess.run(['openssl', 'rsa', '-passin', 'pass:', '-pubout', '-outform', 'DER'],
                                    input=private, check=True, capture_output=True).stdout
            if result.returncode or len(public) < 294 or not private.startswith(b'-----BEGIN PRIVATE KEY-----'):
                raise ValueError()
        except (KeyError, TypeError, AttributeError, ValueError, subprocess.CalledProcessError):
            raise ValueError('FCM credentials должен содержать service account указанного проекта и приватный RSA ключ от 2048 бит') from None
        files.append(('fcm.json', data))
        settings.update(FCM_CREDENTIALS_FILE='/run/gateway-secrets/fcm.json', FCM_PROJECT_ID=project, FCM_APPLICATION_ID=application)
    if not files:
        raise ValueError('Настройте хотя бы один push-провайдер: APNs или FCM')
    acme.protect_tree(root / 'secrets', 10001)
    for name, data in files:
        atomic_write(root / 'secrets' / name, data, 0o400, 10001)
    return settings


def compose(root, *args):
    acme.command(['docker', 'compose', '--project-directory', root, '--env-file', root / '.env',
                  '-f', root / 'compose.yaml', *args])


def copy_source(source, root):
    source = Path(source).resolve()
    target = root / 'app'
    if source != target.resolve():
        staging = Path(tempfile.mkdtemp(prefix='.app-', dir=root))
        try:
            for name in ('go.mod', 'Dockerfile', '.dockerignore', '.gitignore', 'compose.yaml', '.env.example', 'README.md', 'install.sh', 'cmd', 'internal', 'scripts'):
                path = source / name
                if path.is_symlink() or (path.is_dir() and any(p.is_symlink() for p in path.rglob('*'))):
                    raise ValueError('Исходники установщика не должны содержать символические ссылки')
                if path.is_dir():
                    shutil.copytree(path, staging / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
                else:
                    shutil.copy2(path, staging / name)
            if target.is_symlink():
                raise ValueError('Каталог app не должен быть ссылкой')
            if target.exists():
                shutil.rmtree(target)
            staging.rename(target)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    shutil.copy2(target / 'compose.yaml', root / 'compose.yaml')


def systemd_available():
    return bool(shutil.which('systemctl')) and Path('/run/systemd/system').is_dir()


def install_timer(root):
    if not systemd_available():
        print(f'systemd недоступен. Добавьте ежедневный запуск от root: {root}/app/scripts/renew.sh --install-dir {root}')
        return
    name = 'familychat-push-renew-' + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    service = '[Unit]\nDescription=Renew FamilyChat push TLS certificate\n[Service]\nType=oneshot\nUMask=0077\nExecStart=' + str(root/'app/scripts/renew.sh') + ' --install-dir ' + str(root) + '\n'
    timer = '[Unit]\nDescription=Daily FamilyChat push TLS renewal\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n'
    atomic_write(SYSTEMD_DIR/(name+'.service'), service.encode(), 0o644)
    atomic_write(SYSTEMD_DIR/(name+'.timer'), timer.encode(), 0o644)
    acme.command(['systemctl', 'daemon-reload'])
    acme.command(['systemctl', 'enable', '--now', name+'.timer'])


def health_check(config):
    # Probe this host even behind NAT, while curl verifies the public identity.
    origin = f"https://{config['domain']}:{config['port']}"
    address = f"{config['domain']}:{config['port']}:127.0.0.1"
    for _ in range(15):
        try:
            response = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--noproxy', '*',
                '--proto', '=https', '--max-time', '3', '--resolve', address, origin+'/health/live'],
                check=True, capture_output=True)
            if json.loads(response.stdout) == {'status':'ok'}:
                return
        except (OSError, ValueError, subprocess.CalledProcessError):
            pass
        time.sleep(1)
    raise RuntimeError('Шлюз запущен, но локальная HTTPS-проверка не прошла. Проверьте сертификат, порт и логи Docker; настройки сохранены для повторного запуска')


def load_config(root, name='deploy.json'):
    value = json.loads(acme.restricted_file(root / name).read_text())
    if Path(value['install_dir']).resolve() != root.resolve():
        raise ValueError('Каталог установки не соответствует сохранённой конфигурации')
    acme.validate(value)
    return value


def collect_config(args):
    values = vars(args).copy()
    for name, question, default in (
        ('domain', 'Домен или публичный IPv4 push-шлюза:', None),
        ('email', 'Email для сертификата:', None),
        ('client', 'Клиент сертификатов: certbot или acme.sh [acme.sh]:', 'acme.sh'),
        ('challenge', 'Проверка: standalone, webroot или dns [standalone]:', 'standalone')):
        if not values.get(name):
            values[name] = acme.prompt(question) or default
    values['port'] = 9443 if values.get('port') is None else values['port']
    values['acme_binary'] = values.get('acme_binary') or '/root/.acme.sh/acme.sh'
    if not any(values.get(name) for name in PROVIDER_OPTIONS):
        provider = acme.prompt('Платформы: ios, android или both:').lower()
        if provider not in ('ios','android','both'):
            raise ValueError('Выберите ios, android или both')
        if provider in ('ios','both'):
            for name, question in (('apns_key','Путь к APNs .p8 (0400/0600):'), ('apns_key_id','Apple Key ID:'), ('apns_team_id','Apple Team ID:'), ('apns_topic','Bundle ID iOS:')):
                values[name] = acme.prompt(question)
            values['apns_sandbox'] = acme.prompt('Сборка iOS: production или development [production]:').lower() == 'development'
        if provider in ('android','both'):
            for name, question in (('fcm_credentials','Путь к Firebase service account JSON (0400/0600):'), ('fcm_project_id','Firebase Project ID:'), ('fcm_application_id','Android application ID:')):
                values[name] = acme.prompt(question)
    acme.validate(values)
    return values


def persist_dns(config, root):
    if config.get('dns_env'):
        values = acme.read_dns_env(config['dns_env'])
        atomic_write(root/'dns.env', ''.join(f'{name}={value}\n' for name,value in values.items()).encode())
        config['dns_env'] = str(root/'dns.env')
    if config.get('certbot_dns_args'):
        args = acme.dns_args(config)
        for index, arg in enumerate(args):
            if arg.startswith('--dns-') and arg.endswith('-credentials'):
                if index+1 >= len(args):
                    raise ValueError('После DNS credentials укажите путь к файлу')
                private = acme.restricted_file(args[index+1])
                atomic_write(root/'dns-credentials.ini', private.read_bytes())
                args[index+1] = str(root/'dns-credentials.ini')
        acme.private_json(root/'certbot-dns-args.json', args)
        config['certbot_dns_args'] = str(root/'certbot-dns-args.json')


def install(args):
    root = Path(args.install_dir).resolve()
    source = Path(args.source).resolve()
    if source != root/'app' and (root == source or root in source.parents or source in root.parents):
        raise ValueError('Каталог установки должен быть отдельным от исходников')
    existing = next((name for name in ('deploy.json','pending.json') if (root/name).is_file()), None)
    if existing:
        config = load_config(root, existing)
        for name in ('domain','email','client','challenge','port','webroot','dns_provider','dns_env','certbot_dns_args','acme_binary'):
            value = getattr(args,name,None)
            if value is not None and value != config.get(name):
                raise ValueError('Для повторной установки используйте сохранённые настройки без новых параметров адреса или сертификата')
        if any(getattr(args,name,None) for name in PROVIDER_OPTIONS):
            raise ValueError('Провайдеры уже сохранены. Повторите без параметров ключей: они не заменяются при обновлении')
    else:
        if args.command == 'update':
            raise ValueError('Сначала выполните install')
        if root.exists() and any(p.name != '.manage.lock' for p in root.iterdir()):
            raise ValueError('Каталог не пуст и не содержит управляемой установки. Выберите другой --install-dir')
        config = collect_config(args)
        config['install_dir'] = str(root)
    if not existing:
        if config.get('dns_env'):
            acme.read_dns_env(config['dns_env'])
        if config.get('certbot_dns_args'):
            dns = acme.dns_args(config)
            for index, argument in enumerate(dns):
                if argument.startswith('--dns-') and argument.endswith('-credentials'):
                    if index + 1 >= len(dns):
                        raise ValueError('После DNS credentials укажите путь к файлу')
                    acme.restricted_file(dns[index+1])
    acme.ensure_docker()
    dependencies = ['openssl','curl']
    if config['client'] == 'acme.sh' and config['challenge'] == 'standalone':
        dependencies.append('socat')
    missing = [name for name in dependencies if not shutil.which(name)]
    if missing:
        acme.install_packages(missing)
    acme.ensure_acme(config)
    if not existing:
        acme.ensure_port_available(config['port'])
        if config['challenge'] == 'standalone':
            acme.ensure_port_available(80)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        settings = configure_providers(config, root)
        for name in ('data','export'):
            acme.protect_tree(root/name, 10001)
        persist_dns(config, root)
        env = {'PUSH_BUILD_CONTEXT':'./app','PUSH_HTTPS_PORT':str(config['port']),
               'PUSH_TLS_CERT':'/run/gateway-secrets/tls.pem','PUSH_TLS_KEY':'/run/gateway-secrets/tls.pem', **settings}
        atomic_write(root/'.env', ''.join(f'{name}={value}\n' for name,value in env.items()).encode())
        config = {key:value for key,value in config.items() if key not in PROVIDER_OPTIONS and key not in ('source','command')}
        acme.private_json(root/'pending.json', config)
    copy_source(source, root)
    compose(root, 'config', '--quiet')
    compose(root, 'build', 'gateway')
    acme.certificate(config, renew=existing == 'deploy.json')
    compose(root, 'up', '-d', '--no-build', '--wait', '--wait-timeout', '60', 'gateway')
    health_check(config)
    acme.private_json(root/'deploy.json', config)
    (root/'pending.json').unlink(missing_ok=True)
    install_timer(root)
    print(f"Push-шлюз установлен: https://{config['domain']}:{config['port']}\nКаталог: {root}\nДля продления: sudo {root}/app/scripts/renew.sh --install-dir {root}")


@contextmanager
def deployment_lock(root):
    if root.is_symlink():
        raise ValueError('Каталог установки не должен быть ссылкой')
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    with open(root/'.manage.lock', 'a') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def parser():
    cli = argparse.ArgumentParser(description='Установка HTTPS push-шлюза FamilyChat (порт по умолчанию 9443)')
    actions = cli.add_subparsers(dest='command', required=True)
    for action in ('install','update'):
        sub = actions.add_parser(action, description='Сертификат для домена или публичного IPv4; приложение слушает 9443')
        address = sub.add_mutually_exclusive_group()
        address.add_argument('--domain', help='DNS-имя или публичный IPv4')
        address.add_argument('--ip', dest='domain', help='Публичный IPv4 без порта')
        for option in ('email','client','challenge','webroot','dns-provider','dns-env','certbot-dns-args','acme-binary',*('apns-key','apns-key-id','apns-team-id','apns-topic','fcm-credentials','fcm-project-id','fcm-application-id')):
            sub.add_argument('--'+option)
        sub.add_argument('--port', type=int, help='Порт HTTPS (по умолчанию 9443)')
        sub.add_argument('--apns-sandbox', action='store_true', default=None)
        sub.add_argument('--source', default=str(SOURCE))
        sub.add_argument('--install-dir', default=DEFAULT_INSTALL)
    renew = actions.add_parser('renew')
    renew.add_argument('--install-dir', default=DEFAULT_INSTALL)
    return cli


def main():
    os.umask(0o077)
    args = parser().parse_args()
    acme.validate_install_dir(args.install_dir)
    if os.geteuid() != 0:
        raise RuntimeError('Запустите установку через sudo на Ubuntu/Debian')
    acme.system_release()
    root = Path(args.install_dir).resolve()
    with deployment_lock(root):
        if args.command == 'renew':
            config = load_config(root)
            acme.require_ip_support(config)
            acme.certificate(config, renew=True)
        else:
            install(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print('Ошибка: ' + ('Внешняя команда завершилась с ошибкой; проверьте вывод выше' if isinstance(error, subprocess.CalledProcessError) else str(error)), file=sys.stderr)
        sys.exit(1)
