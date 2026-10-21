#!/usr/bin/env python3
"""ACME and system setup adapted from FamilyChat keyserver's installer."""
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

ACME_COMMIT = "807da6498377ee5e0cf43a78091f46f12dc59a89"
ACME_SHA256 = "ddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220"

def command(args, **kwargs):
    # Never print commands: imported file paths/DNS arguments may be sensitive.
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def acme_environment(base=None):
    env = dict(os.environ if base is None else base)
    if os.geteuid() == 0:
        # This controller already runs as root. Inherited sudo arguments such as
        # '--client acme.sh' otherwise trigger acme.sh's interactive sudo guard.
        env = {name: value for name, value in env.items() if not name.startswith('SUDO_')}
        env['HOME'] = pwd.getpwuid(0).pw_dir
    return env


def prompt(message):
    try:
        with open('/dev/tty', 'w', encoding='utf-8') as output, open('/dev/tty', 'rb', buffering=0) as terminal:
            while True:
                output.write(message + ' ')
                output.flush()
                raw = terminal.readline()
                if not raw:
                    raise RuntimeError('Ввод прерван')
                try:
                    return raw.decode('utf-8').strip()
                except UnicodeDecodeError:
                    output.write('Некорректная кодировка. Введите ответ заново.\n')
    except OSError as error:
        raise RuntimeError('Нет терминала /dev/tty. Укажите параметры явно; зависимости установите заранее') from error


def approve(message):
    if prompt(message + ' [y/N]').lower() not in ('y', 'yes', 'д', 'да'):
        raise RuntimeError('Установка отменена. Подтверждение не получено')


def install_packages(packages):
    approve('Установить пакеты: ' + ', '.join(packages) + '?')
    command(['apt-get', 'update'])
    command(['apt-get', 'install', '-y', *packages])


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('HTTPS redirect required')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, limit=16 << 20):
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise ValueError('HTTPS required')
    request = urllib.request.Request(url, headers={'User-Agent': 'FamilyChat-push-gateway-installer'})
    with urllib.request.build_opener(HTTPSRedirect()).open(request, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Слишком большой установочный файл')
    return data


def system_release():
    if sys.platform != 'linux':
        raise RuntimeError('Поддерживаются Ubuntu и Debian')
    info = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    distro, codename = info.get('ID', '').strip('"'), info.get('VERSION_CODENAME', '').strip('"')
    if distro not in ('ubuntu', 'debian') or not re.fullmatch(r'[a-z]+', codename):
        raise RuntimeError('Поддерживаются Ubuntu и Debian с VERSION_CODENAME')
    return distro, codename


def compose_supported():
    try:
        result = subprocess.run(['docker', 'compose', 'version', '--short'], check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    match = re.match(r'v?(\d+)\.(\d+)\.(\d+)', result.stdout.strip())
    return bool(match and tuple(map(int, match.groups())) >= (2, 24, 4))


def installed_package(name):
    result = subprocess.run(['dpkg-query', '-W', '-f=${Status}', name], capture_output=True, text=True)
    return result.returncode == 0 and result.stdout.strip() == 'install ok installed'


def ensure_docker():
    if not shutil.which('docker'):
        distro, codename = system_release()
        approve('Docker отсутствует. Установить Docker Engine и Compose из официального apt-репозитория Docker?')
        command(['apt-get', 'update'])
        command(['apt-get', 'install', '-y', 'ca-certificates'])
        key = Path('/etc/apt/keyrings/docker.asc')
        key.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        key.write_bytes(download(f'https://download.docker.com/linux/{distro}/gpg', limit=1 << 20))
        key.chmod(0o644)
        arch = subprocess.run(['dpkg', '--print-architecture'], check=True, capture_output=True, text=True).stdout.strip()
        if arch not in ('amd64', 'arm64'):
            raise RuntimeError('Релиз поддерживает только amd64 и arm64')
        source = Path('/etc/apt/sources.list.d/docker.sources')
        source.write_text(f'Types: deb\nURIs: https://download.docker.com/linux/{distro}\nSuites: {codename}\nComponents: stable\nArchitectures: {arch}\nSigned-By: {key}\n')
        source.chmod(0o644)
        command(['apt-get', 'update'])
        command(['apt-get', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin', 'docker-compose-plugin'])
        command(['systemctl', 'enable', '--now', 'docker'])
    command(['docker', 'info'], stdout=subprocess.DEVNULL)
    if not compose_supported():
        distro, _ = system_release()
        if installed_package('docker-ce-cli'):
            package = 'docker-compose-plugin'
        elif installed_package('docker.io'):
            package = 'docker-compose-v2' if distro == 'ubuntu' else 'docker-compose'
        else:
            raise RuntimeError('Установите Compose plugin >=2.24.4 из того же источника, что существующий Docker')
        install_packages([package])
        if not compose_supported():
            raise RuntimeError('Требуется Docker Compose plugin >=2.24.4')


def ensure_acme(config):
    if config['client'] == 'certbot':
        if not shutil.which('certbot'):
            install_packages(['certbot'])
        require_ip_support(config)
        return
    binary = Path(config['acme_binary'])
    if not binary.is_absolute() or binary.name != 'acme.sh':
        raise ValueError('--acme-binary должен быть абсолютным путём к acme.sh')
    if binary.is_file():
        require_ip_support(config)
        return
    approve('Установить официальный acme.sh 3.1.6 с проверкой SHA-256 в ' + str(binary.parent) + '?')
    missing = [name for name in ('curl', 'openssl', 'socat') if not shutil.which(name)]
    if missing:
        install_packages(missing)
    data = download('https://codeload.github.com/acmesh-official/acme.sh/tar.gz/' + ACME_COMMIT)
    if hashlib.sha256(data).hexdigest() != ACME_SHA256:
        raise ValueError('SHA256 архива acme.sh не совпадает')
    with tempfile.TemporaryDirectory(prefix='familychat-acme-') as temporary:
        root = Path(temporary)
        prefix = 'acme.sh-' + ACME_COMMIT
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            total, members = 0, []
            for member in archive:
                path = Path(member.name)
                total += member.size
                if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != prefix or not (member.isfile() or member.isdir()) or total > 32 << 20 or len(members) >= 2048:
                    raise ValueError('Небезопасный архив acme.sh')
                members.append(member)
            for member in members:
                target = root / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
                    target.chmod(0o700)
        command(['sh', root / prefix / 'acme.sh', '--install', '--home', binary.parent, '--nocron', '--noprofile', '--accountemail', config['email']], cwd=root / prefix, env=acme_environment())
    if not binary.is_file():
        raise RuntimeError('acme.sh не установлен')
    require_ip_support(config)


def ip_address(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def require_ip_support(config):
    if ip_address(config['domain']) is None:
        return
    if config['client'] == 'certbot':
        args, flags = ['certbot', '--help', 'all'], ('--ip-address', '--required-profile')
        message = 'Для IP-сертификата обновите certbot (поддержка IP в 5.4+) либо выберите --client acme.sh'
    else:
        args, flags = [config['acme_binary'], '--help'], ('--certificate-profile', '--days')
        message = 'Для IP-сертификата обновите acme.sh: требуется поддержка --certificate-profile и --days'
    result = subprocess.run(args, check=True, capture_output=True, text=True,
                            env=acme_environment() if config['client'] == 'acme.sh' else None)
    if not all(flag in result.stdout for flag in flags):
        raise RuntimeError(message)


def private_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".push-gateway-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(value, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def restricted_file(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"Файл {path.name} должен быть обычным файлом с правами 0600 или 0400")
    return path


def read_dns_env(path):
    values = {}
    for line in restricted_file(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("DNS env: ожидаются строки NAME=value без export и команд shell")
        values[name] = value
    return values


def validate(config):
    domain = config["domain"]
    if not isinstance(domain, str):
        raise ValueError("Укажите DNS-имя или публичный IP-адрес")
    address = ip_address(domain)
    if address is not None:
        if address.version != 4:
            raise ValueError('Клиент сервера чатов поддерживает IPv4; для IPv6 используйте DNS-имя')
        if not address.is_global or address.is_multicast or '%' in domain:
            raise ValueError("Для сертификата нужен публичный IP-адрес сервера")
        if config['challenge'] == 'dns':
            raise ValueError("DNS-01 не подтверждает IP-адрес. Выберите standalone или webroot с доступным портом 80")
    elif re.fullmatch(r'[0-9.]+', domain) or len(domain) > 253 or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", domain
    ) or "." not in domain or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in domain.split(".")):
        raise ValueError("Укажите DNS-имя или публичный IP без https://, порта и пути, например push.example.com")
    if not isinstance(config["port"], int) or not 1024 <= config["port"] <= 65535 or config["port"] == 8080:
        raise ValueError("Порт push-шлюза должен быть отдельным: 1024–65535, кроме 8080. По умолчанию 9443; 80/443 не используются приложением")
    if config["client"] not in ("certbot", "acme.sh") or config["challenge"] not in ("standalone", "webroot", "dns"):
        raise ValueError("Выберите certbot/acme.sh и standalone/webroot/dns")
    if config['client'] == 'acme.sh':
        binary = Path(config['acme_binary'])
        if not binary.is_absolute() or binary.name != 'acme.sh':
            raise ValueError('--acme-binary должен быть абсолютным путём к acme.sh')
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", config["email"]):
        raise ValueError("Укажите email для сертификата")
    validate_install_dir(config["install_dir"])
    if config["challenge"] == "webroot" and not config.get("webroot"):
        raise ValueError("Для webroot укажите --webroot: существующий каталог, доступный по HTTP на порту 80")
    if config["challenge"] == "webroot" and (not Path(config['webroot']).is_absolute() or not Path(config['webroot']).is_dir()):
        raise ValueError('Webroot должен быть существующим абсолютным каталогом')
    if config["challenge"] == "dns":
        if config["client"] == "acme.sh" and not re.fullmatch(r"dns_[A-Za-z0-9_]+", config.get("dns_provider") or ""):
            raise ValueError("Для DNS с acme.sh укажите --dns-provider, например dns_cf")
        if config["client"] == "certbot" and not config.get("certbot_dns_args"):
            raise ValueError("Для DNS с certbot укажите --certbot-dns-args: JSON файл с параметрами установленного DNS-плагина")


def validate_install_dir(value):
    root = Path(value)
    if not root.is_absolute() or str(root) == "/" or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(root)):
        raise ValueError("Каталог установки должен быть абсолютным путём без пробелов и специальных символов")
    if root.resolve() == Path("/"):
        raise ValueError("Корневой каталог не может быть каталогом установки")


def ensure_port_available(port):
    # Binding is only a preflight. No process is ever stopped or reconfigured.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("0.0.0.0", port))
        except OSError as error:
            raise RuntimeError(f"Порт {port} занят. Существующие сервисы не изменены. Для ACME выберите webroot или DNS, для приложения — другой отдельный порт") from error


def certbot_base(config):
    base = Path(config["install_dir"]) / "acme/certbot"
    return ["certbot", "--config-dir", str(base / "config"), "--work-dir", str(base / "work"), "--logs-dir", str(base / "logs")]


def acme_base(config):
    return [config["acme_binary"], "--config-home", str(Path(config["install_dir"]) / "acme/acme.sh"),
            "--home", str(Path(config["acme_binary"]).parent)]


def dns_args(config):
    path = restricted_file(config["certbot_dns_args"])
    args = json.loads(path.read_text())
    if not isinstance(args, list) or not args or not all(isinstance(item, str) and "\n" not in item for item in args):
        raise ValueError("DNS параметры certbot должны быть непустым JSON-массивом строк")
    # Credentials are filenames understood by the installed certbot DNS plugin.
    if not any(arg.startswith("--dns-") for arg in args):
        raise ValueError("DNS параметры certbot должны включать --dns-<provider>")
    forbidden = ("--config", "--logs", "--work", "--cert-name", "--domain", "--email", "--standalone", "--webroot", "--manual", "--hook", "--deploy", "--pre-hook", "--post-hook", "--server")
    if any(arg.startswith(forbidden) or arg == "-d" for arg in args):
        raise ValueError("В DNS файле разрешены только параметры DNS-плагина, без доменов, путей ACME и hooks")
    return args


def issue_command(config):
    if config["client"] == "certbot":
        args = certbot_base(config) + ["certonly", "--non-interactive", "--agree-tos", "--email", config["email"], "--cert-name", "familychat-push-gateway", "--keep-until-expiring"]
        if ip_address(config['domain']) is not None:
            args += ['--required-profile', 'shortlived', '--ip-address', config['domain']]
        else:
            args += ['-d', config['domain']]
        if config["challenge"] == "standalone":
            args += ["--standalone", "--preferred-challenges", "http"]
        elif config["challenge"] == "webroot":
            args += ["--webroot", "--webroot-path", config["webroot"]]
        else:
            args += dns_args(config)
        return args
    args = acme_base(config) + ["--issue", "--server", "letsencrypt", "--keylength", "ec-256", "-d", config["domain"]]
    if ip_address(config['domain']) is not None:
        args += ['--certificate-profile', 'shortlived', '--days', '3']
    if config["challenge"] == "standalone":
        args += ["--standalone"]
    elif config["challenge"] == "webroot":
        args += ["--webroot", config["webroot"]]
    else:
        args += ["--dns", config["dns_provider"]]
    return args


def protect_tree(path, owner=None):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Закрытый каталог не может быть символической ссылкой")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in [path] + list(path.rglob("*")):
        if entry.is_symlink():
            continue
        entry.chmod(0o700 if entry.is_dir() else 0o600)
        if owner is not None:
            os.chown(entry, owner, owner)


def publish_pair(config, certificate_path, key_path):
    cert, key = Path(certificate_path), Path(key_path)
    try:
        san = subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-ext', 'subjectAltName'],
                             check=True, capture_output=True, text=True).stdout
        is_ip = ip_address(config['domain']) is not None
        if ('IP Address:' if is_ip else 'DNS:') not in san:
            raise ValueError('Сертификат должен содержать subjectAltName')
        subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout',
                        '-checkip' if is_ip else '-checkhost', config['domain']], check=True, capture_output=True)
        subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0'], check=True, capture_output=True)
        cert_public = subprocess.run(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'],
                                     check=True, capture_output=True).stdout
        key_public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-passin', 'pass:', '-pubout'],
                                    check=True, capture_output=True).stdout
        if cert_public != key_public:
            raise ValueError('Сертификат и приватный ключ не совпадают')
    except subprocess.CalledProcessError:
        raise ValueError('Сертификат просрочен, не подходит адресу или содержит некорректный ключ') from None
    destination = Path(config['install_dir']) / 'secrets'
    protect_tree(destination, 10001)
    fd, temporary = tempfile.mkstemp(prefix='.tls-', dir=destination)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(cert.read_bytes().rstrip() + b'\n' + key.read_bytes().rstrip() + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o400)
            os.fchown(stream.fileno(), 10001, 10001) if os.geteuid() == 0 else None
        os.replace(temporary, destination / 'tls.pem')
    finally:
        Path(temporary).unlink(missing_ok=True)


def publish_certificate(config):
    root = Path(config['install_dir'])
    if config['client'] == 'certbot':
        lineage = root / 'acme/certbot/config/live/familychat-push-gateway'
    else:
        # acme.sh remembers these output paths for automatic renewals: keep them stable.
        lineage = root / 'acme/published'
        protect_tree(lineage)
        command(acme_base(config) + ['--install-cert', '--ecc', '-d', config['domain'],
                '--key-file', lineage / 'privkey.pem', '--fullchain-file', lineage / 'fullchain.pem'],
                env=acme_environment())
    publish_pair(config, lineage / 'fullchain.pem', lineage / 'privkey.pem')


def certificate(config, renew=False):
    acme_dir = Path(config['install_dir']) / 'acme'
    protect_tree(acme_dir)
    if config['client'] == 'acme.sh':
        # acme.sh touches http.header before creating its configuration home.
        protect_tree(acme_dir / 'acme.sh')
    env = os.environ.copy()
    if config.get("dns_env"):
        env.update(read_dns_env(config["dns_env"]))
    if config['client'] == 'acme.sh':
        env = acme_environment(env)
    if config["challenge"] == "standalone":
        ensure_port_available(80)
    if config["client"] == "certbot":
        args = certbot_base(config) + ["renew", "--non-interactive", "--cert-name", "familychat-push-gateway"] if renew else issue_command(config)
        if renew and ip_address(config['domain']) is not None:
            args += ['--required-profile', 'shortlived']
        command(args, env=env)
    else:
        if not renew:
            command(acme_base(config) + ["--register-account", "--server", "letsencrypt", "-m", config["email"]], env=env)
        args = acme_base(config) + ["--renew", "--server", "letsencrypt", "--ecc", "-d", config["domain"]] if renew else issue_command(config)
        if renew and ip_address(config['domain']) is not None:
            args += ['--certificate-profile', 'shortlived', '--days', '3']
        # acme.sh uses exit 2 when renewal is not due; this is not an error.
        result = subprocess.run([str(arg) for arg in args], env=env)
        if result.returncode not in (0, 2):
            raise RuntimeError("acme.sh не смог выпустить/продлить сертификат")
    publish_certificate(config)
