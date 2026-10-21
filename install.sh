#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
action=install
case "${1:-}" in install|update|renew) action="$1"; shift ;; esac
if ! command -v python3 >/dev/null; then
    if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
        printf 'sudo bash install.sh [install|update|renew] --domain NAME | --ip ADDRESS --email EMAIL [--port 9443]\nPython 3 is required for full help.\n'
        exit 0
    fi
    [[ "$(uname -s)" == Linux && "$EUID" == 0 ]] || { echo 'Установите Python 3; запуск установки — sudo на Ubuntu/Debian.' >&2; exit 1; }
    # shellcheck source=/dev/null
    source /etc/os-release
    [[ "$ID" == ubuntu || "$ID" == debian ]] || { echo 'Поддерживаются Ubuntu/Debian.' >&2; exit 1; }
    printf 'Установить Python 3 через apt? [y/N] ' >/dev/tty
    read -r answer </dev/tty
    case "$answer" in y|Y|yes|да|д) apt-get update; apt-get install -y python3 ;; *) exit 1 ;; esac
fi
if [[ ! -f "$root/scripts/manage.py" || ! -f "$root/go.mod" ]] || \
    ! grep -Fxq 'module github.com/balamutik/familychat-push-gateway' "$root/go.mod"; then
    # A downloaded single file bootstraps a reviewed, immutable source bundle.
    # Bump both values below together after the payload's CI has passed.
    temporary="$(mktemp -d)"
    printf -v cleanup 'rm -rf -- %q' "$temporary"
    # shellcheck disable=SC2064
    trap "$cleanup" EXIT
    python3 - "$temporary" <<'PY_BOOTSTRAP'
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import sys
import tarfile
import urllib.parse
import urllib.request

REVISION = '78507d8af0654a3b5639e30d1d1be14b6cf5535b'
SHA256 = '0b3f123c5cf893c2168feed00590206f94317e7bfadca190028f6d5ba9829b4a'

class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('Загрузка требует HTTPS')
        return super().redirect_request(req, fp, code, msg, headers, newurl)

try:
    root = Path(sys.argv[1])
    url = 'https://github.com/balamutik/familychat-push-gateway/archive/' + REVISION + '.tar.gz'
    request = urllib.request.Request(url, headers={'User-Agent':'FamilyChat-push-gateway-installer'})
    with urllib.request.build_opener(HTTPSRedirect()).open(request, timeout=60) as response:
        data = response.read((8 << 20) + 1)
    if len(data) > 8 << 20:
        raise ValueError('Установочный архив слишком большой')
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('SHA-256 установочного архива не совпадает')
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        unpacked = compressed.read((32 << 20) + 1)
    if len(unpacked) > 32 << 20:
        raise ValueError('Распакованный архив слишком большой')
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r:') as archive:
        members, names = [], set()
        prefix = 'familychat-push-gateway-' + REVISION
        for member in archive:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != prefix
                    or not (member.isfile() or member.isdir()) or member.name in names or len(members) >= 2048):
                raise ValueError('Небезопасный архив установки')
            names.add(member.name)
            members.append((member, path))
        for name in ('go.mod','scripts/manage.py','scripts/acme.py'):
            if prefix+'/'+name not in names:
                raise ValueError('Неполный установочный архив')
        for member, path in members:
            target = root.joinpath(*path.parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
except Exception as error:
    sys.exit(f'Не удалось скачать установочный пакет: {error}')
PY_BOOTSTRAP
    root="$temporary"
fi
# Keep this shell alive so its EXIT trap removes a downloaded payload.
python3 "$root/scripts/manage.py" "$action" "$@"
