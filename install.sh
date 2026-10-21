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
exec python3 "$root/scripts/manage.py" "$action" "$@"
