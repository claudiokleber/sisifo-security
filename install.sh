#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo 'Instale Python 3.11+ e o suporte a venv.' >&2; exit 1; }
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'
args=(--source "$SCRIPT_DIR")
with_docker=false
skip_docker=false
for arg in "$@"; do
    case "$arg" in
        --skip-setup) ;; # Setup is always explicit after installation.
        --skip-docker) skip_docker=true ;;
        --with-docker) with_docker=true ;;
        --update|--repair|--rollback|--uninstall) args+=("$arg") ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done
python3 "$SCRIPT_DIR/sisifo/installation.py" "${args[@]}"
if $with_docker && ! $skip_docker; then
    (cd "$SCRIPT_DIR" && docker compose build sisifo nmap && docker compose pull nikto)
fi
echo 'Abra um novo terminal: sisifo. Configuracao: sisifo setup. Web: sisifo web.'
