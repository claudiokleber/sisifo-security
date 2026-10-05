#!/usr/bin/env bash
# User installation. Update uses local source; data and credentials are preserved.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sisifo"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="$INSTALL_DIR/bin"
WRAPPER="$BIN_DIR/sisifo"
skip_setup=false
skip_docker=false
uninstall=false
update=false
for arg in "$@"; do
    case "$arg" in
        --skip-setup) skip_setup=true ;;
        --skip-docker) skip_docker=true ;;
        --uninstall) uninstall=true ;;
        --update) update=true ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done
if $uninstall && $update; then
    echo "Choose update or uninstall, not both." >&2; exit 1
fi
case "${SHELL:-/bin/sh}" in
    */zsh) SHELL_RC="$HOME/.zshrc" ;;
    */bash) SHELL_RC="$HOME/.bashrc" ;;
    */fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
    *) SHELL_RC="$HOME/.profile" ;;
esac
command -v python3 >/dev/null || { echo 'Python 3.11+ required.' >&2; exit 1; }
if $uninstall; then
    # Resolve and verify each target before deletion; never remove INSTALL_DIR itself.
    python3 - "$INSTALL_DIR" "$SHELL_RC" "$BIN_DIR" <<'PY'
from pathlib import Path
import shutil, sys
base, rc, bin_dir = map(Path, sys.argv[1:])
if base.is_symlink():
    raise SystemExit("Linked installation directory refused")
for name in ("venv", "bin"):
    target = base / name
    if target.is_symlink() or target.resolve().parent != base.resolve():
        raise SystemExit("Unsafe removal path")
    if target.exists():
        shutil.rmtree(target)
marker = " # sisifo-managed-path:" + str(bin_dir)
if rc.exists():
    lines = rc.read_text().splitlines()
    rc.write_text("\n".join(line for line in lines if not line.endswith(marker)) + "\n")
print("Installation removed; source, data and credentials preserved.")
PY
    exit 0
fi
if command -v sisifo >/dev/null 2>&1 && [[ "$(command -v sisifo)" != "$WRAPPER" ]]; then
    echo "Another sisifo command exists: $(command -v sisifo). Check PATH ordering."
fi
if $update; then echo "Updating from current local source; no git pull/reset."; fi
mkdir -p "$INSTALL_DIR" "$BIN_DIR"
if [[ ! -x "$VENV_DIR/bin/python" ]]; then python3 -m venv "$VENV_DIR"; fi
"$VENV_DIR/bin/python" -m pip install -e "$SCRIPT_DIR[web]"
python3 - "$WRAPPER" "$VENV_DIR/bin/python" "$SCRIPT_DIR" "$SHELL_RC" "$BIN_DIR" <<'PY'
from pathlib import Path
import shlex, sys
wrapper, python, source, rc, bin_dir = sys.argv[1:]
q = shlex.quote
content = ("#!/bin/sh\n"
           + 'if [ -z "${SISIFO_CONFIG_DIR:-}" ]; then export SISIFO_CONFIG_DIR=' + q(source + '/.sisifo-config') + '; fi\n'
           + 'if [ -z "${SISIFO_DATA_DIR:-}" ]; then export SISIFO_DATA_DIR=' + q(source + '/data') + '; fi\n'
           + 'exec ' + q(python) + ' -m sisifo.cli.main "$@"\n')
path = Path(wrapper)
path.write_text(content)
path.chmod(0o755)
rc = Path(rc)
rc.parent.mkdir(parents=True, exist_ok=True)
marker = " # sisifo-managed-path:" + bin_dir
line = ('set -gx PATH ' + q(bin_dir) + ' $PATH' if rc.name == 'config.fish'
        else 'export PATH=' + q(bin_dir) + ':"$PATH"') + marker
old = rc.read_text() if rc.exists() else ''
if marker not in old:
    rc.write_text(old.rstrip('\n') + '\n' + line + '\n')
PY
if ! $skip_docker; then
    (cd "$SCRIPT_DIR" && docker compose build sisifo nmap && docker compose pull nikto && docker compose run --rm sisifo doctor)
fi
if ! $skip_setup; then
    "$WRAPPER" setup
fi
echo "Installed. Open a new terminal or source $SHELL_RC"
echo "Data: $SCRIPT_DIR/data (SISIFO_DATA_DIR overrides)"
echo "Config: $SCRIPT_DIR/.sisifo-config (SISIFO_CONFIG_DIR overrides)"
