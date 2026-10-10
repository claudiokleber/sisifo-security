"""Per-user installation and launcher repair; standard library only."""
import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from uuid import uuid4


def installation_root():
    if os.getenv('SISIFO_INSTALL_DIR'):
        return Path(os.environ['SISIFO_INSTALL_DIR']).resolve()
    if os.name == 'nt':
        return Path(os.environ['APPDATA']) / 'sisifo'
    return Path(os.getenv('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'sisifo'


def write_atomic(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid4().hex + '.tmp')
    try:
        temp.write_text(content, encoding='utf-8', newline='\n')
        if os.name != 'nt':
            temp.chmod(0o700)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def repair_path(root):
    directory = str(root / 'bin')
    if os.name == 'nt':
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
            try:
                value, kind = winreg.QueryValueEx(key, 'Path')
            except FileNotFoundError:
                value, kind = '', winreg.REG_EXPAND_SZ
            entries = [p for p in value.split(';') if p and p.rstrip('\\').casefold() != directory.casefold()]
            winreg.SetValueEx(key, 'Path', 0, kind, ';'.join([directory, *entries]))
        # Notify Explorer; already-open terminals still keep their own environment.
        import ctypes
        from ctypes import wintypes
        response = ctypes.c_size_t()
        notify = ctypes.windll.user32.SendMessageTimeoutW
        notify.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR,
                           wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
        notify(65535, 26, 0, 'Environment', 2, 1000, ctypes.byref(response))
    else:
        # Cover interactive and login shells without changing unrelated settings.
        for name in ['.profile', '.bashrc', '.zprofile', '.zshrc', '.config/fish/config.fish']:
            rc = Path.home() / name
            old = rc.read_text(encoding='utf-8') if rc.exists() else ''
            marker = ' # sisifo-managed-path:' + directory
            line = ('set -gx PATH ' + shlex.quote(directory) + ' $PATH' if name.endswith('config.fish')
                    else 'export PATH=' + shlex.quote(directory) + ':"$PATH"') + marker
            lines = [s for s in old.splitlines() if not s.endswith(marker)]
            write_atomic(rc, '\n'.join([*lines, line]) + '\n')


def activate(root, state):
    release = state['release']
    if not isinstance(release, str) or len(release) != 32 or any(c not in '0123456789abcdef' for c in release):
        raise ValueError('Invalid installation release')
    python = root / 'releases' / release / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not python.is_file():
        raise ValueError('Python privado ausente; execute novamente o instalador para reconstruir.')
    # State is embedded per release: old launcher remains independent until final replacement.
    launch = root / 'releases' / release / 'launch.py'
    settings = {k: state[k] for k in ('data', 'config') if state.get(k)}
    write_atomic(launch, 'import os\n' + f'os.environ.setdefault("SISIFO_INSTALL_DIR", {str(root)!r})\n' + f'settings = {settings!r}\n'
                 + 'for k, v in settings.items():\n    os.environ.setdefault("SISIFO_" + k.upper() + "_DIR", v)\n'
                 + 'from sisifo.cli.main import app\napp(prog_name="sisifo")\n')
    if os.name == 'nt':
        content = ('@echo off\r\nsetlocal\r\n'
                   f'"%~dp0..\\releases\\{release}\\Scripts\\python.exe" -I "%~dp0..\\releases\\{release}\\launch.py" %*\r\n'
                   'exit /b %errorlevel%\r\n')
        wrapper = root / 'bin/sisifo.bat'
    else:
        content = '#!/bin/sh\nexec ' + shlex.quote(str(python)) + ' -I ' + shlex.quote(str(launch)) + ' "$@"\n'
        wrapper = root / 'bin/sisifo'
    write_atomic(wrapper, content)


def install(source, root=None):
    root = root or installation_root()
    source = Path(source).resolve()
    if not (source / 'pyproject.toml').is_file():
        raise ValueError('Fonte inválida; informe a pasta do projeto.')
    manifest = root / 'installation.json'
    old = json.loads(manifest.read_text(encoding='utf-8')) if manifest.exists() else {}
    release = uuid4().hex
    runtime = root / 'releases' / release
    subprocess.run([sys.executable, '-m', 'venv', str(runtime)], check=True)
    python = runtime / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    subprocess.run([str(python), '-m', 'pip', 'install', str(source) + '[web]'], check=True)
    subprocess.run([str(python), '-I', '-m', 'sisifo.cli.main', '--help'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([str(python), '-I', '-c', 'from sisifo.web.server import app; from sisifo.cli.commands.menu import menu'], check=True)
    state = {'release': release, 'previous': old.get('release'), 'source': str(source)}
    # Keep existing installations' data locations; never copy or remove credentials.
    for key, legacy in [('data', source / 'data'), ('config', source / '.sisifo-config')]:
        state[key] = old.get(key) or (str(legacy) if legacy.is_dir() else None)
    repair_path(root)
    activate(root, state)
    write_atomic(manifest, json.dumps(state, indent=2))
    print('Instalacao concluida. Execute sisifo em um novo terminal. Docker e opcional.')
    return state


def repair(rollback=False, root=None):
    root = root or installation_root()
    manifest = root / 'installation.json'
    if not manifest.exists():
        raise ValueError('Instalacao gerenciada ausente; execute install.ps1 ou install.sh.')
    state = json.loads(manifest.read_text(encoding='utf-8'))
    if rollback:
        if not state.get('previous'):
            raise ValueError('Nenhuma versao anterior disponivel.')
        state['release'], state['previous'] = state['previous'], state['release']
    activate(root, state)
    repair_path(root)
    write_atomic(manifest, json.dumps(state, indent=2))
    print('Comando e PATH reparados. Abra um novo terminal para carregar o PATH.')


def uninstall(root=None):
    # Remove launchers only. Keep all runtimes for recovery and all user data.
    root = root or installation_root()
    for name in ['sisifo', 'sisifo.bat']:
        (root / 'bin' / name).unlink(missing_ok=True)
    print('Comando removido. Ambientes, dados e credenciais preservados para recuperacao.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source')
    parser.add_argument('--update', action='store_true')
    parser.add_argument('--repair', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    if sum([args.update, args.repair, args.rollback, args.uninstall]) > 1:
        parser.error('Escolha apenas uma operacao')
    try:
        if args.uninstall:
            uninstall()
        elif args.repair or args.rollback:
            repair(args.rollback)
        else:
            install(args.source)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f'Instalacao nao concluida: {exc}', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
