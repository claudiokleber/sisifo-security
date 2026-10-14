"""Sísifo terminal branding, adapted from the supplied branding.py.

Standard library only. Capabilities are checked at output time, not import.
No stdout reconfiguration, background activity or filesystem writes on import.
"""

from __future__ import annotations

import itertools
import os
import re
import shutil
import sys
import threading
import time
import unicodedata
from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError, version

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GRAY = (142, 142, 142)
GRAY_DIM = (107, 107, 107)
RED = (255, 42, 42)
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def package_version():
    try:
        return version("sisifo")
    except PackageNotFoundError:
        return "desenvolvimento"


def _tty(stream):
    return bool(getattr(stream, "isatty", lambda: False)())


def _unicode(stream):
    if os.getenv("SISIFO_ASCII") == "1":
        return False
    encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
    return encoding in {"utf8", "utf8sig"}


def _text(value, stream):
    value = _ANSI.sub("", str(value)).replace("\x1b", "")
    # Strip terminal controls supplied by external evidence, preserving line breaks.
    value = "".join(c for c in value if c in "\n\t" or unicodedata.category(c) != "Cc")
    if not _unicode(stream):
        value = "".join(
            c for c in unicodedata.normalize("NFKD", value) if not unicodedata.combining(c)
        )
        value = value.encode("ascii", "replace").decode()
    return value


def _color(stream):
    if not _tty(stream) or "NO_COLOR" in os.environ or os.getenv("TERM") == "dumb":
        return False
    if os.name == "nt":
        try:
            import ctypes

            kernel = ctypes.windll.kernel32
            handle = kernel.GetStdHandle(-12 if stream is sys.stderr else -11)
            mode = ctypes.c_uint32()
            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel.SetConsoleMode(handle, mode.value | 4))
        except (AttributeError, OSError):
            return False
    return True


def paint(text, rgb=WHITE, bold=False, *, stream=None):
    stream = stream or sys.stdout
    text = _text(text, stream)
    if not _color(stream):
        return text
    truecolor = (
        os.getenv("COLORTERM", "").lower() in {"truecolor", "24bit"} or "WT_SESSION" in os.environ
    )
    if truecolor:
        code = "38;2;" + ";".join(map(str, rgb))
    else:
        code = f"38;5;{16 + 36 * round(rgb[0] / 51) + 6 * round(rgb[1] / 51) + round(rgb[2] / 51)}"
    return ("\x1b[1m" if bold else "") + f"\x1b[{code}m{text}\x1b[0m"


def visible_len(text):
    return sum(
        0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in "WF" else 1
        for c in _ANSI.sub("", text)
    )


def _width(stream):
    try:
        return max(20, os.get_terminal_size(stream.fileno()).columns)
    except (AttributeError, OSError, ValueError):
        return max(20, shutil.get_terminal_size((80, 24)).columns)


def _wrap(text, width):
    rows, row = [], ""
    for char in text:
        if char == "\n" or visible_len(row + char) > width:
            rows.append(row)
            row = ""
        if char != "\n":
            row += char
    return rows + [row]


def banner(version=None, tagline="Evidências, análise e investigação", *, stream=None):
    stream = stream or sys.stdout
    version = package_version() if version is None else version
    word = _WORDMARK if _unicode(stream) else _WORDMARK_ASCII
    hill = _HILL if _unicode(stream) else _HILL_ASCII
    print(file=stream)
    if _width(stream) < 74:
        print(paint("  SISIFO  / [#]", WHITE, True, stream=stream), file=stream)
    else:
        for i, line in enumerate(word):
            shade = tuple(round(255 + (107 - 255) * i / (len(word) - 1)) for _ in range(3))
            art = "".join(
                paint(c, RED if c in "▓#" else GRAY if c in "·." else WHITE, stream=stream)
                for c in (hill[i] if i < len(hill) else "")
            )
            print("  " + paint(line, shade, True, stream=stream) + "   " + art, file=stream)
    for line in _wrap(_text(f"{tagline} - v{version}", stream), _width(stream) - 2):
        print("  " + paint(line, GRAY, stream=stream), file=stream)
    print(file=stream)


def panel(rows, title="", *, stream=None):
    stream = stream or sys.stdout
    rows = [(_text(k, stream), _text(v, stream)) for k, v in rows]
    width = _width(stream) - 6
    key_width = min(max((visible_len(k) for k, _ in rows), default=0), max(1, width // 3))
    body = []
    for key, value in rows:
        key = _wrap(key, key_width)[0] if key_width else key
        first = key + " " * (key_width - visible_len(key)) + "  "
        for i, line in enumerate(_wrap(value, max(1, width - key_width - 2))):
            body.append((first if i == 0 else " " * (key_width + 2)) + line)
    tl, tr, bl, br, h, v = (
        ("╭", "╮", "╰", "╯", "─", "│") if _unicode(stream) else ("+", "+", "+", "+", "-", "|")
    )
    title = _text(title, stream)
    if title:
        print(paint("  " + title, WHITE, True, stream=stream), file=stream)
    print(paint("  " + tl + h * (width + 2) + tr, GRAY, stream=stream), file=stream)
    for line in body:
        print(
            paint(
                "  " + v + " " + line + " " * (width - visible_len(line)) + " " + v,
                WHITE,
                stream=stream,
            ),
            file=stream,
        )
    print(paint("  " + bl + h * (width + 2) + br, GRAY, stream=stream), file=stream)
    print(file=stream)


def menu(items, *, stream=None):
    stream = stream or sys.stdout
    for key, label in items:
        print(
            "  " + paint(key, RED, True, stream=stream) + "   " + _text(label, stream), file=stream
        )
    print(file=stream)


def prompt(options, default="0"):
    while True:
        choice = (
            input(_text(f"Escolha [{'/'.join(options)}] ({default}): ", sys.stdout)).strip()
            or default
        )
        if choice in options:
            return choice
        warn("Opção inválida.")


def section(title, *, stream=None):
    stream = stream or sys.stdout
    print("\n" + paint("  " + title, WHITE, True, stream=stream), file=stream)


def _message(symbol, message, rgb, stream):
    stream = stream or sys.stdout
    print(
        paint(f"  [{symbol}]", rgb, True, stream=stream) + " " + _text(message, stream), file=stream
    )


def ok(message, *, stream=None):
    _message("+", message, WHITE, stream)


def info(message, *, stream=None):
    _message("*", message, GRAY, stream)


def warn(message, *, stream=None):
    _message("!", message, WHITE, stream)


def error(message, hint="", *, stream=None):
    _message("-", message, RED, stream)
    if hint:
        info(hint, stream=stream)


@contextmanager
def climb(message="Coletando evidências", fps=8, *, stream=None):
    # Progress belongs on stderr; pipe/JSON output remains unchanged.
    stream = stream or sys.stderr
    if not _color(stream):
        yield
        return
    stop = threading.Event()
    started = time.monotonic()
    ramp = "▁▂▃▄▅▆▇" if _unicode(stream) else "_.-~^*#"
    frames = list(range(7)) + [6, 3, 0]

    def spin():
        for pos in itertools.cycle(frames):
            cells = ramp[:pos] + ("●" if _unicode(stream) else "O") + ramp[pos + 1 :]
            line = f"{cells}  {_text(message, stream)}  {time.monotonic() - started:.0f}s"
            stream.write("\r\x1b[2K" + paint(line, WHITE, stream=stream))
            stream.flush()
            if stop.wait(1 / max(1, min(fps, 30))):
                break

    worker = threading.Thread(target=spin, daemon=True)
    worker.start()
    success = False
    try:
        yield
        success = True
    finally:
        stop.set()
        worker.join()
        stream.write("\r\x1b[2K")
        stream.flush()
        if success:
            ok(f"{message} ({time.monotonic() - started:.1f}s)", stream=stream)


def progress(done, total, label="", width=24, *, stream=None):
    stream = stream or sys.stderr
    fraction = min(1, max(0, done / total)) if total > 0 else 0
    width = min(max(1, width), max(1, _width(stream) - 15))
    count = round(fraction * width)
    on, off = ("━", "─") if _unicode(stream) else ("#", "-")
    print(
        paint(on * count + off * (width - count), WHITE, stream=stream)
        + _text(f" {fraction:.0%} {label}", stream),
        file=stream,
    )


def _demo():
    banner()
    panel([("Versão", package_version()), ("Modo", "Demonstração local")], "Sísifo")
    menu([("1", "Executar ferramentas"), ("0", "Sair")])
    ok("Identidade visual carregada")
    info("Nenhuma ferramenta externa será executada")
    warn("Demonstração")
    error("Exemplo de erro", "Use sisifo doctor para diagnóstico")
    with climb("Demonstração do progresso"):
        time.sleep(1)
    progress(1, 1, "Concluído")


_WORDMARK = [
    "███████╗ ██╗ ███████╗ ██╗ ███████╗  ██████╗ ",
    "██╔════╝ ██║ ██╔════╝ ██║ ██╔════╝ ██╔═══██╗",
    "███████╗ ██║ ███████╗ ██║ █████╗   ██║   ██║",
    "╚════██║ ██║ ╚════██║ ██║ ██╔══╝   ██║   ██║",
    "███████║ ██║ ███████║ ██║ ██║      ╚██████╔╝",
    "╚══════╝ ╚═╝ ╚══════╝ ╚═╝ ╚═╝       ╚═════╝ ",
]
_HILL = [
    "       ▄▄▄▄           ",
    "      ▐██▓▓▌ ·  ·  ·  ",
    "      ▐██▓▓▌          ",
    "    ╱  ▀▀▀▀           ",
    "  ╱                   ",
    "╱                     ",
]
_WORDMARK_ASCII = [
    " SSSS  III  SSSS  III  FFFFF   OOO  ",
    "S       I  S       I   F      O   O ",
    " SSS    I   SSS    I   FFF    O   O ",
    "    S   I      S   I   F      O   O ",
    "SSSS   III SSSS   III  F       OOO  ",
]
_HILL_ASCII = [
    "     .--.        ",
    "    ( ## )  . . .",
    "   / '--'        ",
    "  /              ",
    " /               ",
]

if __name__ == "__main__":
    _demo()
