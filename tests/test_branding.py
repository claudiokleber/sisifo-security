import io
import sys

import pytest

from sisifo import branding as ui


class Output(io.StringIO):
    def __init__(self, tty=False, encoding="utf-8"):
        super().__init__()
        self.tty = tty
        self._encoding = encoding

    @property
    def encoding(self):
        return self._encoding

    def isatty(self):
        return self.tty


def render(stream):
    ui.banner("test", stream=stream)
    ui.panel([("Versão", "test"), ("Análise", "Evidência")], "Configuração", stream=stream)
    ui.menu([("0", "Sair")], stream=stream)
    ui.section("Análise", stream=stream)
    ui.ok("Salvo", stream=stream)
    ui.info("Informação", stream=stream)
    ui.warn("Revisão", stream=stream)
    ui.error("Erro", "Dica", stream=stream)
    ui.progress(1, 2, "Evidências", stream=stream)


def test_redirected_output_never_contains_ansi():
    output = Output()
    render(output)
    ui.error("\x1b[31mconteúdo externo\x1b[0m", stream=output)
    with ui.climb("Teste", stream=output):
        pass
    assert "\x1b" not in output.getvalue()
    assert "\r" not in output.getvalue()


@pytest.mark.parametrize("encoding", ["ascii", "cp1252"])
def test_non_unicode_terminal_fallback(encoding):
    output = Output(encoding=encoding)
    render(output)
    output.getvalue().encode("ascii")
    assert "Versao" in output.getvalue()


def test_forced_ascii(monkeypatch):
    monkeypatch.setenv("SISIFO_ASCII", "1")
    output = Output()
    render(output)
    output.getvalue().encode("ascii")


def test_no_color_disables_controls_even_on_terminal(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    output = Output(tty=True)
    render(output)
    with ui.climb("Teste", stream=output):
        pass
    assert "\x1b" not in output.getvalue()


def test_panel_width_with_accents_combining_and_long_values(monkeypatch):
    monkeypatch.setattr(ui, "_width", lambda stream: 48)
    output = Output()
    ui.panel([("Versão", "São Paulo"), ("Análise", "a\u0301" * 80), ("Dados", "C:/" + "x" * 100)], stream=output)
    lines = [line for line in output.getvalue().splitlines() if line]
    assert len({ui.visible_len(line) for line in lines}) == 1
    assert all(ui.visible_len(line) <= 48 for line in lines)
    assert "São Paulo" in output.getvalue()


@pytest.mark.parametrize("width", [20, 40, 80, 120])
def test_banner_handles_terminal_width(monkeypatch, width):
    monkeypatch.setattr(ui, "_width", lambda stream: width)
    output = Output()
    ui.banner(stream=output)
    assert ui.package_version() in output.getvalue()
    assert all(ui.visible_len(line) <= width for line in output.getvalue().splitlines())


def test_spinner_does_not_claim_success_after_exception(monkeypatch):
    monkeypatch.setattr(ui, "_color", lambda stream: True)
    output = Output(tty=True)
    with pytest.raises(ValueError):
        with ui.climb("Teste", stream=output):
            raise ValueError("failure")
    assert "[+]" not in output.getvalue()


def test_progress_is_not_written_to_stdout(monkeypatch):
    out, err = Output(), Output()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    with ui.climb("Teste"):
        print('{"resultado": "ok"}')
    assert out.getvalue() == '{"resultado": "ok"}\n'
    assert err.getvalue() == ""
