import json
import os
from unittest.mock import Mock

import pytest

from sisifo import installation


def runtime(root, release):
    python = (
        root / "releases" / release / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    )
    python.parent.mkdir(parents=True)
    python.touch()


def test_failed_update_preserves_launcher(tmp_path, monkeypatch):
    source = tmp_path / "source with spaces"
    source.mkdir()
    (source / "pyproject.toml").touch()
    root = tmp_path / "installation"
    (root / "bin").mkdir(parents=True)
    wrapper = root / "bin/sisifo.bat"
    wrapper.write_text("old launcher", encoding="utf-8")
    monkeypatch.setattr(installation.subprocess, "run", Mock(side_effect=OSError("offline")))
    with pytest.raises(OSError):
        installation.install(source, root)
    assert wrapper.read_text(encoding="utf-8") == "old launcher"


def test_repair_and_rollback_preserve_data(tmp_path, monkeypatch):
    root = tmp_path / "instalacao com espacos"
    old, new = "a" * 32, "b" * 32
    runtime(root, old)
    runtime(root, new)
    data = tmp_path / "data"
    data.mkdir()
    marker = data / "keep.txt"
    marker.write_text("preserve", encoding="utf-8")
    state = dict(release=new, previous=old, data=str(data), config=None)
    (root / "installation.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(installation, "repair_path", lambda root: None)
    installation.repair(True, root)
    wrapper = root / ("bin/sisifo.bat" if os.name == "nt" else "bin/sisifo")
    assert old in wrapper.read_text(encoding="utf-8")
    installation.uninstall(root)
    assert not wrapper.exists()
    assert marker.read_text(encoding="utf-8") == "preserve"
    assert (root / "installation.json").exists()


def test_invalid_release_rejected(tmp_path):
    with pytest.raises(ValueError):
        installation.activate(tmp_path, {"release": "../../escape"})


def test_launcher_does_not_reference_source(tmp_path):
    release = "a" * 32
    runtime(tmp_path, release)
    installation.activate(tmp_path, dict(release=release, source="deleted-source"))
    wrapper = tmp_path / ("bin/sisifo.bat" if os.name == "nt" else "bin/sisifo")
    text = wrapper.read_text(encoding="utf-8")
    assert "deleted-source" not in text
    assert "activate" not in text
    assert "-I" in text


def test_menu_does_not_initialize_docker(monkeypatch):
    import docker
    from typer.testing import CliRunner

    from sisifo.cli.main import app

    monkeypatch.setattr(
        docker, "from_env", Mock(side_effect=AssertionError("Docker must not be contacted"))
    )
    result = CliRunner().invoke(app, ["menu"], input="0\n")
    assert result.exit_code == 0
