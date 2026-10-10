import pytest


@pytest.fixture(autouse=True)
def private_test_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SISIFO_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SISIFO_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("SISIFO_AI_API_KEY", raising=False)
