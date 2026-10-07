import json
import os
import shutil
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from sisifo.core.execution import Control
from sisifo.modules.network.models import CaptureConfig, CaptureResult, CaptureStatus, DisplayFilter
from sisifo.modules.network.service import NetworkService


@pytest.fixture
def service(tmp_path):
    return NetworkService(tmp_path / 'store')


@pytest.fixture
def capture(service):
    path = service.captures_dir / 'test.pcap'
    shutil.copyfile(Path(__file__).parent / 'fixtures/network-synthetic.pcap', path)
    result = CaptureResult(file_path=str(path), status='completed', file_sha256=service._calculate_sha256(path))
    service._save_capture_metadata(result)
    return result


def test_paths_and_metadata_are_confined(service, capture, tmp_path):
    for identifier in ['../../outside', str(tmp_path / 'outside'), 'not-an-id']:
        with pytest.raises(ValueError):
            service.get_capture(identifier)
    capture.file_path = str(tmp_path / 'outside.pcap')
    service._save_capture_metadata(capture)
    with pytest.raises(ValueError, match='armazenamento'):
        service.get_capture(capture.id)


def test_tool_errors_and_timeout(service):
    with pytest.raises(ValueError, match='código 2'):
        service._run_tool([sys.executable, '-c', 'raise SystemExit(2)'])
    with pytest.raises(ValueError, match='tempo'):
        service._run_tool([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.1)


def test_invalid_filter_is_not_empty_success(service, capture, monkeypatch):
    monkeypatch.setattr(service, 'discover_tools', lambda: SimpleNamespace(tshark_path='fake', tshark_version='1'))
    def fail(*args):
        raise ValueError('Filtro inválido')
    monkeypatch.setattr(service, '_run_tool', fail)
    with pytest.raises(ValueError, match='Filtro'):
        service.list_packets(capture.id, DisplayFilter(expression='invalid'))
    assert not list(service.indexes_dir.rglob('*.json'))


def test_cache_keys_filter_version_and_integrity(service, capture, monkeypatch):
    diag = SimpleNamespace(tshark_path='fake', tshark_version='1')
    monkeypatch.setattr(service, 'discover_tools', lambda: diag)
    calls = []
    def run(cmd, *args):
        calls.append(cmd)
        return ''
    monkeypatch.setattr(service, '_run_tool', run)
    for expr in ['tcp', 'udp', 'tcp']:
        service.list_packets(capture.id, DisplayFilter(expression=expr))
    assert len(calls) == 2
    assert all('-n' in cmd for cmd in calls)
    diag.tshark_version = '2'
    service.list_packets(capture.id, DisplayFilter(expression='tcp'))
    assert len(calls) == 3
    Path(capture.file_path).write_bytes(b'changed')
    with pytest.raises(ValueError, match='Integridade'):
        service.list_packets(capture.id)


def mock_capture_environment(service, monkeypatch):
    diag = SimpleNamespace(dumpcap_path='fake', tshark_path=None, is_docker=False,
                           dumpcap_version='test', tshark_version=None, interfaces=[])
    monkeypatch.setattr(service, 'discover_tools', lambda: diag)
    monkeypatch.setattr(service, 'validate_capture_config', lambda c: (True, ''))


def test_precancel_preserves_reason(service, monkeypatch):
    mock_capture_environment(service, monkeypatch)
    control = Control()
    control.cancelled.set()
    result = service.start_capture(CaptureConfig(interface_id='test'), control)
    assert result.status == CaptureStatus.CANCELLED
    assert result.finished_at is not None


def test_stop_from_other_service_terminates_owned_process(service, monkeypatch):
    import subprocess
    mock_capture_environment(service, monkeypatch)
    real_popen = subprocess.Popen
    started = threading.Event()
    children = []
    def popen(cmd, **kwargs):
        output = cmd[cmd.index('-w') + 1]
        Path(output).write_bytes(b'partial')
        child = real_popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
        children.append(child)
        started.set()
        return child
    monkeypatch.setattr('sisifo.modules.network.service.subprocess.Popen', popen)
    results = []
    thread = threading.Thread(target=lambda: results.append(service.start_capture(CaptureConfig(interface_id='test'))))
    thread.start()
    try:
        assert started.wait(5)
        other = NetworkService(service.data_dir)
        record = other.list_captures()[0]
        assert other.stop_capture(record.id).status == CaptureStatus.RUNNING
        thread.join(5)
        assert not thread.is_alive()
        assert children[0].poll() is not None
        assert results[0].status == CaptureStatus.CANCELLED
        assert results[0].file_size == 7
        assert results[0].file_sha256
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
        thread.join(5)


@pytest.mark.parametrize('suffix', ['pcap', 'pcapng'])
def test_tshark_integration(service, suffix):
    if not service._find_executable('tshark'):
        if os.getenv('SISIFO_REQUIRE_TSHARK'):
            pytest.fail('TShark required neste ambiente')
        pytest.skip('TShark não instalado; CI Linux instala ferramenta real')
    fixture = Path(__file__).parent / f'fixtures/network-synthetic.{suffix}'
    result = service.import_pcap(fixture)
    assert result.packet_count == 2
    assert len(service.list_packets(result.id)) == 2
    tcp = DisplayFilter(expression='tcp')
    udp = DisplayFilter(expression='udp')
    assert len(service.list_packets(result.id, tcp)) == 1
    assert service.get_protocol_stats(result.id, tcp).total_packets == 1
    assert service.get_protocol_stats(result.id, udp).total_packets == 1
    assert service.get_protocol_stats(result.id).total_packets == 2
    assert service.get_endpoints(result.id)[0].packets_tx + service.get_endpoints(result.id)[0].packets_rx == 2
    assert len(service.get_conversations(result.id)) == 2
    report = service.generate_report(result.id, tcp)
    assert report.protocol_stats.total_packets == 1
    assert json.loads(report.model_dump_json())['protocol_stats']['total_packets'] == 1
    assert service.get_packet_detail(result.id, 1).number == 1
    with pytest.raises(ValueError):
        service.list_packets(result.id, DisplayFilter(expression='tcp &&&'))
    bad = service.data_dir / 'truncated.pcap'
    bad.write_bytes(b'not a capture')
    with pytest.raises(ValueError):
        service.import_pcap(bad)


def test_spawn_failure_has_safe_terminal_record(service, monkeypatch):
    mock_capture_environment(service, monkeypatch)
    def fail(*args, **kwargs):
        raise OSError('synthetic spawn failure')
    monkeypatch.setattr('sisifo.modules.network.service.subprocess.Popen', fail)
    result = service.start_capture(CaptureConfig(interface_id='test'))
    assert result.status == CaptureStatus.FAILED
    assert result.finished_at is not None
    assert service.get_capture(result.id).status == CaptureStatus.FAILED


def test_restart_marks_abandoned_capture_interrupted(service, capture):
    capture.status = CaptureStatus.RUNNING
    service._save_capture_metadata(capture)
    restarted = NetworkService(service.data_dir)
    assert restarted.get_capture(capture.id).status == CaptureStatus.INTERRUPTED


def test_foreign_metadata_id_rejected(service, capture):
    original_id = capture.id
    capture.id = 'b' * 32
    (service.captures_dir / f'{original_id}.json').write_text(capture.model_dump_json(), encoding='utf-8')
    with pytest.raises(ValueError, match='divergente'):
        service.get_capture(original_id)


def test_tshark_csv_preserves_separators_and_protocol_counts(service, capture, monkeypatch):
    import csv
    import io
    monkeypatch.setattr(service, 'discover_tools', lambda: SimpleNamespace(tshark_path='fake', tshark_version='1'))
    values = ['1', '0', '1700000000', '192.0.2.1', '192.0.2.2', '', '', '', '', 'UDP', '42',
              'text, with | delimiters', '', '', '12345', '9999', '', '', '', '']
    stream = io.StringIO()
    csv.writer(stream).writerow(values)
    monkeypatch.setattr(service, '_run_tool', lambda *args: stream.getvalue())
    assert service.list_packets(capture.id)[0].info == values[11]
    stats = service.get_protocol_stats(capture.id)
    assert stats.total_packets == 1
    assert stats.total_bytes == 42
    assert stats.by_protocol[0].percentage_packets == 100
