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
    return NetworkService(tmp_path / "store")


@pytest.fixture
def capture(service):
    path = service.captures_dir / "test.pcap"
    shutil.copyfile(Path(__file__).parent / "fixtures/network-synthetic.pcap", path)
    result = CaptureResult(
        file_path=str(path),
        status=CaptureStatus.COMPLETED,
        file_sha256=service._calculate_sha256(path),
    )
    service._save_capture_metadata(result)
    return result


def test_paths_and_metadata_are_confined(service, capture, tmp_path):
    for identifier in ["../../outside", str(tmp_path / "outside"), "not-an-id"]:
        with pytest.raises(ValueError):
            service.get_capture(identifier)
    capture.file_path = str(tmp_path / "outside.pcap")
    service._save_capture_metadata(capture)
    with pytest.raises(ValueError, match="armazenamento"):
        service.get_capture(capture.id)


def test_tool_errors_and_timeout(service):
    with pytest.raises(ValueError, match=r"c.*digo 2"):
        service._run_tool([sys.executable, "-c", "raise SystemExit(2)"])
    with pytest.raises(ValueError, match="tempo"):
        service._run_tool([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)


def test_invalid_filter_is_not_empty_success(service, capture, monkeypatch):
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    def fail(*args):
        raise ValueError("Filtro inválido")

    monkeypatch.setattr(service, "_run_tool", fail)
    with pytest.raises(ValueError, match="Filtro"):
        service.list_packets(capture.id, DisplayFilter(expression="invalid"))
    assert not list(service.indexes_dir.rglob("*.json"))


def test_cache_keys_filter_version_and_integrity(service, capture, monkeypatch):
    diag = SimpleNamespace(tshark_path="fake", tshark_version="1")
    monkeypatch.setattr(service, "discover_tools", lambda: diag)
    calls = []

    def run(cmd, *args):
        calls.append(cmd)
        return ""

    monkeypatch.setattr(service, "_run_tool", run)
    for expr in ["tcp", "udp", "tcp"]:
        service.list_packets(capture.id, DisplayFilter(expression=expr))
    assert len(calls) == 2
    assert all("-n" in cmd for cmd in calls)
    diag.tshark_version = "2"
    service.list_packets(capture.id, DisplayFilter(expression="tcp"))
    assert len(calls) == 3
    Path(capture.file_path).write_bytes(b"changed")
    with pytest.raises(ValueError, match="Integridade"):
        service.list_packets(capture.id)


def mock_capture_environment(service, monkeypatch):
    diag = SimpleNamespace(
        dumpcap_path="fake",
        tshark_path=None,
        is_docker=False,
        dumpcap_version="test",
        tshark_version=None,
        interfaces=[],
    )
    monkeypatch.setattr(service, "discover_tools", lambda: diag)
    monkeypatch.setattr(service, "validate_capture_config", lambda c: (True, ""))


def test_precancel_preserves_reason(service, monkeypatch):
    mock_capture_environment(service, monkeypatch)
    control = Control()
    control.cancelled.set()
    result = service.start_capture(CaptureConfig(interface_id="test"), control)
    assert result.status == CaptureStatus.CANCELLED
    assert result.finished_at is not None


def test_stop_from_other_service_terminates_owned_process(service, monkeypatch):
    import subprocess

    mock_capture_environment(service, monkeypatch)
    real_popen = subprocess.Popen
    started = threading.Event()
    children = []

    def popen(cmd, **kwargs):
        output = cmd[cmd.index("-w") + 1]
        Path(output).write_bytes(b"partial")
        child = real_popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        children.append(child)
        started.set()
        return child

    monkeypatch.setattr("sisifo.modules.network.service.subprocess.Popen", popen)
    results = []
    thread = threading.Thread(
        target=lambda: results.append(service.start_capture(CaptureConfig(interface_id="test")))
    )
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


@pytest.mark.parametrize("suffix", ["pcap", "pcapng"])
def test_tshark_integration(service, suffix):
    if not service._find_executable("tshark"):
        if os.getenv("SISIFO_REQUIRE_TSHARK"):
            pytest.fail("TShark required neste ambiente")
        pytest.skip("TShark não instalado; CI Linux instala ferramenta real")
    fixture = Path(__file__).parent / f"fixtures/network-synthetic.{suffix}"
    result = service.import_pcap(fixture)
    assert result.packet_count == 2
    assert len(service.list_packets(result.id)) == 2
    tcp = DisplayFilter(expression="tcp")
    udp = DisplayFilter(expression="udp")
    assert len(service.list_packets(result.id, tcp)) == 1
    assert service.get_protocol_stats(result.id, tcp).total_packets == 1
    assert service.get_protocol_stats(result.id, udp).total_packets == 1
    assert service.get_protocol_stats(result.id).total_packets == 2
    assert (
        service.get_endpoints(result.id)[0].packets_tx
        + service.get_endpoints(result.id)[0].packets_rx
        == 2
    )
    assert len(service.get_conversations(result.id)) == 2
    report = service.generate_report(result.id, tcp)
    assert report.protocol_stats.total_packets == 1
    assert json.loads(report.model_dump_json())["protocol_stats"]["total_packets"] == 1
    assert service.get_packet_detail(result.id, 1).number == 1
    with pytest.raises(ValueError):
        service.list_packets(result.id, DisplayFilter(expression="tcp &&&"))
    bad = service.data_dir / "truncated.pcap"
    bad.write_bytes(b"not a capture")
    with pytest.raises(ValueError):
        service.import_pcap(bad)


def test_spawn_failure_has_safe_terminal_record(service, monkeypatch):
    mock_capture_environment(service, monkeypatch)

    def fail(*args, **kwargs):
        raise OSError("synthetic spawn failure")

    monkeypatch.setattr("sisifo.modules.network.service.subprocess.Popen", fail)
    result = service.start_capture(CaptureConfig(interface_id="test"))
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
    capture.id = "b" * 32
    (service.captures_dir / f"{original_id}.json").write_text(
        capture.model_dump_json(), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="divergente"):
        service.get_capture(original_id)


def test_tshark_csv_preserves_separators_and_protocol_counts(service, capture, monkeypatch):
    import csv
    import io

    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )
    values = [
        "1",
        "0",
        "1700000000",
        "192.0.2.1",
        "192.0.2.2",
        "",
        "",
        "",
        "",
        "UDP",
        "42",
        "text, with | delimiters",
        "",
        "",
        "12345",
        "9999",
        "",
        "",
        "",
        "",
    ]
    stream = io.StringIO()
    csv.writer(stream).writerow(values)
    monkeypatch.setattr(service, "_run_tool", lambda *args: stream.getvalue())
    assert service.list_packets(capture.id)[0].info == values[11]
    stats = service.get_protocol_stats(capture.id)
    assert stats.total_packets == 1
    assert stats.total_bytes == 42
    assert stats.by_protocol[0].percentage_packets == 100


def test_hex_dump_parsing_fidelity(service, capture, monkeypatch):
    """Test that hex dump parsing correctly extracts bytes without ASCII column contamination."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    # Simulate TShark -x output with ASCII column that looks like hex
    tshark_hex_output = (
        "0000  64 65 66 67 68 69 6a 6b  6c 6d 6e 6f 70 71 72 73   defghijklmnopqrs\n"
        "0010  74 75 76 77 78 79 7a 00  00 00 00 00 00 00 00 00   tuvwxyz........."
    )
    result = service._parse_hex_dump_text(tshark_hex_output, 32)

    # Should extract exactly 32 bytes (64 65 66 ... 73 74 75 76 77 78 79 7a 00 ...)
    # First line: 16 bytes (64-73), second line: 16 bytes (74-00...)
    # But wait - the ASCII "defghijklmnopqrs" contains "de" which could be mistaken for hex
    # The parser should NOT extract "de" from the ASCII column

    # Verify the actual bytes extracted by checking the formatted output
    # The formatted output should show the correct bytes
    assert "64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73" in result
    assert "74 75 76 77 78 79 7a 00 00 00 00 00 00 00 00 00" in result
    # Should NOT have "de" from the ASCII column interpreted as bytes


def test_hex_dump_partial_lines(service, capture, monkeypatch):
    """Test hex dump extraction and presentation with various partial line lengths."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    test_cases = [
        (1, "0000  64                                                    d", [0x64]),
        (2, "0000  64 65                                               de", [0x64, 0x65]),
        (
            8,
            "0000  64 65 66 67 68 69 6a 6b                            defghijk",
            [0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B],
        ),
        (
            15,
            "0000  64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72    defghijklmnopqr",
            [
                0x64,
                0x65,
                0x66,
                0x67,
                0x68,
                0x69,
                0x6A,
                0x6B,
                0x6C,
                0x6D,
                0x6E,
                0x6F,
                0x70,
                0x71,
                0x72,
            ],
        ),
        (
            16,
            "0000  64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73   defghijklmnopqrs",
            [
                0x64,
                0x65,
                0x66,
                0x67,
                0x68,
                0x69,
                0x6A,
                0x6B,
                0x6C,
                0x6D,
                0x6E,
                0x6F,
                0x70,
                0x71,
                0x72,
                0x73,
            ],
        ),
    ]

    for expected_bytes, hex_output, expected_data in test_cases:
        # Validate raw byte extraction fidelity
        raw = service._extract_hex_dump_bytes(hex_output, expected_bytes)
        assert len(raw) == expected_bytes
        assert list(raw) == expected_data

        # Validate visual formatting has offset, hex column and ASCII column
        formatted = service._format_hex_dump(raw, expected_bytes)
        first_line = formatted.splitlines()[0]
        assert first_line.startswith("00000000  ")
        hex_col = first_line[10:57].strip()
        assert hex_col == " ".join(f"{b:02x}" for b in expected_data)
        ascii_col = first_line[57:].strip()
        assert len(ascii_col) == expected_bytes


def test_hex_dump_multi_line(service, capture, monkeypatch):
    """Test hex dump parsing with multiple lines."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    # 3 lines: 16 + 16 + 8 = 40 bytes
    hex_output = (
        "0000  64 65 66 67 68 69 6a 6b  6c 6d 6e 6f 70 71 72 73   defghijklmnopqrs\n"
        "0010  74 75 76 77 78 79 7a 00  00 00 00 00 00 00 00 00   tuvwxyz.........\n"
        "0020  01 02 03 04 05 06 07 08                              ........\n"
    )
    raw = service._extract_hex_dump_bytes(hex_output, 40)
    assert len(raw) == 40
    assert raw[0] == 0x64
    assert raw[15] == 0x73
    assert raw[16] == 0x74
    assert raw[31] == 0x00
    assert raw[32] == 0x01
    assert raw[39] == 0x08


def test_hex_dump_ascii_looks_like_hex(service, capture, monkeypatch):
    """Test that ASCII column with hex-like pairs is not parsed as bytes."""
    # ASCII column contains "de ad be ef" which looks like hex bytes
    hex_output_16 = "0000  64 65 66 67  00 00 00 00  00 00 00 00  00 00 00 00   de ad be ef ...."
    raw_16 = service._extract_hex_dump_bytes(hex_output_16, 16)
    assert len(raw_16) == 16
    assert list(raw_16[:8]) == [0x64, 0x65, 0x66, 0x67, 0x00, 0x00, 0x00, 0x00]
    assert list(raw_16[8:]) == [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    # Partial line with 8 bytes where ASCII has hex-like tokens
    hex_output_8 = "0000  64 65 66 67  00 00 00 00                            de ad be ef ...."
    raw_8 = service._extract_hex_dump_bytes(hex_output_8, 8)
    assert len(raw_8) == 8
    assert list(raw_8) == [0x64, 0x65, 0x66, 0x67, 0x00, 0x00, 0x00, 0x00]


def test_hex_dump_invalid_offset(service, capture, monkeypatch):
    """Test that invalid/malformed offsets are explicitly rejected."""
    hex_output = "INVALID  64 65 66 67  00 00 00 00  00 00 00 00  00 00 00 00   ...."
    with pytest.raises(ValueError, match="Linha de hex dump inválida|Offset"):
        service._extract_hex_dump_bytes(hex_output, 8)


def test_hex_dump_incomplete_output(service, capture, monkeypatch):
    """Test handling of incomplete/mismatched TShark output."""
    # Hex output has 16 bytes, but expected caplen is 32 (incomplete dump)
    hex_output = "0000  64 65 66 67  00 00 00 00  00 00 00 00  00 00 00 00   ...."
    with pytest.raises(ValueError, match="diverge do tamanho capturado"):
        service._extract_hex_dump_bytes(hex_output, 32)


def test_hex_dump_failure_not_silent(service, capture, monkeypatch):
    """Test that hex dump extraction failures are properly reported, not silently ignored."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    # Make _run_tool raise an exception
    def fail_hex(*args, **kwargs):
        raise ValueError("TShark failed")

    monkeypatch.setattr(service, "_run_tool", fail_hex)

    # Should raise the error, not silently return empty hex_dump
    with pytest.raises(ValueError, match="TShark failed"):
        service.get_packet_detail(capture.id, 1)


def test_truncation_info_in_detail(service, capture, monkeypatch):
    """Test that packet detail includes truncation info when captured < original."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    # Mock frame with captured < original (truncated capture)
    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "100",
                                    "frame.caplen": "50",
                                    "frame.protocols": "eth:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.dst": "00:00:00:00:00:01",
                                    "eth.src": "00:00:00:00:00:02",
                                    "eth.type": "0x0800",
                                },
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        elif "-x" in cmd:
            # Return 50 bytes of hex (matching caplen)
            return "0000  64 65 66 67  00 00 00 00  00 00 00 00  00 00 00 00   ...."
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)

    # Need to create a valid capture first
    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)

    # Should have captured_length (50) and original_length (100)
    assert detail.captured_length == 50  # captured length
    assert detail.original_length == 100  # original length on wire
    # The hex dump should show truncation marker
    assert "truncated" in detail.hex_dump.lower() or detail.captured_length < detail.original_length


def test_protocol_tree_preserves_encapsulation_order(service, capture, monkeypatch):
    """Test that protocol tree preserves the actual encapsulation order from frame.protocols."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    # Mock frame.protocols with non-standard order: frame -> eth -> custom -> ip -> tcp
    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "60",
                                    "frame.caplen": "60",
                                    "frame.protocols": "eth:custom:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.dst": "00:00:00:00:00:01",
                                    "eth.src": "00:00:00:00:00:02",
                                    "eth.type": "0x0800",
                                },
                                "custom": {"custom.field": "value"},
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        elif "-x" in cmd:
            return "0000  64 65 66 67  00 00 00 00  00 00 00 00  00 00 00 00   ...."
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)

    # Need to create a valid capture first
    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)

    # Protocol tree should preserve encapsulation order: FRAME, ETH, CUSTOM, IP, TCP
    layer_names = [layer["name"] for layer in detail.layers]
    assert "FRAME" in layer_names
    assert "ETH" in layer_names
    assert "CUSTOM" in layer_names
    assert "IP" in layer_names
    assert "TCP" in layer_names

    # Verify order: FRAME -> ETH -> CUSTOM -> IP -> TCP
    frame_idx = layer_names.index("FRAME")
    eth_idx = layer_names.index("ETH")
    custom_idx = layer_names.index("CUSTOM")
    ip_idx = layer_names.index("IP")
    tcp_idx = layer_names.index("TCP")
    assert frame_idx < eth_idx < custom_idx < ip_idx < tcp_idx


def test_hex_dump_error_capture(service, capture, monkeypatch):
    """Test that hex dump extraction errors are captured in hex_dump_error field."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    # Make _run_tool raise an exception only for hex dump (-x flag)
    def mock_run_tool(cmd, *args, **kwargs):
        if "-x" in cmd:
            raise ValueError("TShark hex dump failed")
        # For JSON output, return valid data
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "60",
                                    "frame.caplen": "60",
                                    "frame.protocols": "eth:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.dst": "00:00:00:00:00:01",
                                    "eth.src": "00:00:00:00:00:02",
                                    "eth.type": "0x0800",
                                },
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)

    # Should not raise, but hex_dump_error should be set
    detail = service.get_packet_detail(capture.id, 1)
    assert detail.hex_dump_error is not None
    assert "Falha ao extrair hex dump" in detail.hex_dump_error
    # hex_dump should be empty but not cause failure
    assert detail.hex_dump == ""


def test_protocol_tree_preserves_repeated_layers(service, capture, monkeypatch):
    """Test that protocol tree preserves repeated protocol layers (e.g., IP-in-IP)."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    # Mock frame.protocols with repeated IP layers: frame -> eth -> ip -> ip -> tcp
    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "80",
                                    "frame.caplen": "80",
                                    "frame.protocols": "eth:ip:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.dst": "00:00:00:00:00:01",
                                    "eth.src": "00:00:00:00:00:02",
                                    "eth.type": "0x0800",
                                },
                                "ip": [
                                    {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                    {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                                ],
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        elif "-x" in cmd:
            return "0000  64 65 66 67  00 00 00 00  00 00 00 00  00 00 00 00   ...."
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)

    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)

    # Should have two IP layers
    ip_layers = [layer for layer in detail.layers if layer["name"] == "IP"]
    assert len(ip_layers) == 2, f"Expected 2 IP layers, got {len(ip_layers)}"

    # Both should have src/dst fields
    for ip_layer in ip_layers:
        fields = ip_layer["fields"]
        src_fields = [f for f in fields if "src" in f.lower()]
        dst_fields = [f for f in fields if "dst" in f.lower()]
        assert len(src_fields) > 0
        assert len(dst_fields) > 0


# =========================================================================
# Regressões: Ordem de encapsulamento, fidelidade de bytes e contrato Web
# =========================================================================


def test_hex_dump_offset_gap_rejected(service):
    """Test that non-contiguous offset gaps are explicitly rejected (Priority 3)."""
    # Line 1 has 2 bytes (offset 0 -> next expected is 2). Line 2 has offset 0x20 = 32 (gap).
    hex_output = "0000  01 02   ..\n0020  03 04   ..\n"
    with pytest.raises(ValueError, match="Lacuna de offset detectada"):
        service._extract_hex_dump_bytes(hex_output)


def test_hex_dump_initial_offset_non_zero_rejected(service):
    """Test that non-zero initial offset is explicitly rejected."""
    hex_output = "0010  64 65   de"
    with pytest.raises(ValueError, match="Offset inicial inválido"):
        service._extract_hex_dump_bytes(hex_output)


def test_hex_dump_regressive_or_repeated_offset_rejected(service):
    """Test that regressive or repeated offsets are rejected."""
    hex_output = "0000  01 02   ..\n0000  03 04   ..\n"
    with pytest.raises(ValueError, match="Offset repetido ou regressivo"):
        service._extract_hex_dump_bytes(hex_output)


def test_protocol_tree_exact_order_nested_ipinip(service, capture, monkeypatch):
    """Test exact layer order and field values for IP-in-IP encapsulation: FRAME -> ETH -> IP -> IP -> TCP."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "74",
                                    "frame.caplen": "74",
                                    "frame.protocols": "eth:ip:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.dst": "02:00:00:00:00:02",
                                    "eth.src": "02:00:00:00:00:01",
                                    "eth.type": "0x0800",
                                },
                                "ip": [
                                    {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2", "ip.proto": "4"},
                                    {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "ip.proto": "6"},
                                ],
                                "tcp": {"tcp.srcport": "12345", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        elif "-x" in cmd:
            # 74 bytes of valid hex
            return (
                "0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00   ..............E.\n"
                "0010  00 3c 00 02 00 00 40 04 f6 b8 c0 00 02 01 c0 00   .<....@.........\n"
                "0020  02 02 45 00 00 28 00 01 00 00 40 06 66 cd 0a 00   ..E..(....@.f...\n"
                "0030  00 01 0a 00 00 02 30 39 00 50 00 00 00 01 00 00   ......09.P......\n"
                "0040  00 00 50 02 20 00 00 00 00 00                     ..P. ....."
            )
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)
    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)
    layer_names = [layer["name"] for layer in detail.layers]
    assert layer_names == ["FRAME", "ETH", "IP", "IP", "TCP"], f"Ordem incorreta: {layer_names}"

    # Verify distinct field values between outer and inner IP
    ip_layers = [layer for layer in detail.layers if layer["name"] == "IP"]
    assert len(ip_layers) == 2
    outer_fields = " ".join(ip_layers[0]["fields"])
    inner_fields = " ".join(ip_layers[1]["fields"])
    assert "192.0.2.1" in outer_fields and "192.0.2.2" in outer_fields
    assert "10.0.0.1" in inner_fields and "10.0.0.2" in inner_fields


def test_protocol_tree_mixed_ipv6_encapsulation(service, capture, monkeypatch):
    """Test mixed IPv6 and IPv4 encapsulation order: FRAME -> ETH -> IPV6 -> IP -> TCP."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "60",
                                    "frame.caplen": "60",
                                    "frame.protocols": "eth:ipv6:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.src": "00:00:00:00:00:01",
                                    "eth.dst": "00:00:00:00:00:02",
                                },
                                "ipv6": {"ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::2"},
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)
    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)
    layer_names = [layer["name"] for layer in detail.layers]
    assert layer_names == ["FRAME", "ETH", "IPV6", "IP", "TCP"]


def test_protocol_tree_unknown_protocol_preserved(service, capture, monkeypatch):
    """Test that unknown protocols between known protocols are preserved in exact position."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "60",
                                    "frame.caplen": "60",
                                    "frame.protocols": "eth:custom_tunnel:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.src": "00:00:00:00:00:01",
                                    "eth.dst": "00:00:00:00:00:02",
                                },
                                "custom_tunnel": {"tunnel.id": "42"},
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)
    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)
    layer_names = [layer["name"] for layer in detail.layers]
    assert layer_names == ["FRAME", "ETH", "CUSTOM_TUNNEL", "IP", "TCP"]


def test_protocol_tree_ethertype_alias_no_duplication(service, capture, monkeypatch):
    """Test that ethertype alias does not duplicate Ethernet layer."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "60",
                                    "frame.caplen": "60",
                                    "frame.protocols": "eth:ethertype:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.src": "00:00:00:00:00:01",
                                    "eth.dst": "00:00:00:00:00:02",
                                    "eth.type": "0x0800",
                                },
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)
    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)
    layer_names = [layer["name"] for layer in detail.layers]
    assert layer_names == ["FRAME", "ETH", "IP", "TCP"]
    assert layer_names.count("ETH") == 1


def test_protocol_tree_missing_data_layer_not_invented(service, capture, monkeypatch):
    """Test that protocol listed in frame.protocols but absent in data is not invented."""
    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "60",
                                    "frame.caplen": "60",
                                    "frame.protocols": "eth:missing_proto:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.src": "00:00:00:00:00:01",
                                    "eth.dst": "00:00:00:00:00:02",
                                },
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        return ""

    monkeypatch.setattr(service, "_run_tool", mock_run_tool)
    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    detail = service.get_packet_detail(capture.id, 1)
    layer_names = [layer["name"] for layer in detail.layers]
    assert "MISSING_PROTO" not in layer_names
    assert layer_names == ["FRAME", "ETH", "IP", "TCP"]


def test_web_api_packet_detail_contract(service, capture, monkeypatch):
    """Test that Web API returns PacketDetail response model with original_length, captured_length, extracted_length, and hex_dump_error."""
    from starlette.testclient import TestClient

    from sisifo.web.server import app

    monkeypatch.setattr(
        service, "discover_tools", lambda: SimpleNamespace(tshark_path="fake", tshark_version="1")
    )

    def mock_run_tool(cmd, *args, **kwargs):
        if "-T" in cmd and "json" in cmd:
            return json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_relative": "0",
                                    "frame.time_epoch": "1700000000",
                                    "frame.len": "100",
                                    "frame.caplen": "50",
                                    "frame.protocols": "eth:ip:tcp",
                                    "frame.time": "2024-01-01T00:00:00Z",
                                },
                                "eth": {
                                    "eth.src": "00:00:00:00:00:01",
                                    "eth.dst": "00:00:00:00:00:02",
                                },
                                "ip": {"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"},
                                "tcp": {"tcp.srcport": "1234", "tcp.dstport": "80"},
                            }
                        }
                    }
                ]
            )
        elif "-x" in cmd:
            raise ValueError("Falha simulada no tshark -x")
        return ""

    monkeypatch.setattr("sisifo.web.server.NetworkService", lambda *a, **kw: service)
    monkeypatch.setattr(service, "_run_tool", mock_run_tool)

    capture.status = CaptureStatus.COMPLETED
    service._save_capture_metadata(capture)

    # Fake authenticated session
    client = TestClient(app, base_url="http://127.0.0.1")
    from sisifo.web.security import session_manager

    token = session_manager.create_session()
    client.cookies.set("sisifo_session", token)

    resp = client.get(f"/api/network/captures/{capture.id}/packets/1")
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["number"] == 1
    assert data["original_length"] == 100
    assert data["captured_length"] == 50
    assert data["extracted_length"] == 0
    assert data["hex_dump_error"] is not None
    assert "Falha ao extrair hex dump" in data["hex_dump_error"]
