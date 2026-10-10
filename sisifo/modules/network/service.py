"""Core network service for capture, import, analysis, and reporting."""

import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from sisifo.core.execution import BudgetExceeded, Cancelled, Control, file_lock
from sisifo.core.session import atomic_write, data_root

from .models import (
    AIAnalysisInput,
    CaptureConfig,
    CaptureLimits,
    CaptureResult,
    CaptureSource,
    CaptureStatus,
    ConversationStats,
    DisplayFilter,
    EndpointStats,
    NetworkDiagnostics,
    NetworkInterface,
    PacketDetail,
    PacketSummary,
    ProtocolHierarchyItem,
    ProtocolStats,
)


class OrderedMultiDict(dict):
    """Dictionary that preserves all duplicate keys and pairs in insertion order."""

    def __init__(self, pairs: Optional[list[tuple[str, Any]]] = None):
        super().__init__()
        self._pairs: list[tuple[str, Any]] = []
        self._multikeys: set[str] = set()
        if pairs:
            for k, v in pairs:
                self._pairs.append((k, v))
                if k not in self:
                    super().__setitem__(k, v)
                elif k in self._multikeys:
                    super().__getitem__(k).append(v)
                else:
                    self._multikeys.add(k)
                    super().__setitem__(k, [super().__getitem__(k), v])


class NetworkService:
    """Shared service for network monitoring and analysis operations."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or data_root()
        self.captures_dir = self.data_dir / "network" / "captures"
        self.indexes_dir = self.data_dir / "network" / "indexes"
        self.reports_dir = self.data_dir / "network" / "reports"
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.indexes_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self._dumpcap_path: Optional[str] = None
        self._tshark_path: Optional[str] = None
        self._wireshark_path: Optional[str] = None
        self._diagnostics: Optional[NetworkDiagnostics] = None
        # Only reconcile abandoned records when no capture owner is alive.
        try:
            with file_lock(self.captures_dir / ".capture.lock"):
                for record in self.captures_dir.glob("*.json"):
                    try:
                        capture = self.get_capture(record.stem)
                        if capture.status in {CaptureStatus.RUNNING, CaptureStatus.PENDING}:
                            capture.status = CaptureStatus.INTERRUPTED
                            capture.error = "Executor interrompido; captura nÃ£o repetida"
                            capture.finished_at = datetime.now(UTC)
                            self._save_capture_metadata(capture)
                    except (ValueError, OSError):
                        continue
        except ValueError:
            pass

    def _path(self, root, name):
        root = root.resolve()
        path = (root / name).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Caminho fora do armazenamento de rede")
        return path

    def _id(self, capture_id):
        if not re.fullmatch(r"[a-f0-9]{32}", capture_id):
            raise ValueError("ID de captura invÃ¡lido")
        return capture_id

    def _capture_file(self, result):
        return self._path(self.captures_dir, result.file_path)

    def _run_tool(self, cmd, control=None, timeout=120):
        supplied_control = control is not None
        control = control or Control(timeout)
        deadline = min(control.deadline, time.monotonic() + timeout)
        proc = None
        # Disk-backed pipes bound memory and avoid pipe deadlocks.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                control.check()
                proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
                while True:
                    control.check()
                    if time.monotonic() >= deadline:
                        raise ValueError("Ferramenta excedeu o limite de tempo")
                    if os.fstat(stdout.fileno()).st_size > 32 * 1024 * 1024 or os.fstat(stderr.fileno()).st_size > 1024 * 1024:
                        raise ValueError("SaÃ­da da ferramenta excedeu o limite")
                    if proc.poll() is not None:
                        break
                    control.cancelled.wait(0.05)
                if proc.returncode != 0:
                    raise ValueError(f"Ferramenta rejeitou arquivo/filtro ou falhou (cÃ³digo {proc.returncode})")
                stdout.seek(0)
                return stdout.read().decode("utf-8", errors="replace")
            except BudgetExceeded:
                if supplied_control:
                    raise
                raise ValueError("Ferramenta excedeu o limite de tempo") from None
            except OSError:
                raise ValueError("NÃ£o foi possÃ­vel executar a ferramenta de rede") from None
            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)

    # -------------------------------------------------------------------------
    # Dependency discovery
    # -------------------------------------------------------------------------

    def discover_tools(self) -> NetworkDiagnostics:
        """Discover Wireshark suite tools and system capabilities."""
        if self._diagnostics is not None:
            return self._diagnostics

        platform = sys.platform
        is_docker = os.path.exists("/.dockerenv") or os.getenv("SISIFO_DATA_DIR") == "/data"

        dumpcap_path = self._find_executable("dumpcap")
        tshark_path = self._find_executable("tshark")
        wireshark_path = self._find_executable("wireshark")

        dumpcap_version = self._get_version(dumpcap_path, ["-v"]) if dumpcap_path else None
        tshark_version = self._get_version(tshark_path, ["-v"]) if tshark_path else None

        npcap_version = None
        libpcap_version = None
        if platform == "win32":
            npcap_version = self._get_npcap_version()
        else:
            libpcap_version = self._get_libpcap_version()

        interfaces = self._discover_interfaces(dumpcap_path)
        capture_permissions, permission_details = self._check_capture_permissions(dumpcap_path, platform, is_docker)

        storage_path = str(self.captures_dir)
        storage_available_mib = self._get_available_storage_mib(self.captures_dir)

        active_captures = self._count_active_captures()
        recent_captures = self.list_captures(limit=10)

        self._diagnostics = NetworkDiagnostics(
            platform=platform,
            is_docker=is_docker,
            dumpcap_path=dumpcap_path,
            tshark_path=tshark_path,
            wireshark_path=wireshark_path,
            npcap_version=npcap_version,
            libpcap_version=libpcap_version,
            dumpcap_version=dumpcap_version,
            tshark_version=tshark_version,
            interfaces=interfaces,
            capture_permissions=capture_permissions,
            permission_details=permission_details,
            storage_path=storage_path,
            storage_available_mib=storage_available_mib,
            max_concurrent_captures=2,
            active_captures=active_captures,
            recent_captures=recent_captures,
        )
        return self._diagnostics

    def _find_executable(self, name: str) -> Optional[str]:
        """Find executable in PATH or common Wireshark install locations."""
        # First check PATH
        path = shutil.which(name)
        if path:
            return path

        # Common Windows locations
        if sys.platform == "win32":
            program_files = os.getenv("ProgramFiles", "C:\\Program Files")
            program_files_x86 = os.getenv("ProgramFiles(x86)", "C:\\Program Files (x86)")
            for base in [program_files, program_files_x86]:
                candidate = Path(base) / "Wireshark" / f"{name}.exe"
                if candidate.exists():
                    return str(candidate)

        return None

    def _get_version(self, path: Optional[str], args: list[str]) -> Optional[str]:
        """Get version string from executable."""
        if not path:
            return None
        try:
            result = subprocess.run(
                [path, *args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            # Version is typically in first line of stderr or stdout
            output = result.stdout or result.stderr
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if not lines:
                return None
            for line in lines:
                if re.search(r"\b(tshark|dumpcap|wireshark)\b.*\b\d+\.\d+", line, re.IGNORECASE):
                    return line
            return lines[0]
        except Exception:
            return None

    def _get_npcap_version(self) -> Optional[str]:
        """Get Npcap version on Windows."""
        try:
            result = subprocess.run(
                ["reg", "query", "HKLM\\SOFTWARE\\Npcap", "/v", "Version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Version" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[-1]
        except Exception:
            pass
        return None

    def _get_libpcap_version(self) -> Optional[str]:
        """Get libpcap version on Linux."""
        try:
            result = subprocess.run(
                ["dpkg", "-l", "libpcap*"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in result.stdout.splitlines():
                if line.startswith("ii") and "libpcap" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        except Exception:
            pass
        return None

    def _discover_interfaces(self, dumpcap_path: Optional[str]) -> list[NetworkInterface]:
        """Discover available network interfaces using dumpcap -D."""
        interfaces = []
        if not dumpcap_path:
            return interfaces

        try:
            result = subprocess.run(
                [dumpcap_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            # Output format: "1. \\Device\\NPF_{...} (Description)"
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                match = re.match(r"^\d+\.\s+(.+?)\s*\((.+?)\)\s*$", line)
                if match:
                    iface_id = match.group(1)
                    description = match.group(2)
                    interfaces.append(NetworkInterface(
                        id=iface_id,
                        name=description,
                        description=description,
                        loopback="loopback" in description.lower() or "lo" in iface_id.lower(),
                    ))
        except Exception:
            pass
        return interfaces

    def _check_capture_permissions(
        self, dumpcap_path: Optional[str], platform: str, is_docker: bool
    ) -> tuple[bool, str]:
        """Check if we have permission to capture packets."""
        if not dumpcap_path:
            return False, "dumpcap nÃ£o encontrado"

        if is_docker:
            return False, "Captura nativa nÃ£o disponÃ­vel no Docker; use importaÃ§Ã£o offline"

        if platform == "win32":
            # On Windows with Npcap, check if we can open an interface
            # This is a basic check; actual permission depends on Npcap service
            return True, "Windows: Npcap necessÃ¡rio; execute como administrador se falhar"
        else:
            # On Linux, check capabilities
            try:
                result = subprocess.run(
                    ["getcap", dumpcap_path],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if "cap_net_admin" in result.stdout or "cap_net_raw" in result.stdout:
                    return True, "Linux: dumpcap tem capabilities de rede"
                # Check if running as root
                if os.geteuid() == 0:
                    return True, "Linux: executando como root"
                return False, "Linux: dumpcap precisa de capabilities (cap_net_admin, cap_net_raw) ou root"
            except Exception:
                return False, "NÃ£o foi possÃ­vel verificar permissÃµes de captura"

    def _get_available_storage_mib(self, path: Path) -> int:
        """Get available storage in MiB."""
        try:
            stat = shutil.disk_usage(path)
            return stat.free // (1024 * 1024)
        except Exception:
            return 0

    def _count_active_captures(self) -> int:
        """Count currently running captures."""
        count = 0
        for capture_file in self.captures_dir.glob("*.json"):
            try:
                data = json.loads(capture_file.read_text(encoding="utf-8"))
                if data.get("status") in {"pending", "running"}:
                    count += 1
            except Exception:
                pass
        return count

    # -------------------------------------------------------------------------
    # Capture operations
    # -------------------------------------------------------------------------

    def validate_capture_config(self, config: CaptureConfig) -> tuple[bool, str]:
        """Validate capture configuration before starting."""
        diagnostics = self.discover_tools()

        if not diagnostics.dumpcap_path:
            return False, "dumpcap nÃ£o encontrado; instale Wireshark/TShark"

        if not diagnostics.capture_permissions:
            return False, f"Sem permissÃ£o para captura: {diagnostics.permission_details}"

        if diagnostics.is_docker:
            return False, "Captura nativa nÃ£o disponÃ­vel no Docker; use importaÃ§Ã£o offline"

        # Check interface exists
        interface_ids = [i.id for i in diagnostics.interfaces]
        if config.interface_id not in interface_ids:
            return False, f"Interface '{config.interface_id}' nÃ£o encontrada"

        # Check storage
        max_size_mib = config.limits.max_file_size_mib
        if diagnostics.storage_available_mib < max_size_mib:
            return False, f"EspaÃ§o insuficiente: {diagnostics.storage_available_mib} MiB disponÃ­veis, {max_size_mib} MiB necessÃ¡rios"

        # Check concurrent captures
        if diagnostics.active_captures >= config.limits.max_concurrent_captures:
            return False, f"Limite de capturas simultÃ¢neas atingido ({diagnostics.active_captures}/{config.limits.max_concurrent_captures})"

        return True, "ConfiguraÃ§Ã£o vÃ¡lida"

    def start_capture(self, config, control=None, progress_callback=None):
        # One owner across native CLI processes and web workers.
        with file_lock(self.captures_dir / ".capture.lock"):
            return self._start_capture(config, control, progress_callback)

    def _start_capture(
        self,
        config: CaptureConfig,
        control: Optional[Control] = None,
        progress_callback=None,
    ) -> CaptureResult:
        """Start a packet capture using dumpcap."""
        diagnostics = self.discover_tools()
        valid, msg = self.validate_capture_config(config)
        if not valid:
            raise ValueError(msg)

        if config.ring_buffer or config.output_directory:
            raise ValueError("RotaÃ§Ã£o e diretÃ³rio personalizado ainda nÃ£o suportados com seguranÃ§a")

        # Create capture record
        capture_id = uuid4().hex
        timestamp = datetime.now(UTC).isoformat().replace(":", "-").replace(".", "-")
        output_file = self.captures_dir / f"{capture_id}_{timestamp}.pcapng"

        # Build dumpcap command
        cmd = [diagnostics.dumpcap_path]
        cmd.extend(["-i", config.interface_id])
        cmd.extend(["-w", str(output_file)])

        # Capture filter (BPF syntax)
        if config.capture_filter.expression:
            cmd.extend(["-f", config.capture_filter.expression])

        # Ring buffer
        if config.ring_buffer:
            cmd.extend(["-b", f"files:{config.ring_buffer_files}"])
            # Also add size-based rotation
            cmd.extend(["-b", f"filesize:{config.limits.max_file_size_mib * 1024}"])

        # Limits
        cmd.extend(["-a", f"duration:{config.limits.max_duration_seconds}"])
        cmd.extend(["-c", str(config.limits.max_packets)])
        cmd.extend(["-a", f"filesize:{config.limits.max_file_size_mib * 1024}"])

        # Create initial metadata
        result = CaptureResult(
            id=capture_id,
            source=CaptureSource.CAPTURED,
            status=CaptureStatus.RUNNING,
            created_at=datetime.now(UTC),
            started_at=datetime.now(UTC),
            interface_id=config.interface_id,
            interface_name=self._get_interface_name(config.interface_id),
            capture_filter=config.capture_filter.expression,
            limits=config.limits,
            file_path=str(output_file),
            environment="docker" if diagnostics.is_docker else "native",
            is_docker=diagnostics.is_docker,
            dumpcap_version=diagnostics.dumpcap_version,
            tshark_version=diagnostics.tshark_version,
        )
        self._save_capture_metadata(result)

        control = control or Control(config.limits.max_duration_seconds + 30)
        if progress_callback:
            control.progress_callback = progress_callback

        proc = None
        stop_file = self._path(self.captures_dir, f"{capture_id}.stop")
        output_log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        try:
            control.progress(f"Iniciando captura na interface {config.interface_id}...")
            proc = subprocess.Popen(
                cmd,
                stdout=output_log,
                stderr=output_log,
                text=True,
            )

            # Monitor process
            while True:
                if stop_file.exists():
                    control.cancelled.set()
                control.check()
                if os.fstat(output_log.fileno()).st_size > 1024 * 1024:
                    raise ValueError("SaÃ­da da captura excedeu o limite")
                ret = proc.poll()
                if ret is not None:
                    break
                time.sleep(0.5)
                if progress_callback:
                    control.progress(f"Capturando... (tempo decorrido: {int(time.monotonic() - control.deadline + config.limits.max_duration_seconds)}s)")

            control.check()
            if stop_file.exists():
                raise Cancelled()
            output_log.seek(0)
            stdout, stderr = "", output_log.read()

            # Update result with outcome
            result.finished_at = datetime.now(UTC)
            if ret == 0:
                result.status = CaptureStatus.COMPLETED
            elif ret == 1:
                # Check if it was cancelled/timeout
                if "interrupted" in stderr.lower() or "cancelled" in stderr.lower():
                    result.status = CaptureStatus.CANCELLED
                else:
                    result.status = CaptureStatus.FAILED
                    result.error = "Dumpcap falhou; verifique interface e filtro"
            else:
                result.status = CaptureStatus.FAILED
                result.error = f"Dumpcap saiu com cÃ³digo {ret}"

            # Parse dumpcap output for statistics
            self._parse_dumpcap_output(result, stdout, stderr)

            # Calculate file hash
            if output_file.exists():
                result.file_size = output_file.stat().st_size
                result.file_sha256 = self._calculate_sha256(output_file)

        except (Cancelled, KeyboardInterrupt):
            result.status = CaptureStatus.CANCELLED
            result.error = "Cancelado pelo usuÃ¡rio"
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        except BudgetExceeded:
            result.status = CaptureStatus.PARTIAL
            result.error = "Limite de tempo atingido"
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        except Exception as e:
            result.status = CaptureStatus.FAILED
            result.error = str(e)
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        finally:
            output_log.close()
            result.finished_at = datetime.now(UTC)
            if output_file.exists():
                result.file_size = output_file.stat().st_size
                result.file_sha256 = self._calculate_sha256(output_file)
            self._save_capture_metadata(result)
            stop_file.unlink(missing_ok=True)

        return result

    def _get_interface_name(self, interface_id: str) -> str:
        """Get human-readable name for interface ID."""
        diagnostics = self.discover_tools()
        for iface in diagnostics.interfaces:
            if iface.id == interface_id:
                return iface.name
        return interface_id

    def _parse_dumpcap_output(self, result: CaptureResult, stdout: str, stderr: str):
        """Parse dumpcap output for packet counts and drops."""
        output = stdout + "\n" + stderr
        # dumpcap output: "File: /path/to/file.pcapng\nPackets captured: 123\nPackets dropped: 456\nPackets received: 789"
        for line in output.splitlines():
            line = line.strip()
            if "Packets captured:" in line:
                try:
                    result.packet_count = int(line.split(":")[-1].strip())
                except Exception:
                    pass
            elif "Packets dropped:" in line:
                try:
                    result.dropped_packets = int(line.split(":")[-1].strip())
                except Exception:
                    pass

    def _calculate_sha256(self, path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _save_capture_metadata(self, result: CaptureResult):
        """Save capture metadata to JSON file."""
        metadata_file = self._path(self.captures_dir, f"{self._id(result.id)}.json")
        atomic_write(metadata_file, result.model_dump_json(indent=2))

    # -------------------------------------------------------------------------
    # Import operations
    # -------------------------------------------------------------------------

    def import_pcap(
        self,
        file_path: Path,
        control: Optional[Control] = None,
        progress_callback=None,
    ) -> CaptureResult:
        """Import and validate a PCAP/PCAPNG file."""
        if not file_path.exists():
            raise ValueError("Arquivo nÃ£o encontrado")

        if file_path.stat().st_size > 500 * 1024 * 1024:  # 500 MiB limit
            raise ValueError("Arquivo excede 500 MiB")

        # Validate file with capinfos
        diagnostics = self.discover_tools()
        if not diagnostics.tshark_path:
            raise ValueError("tshark nÃ£o encontrado; necessÃ¡rio para validaÃ§Ã£o")

        control = control or Control(300)
        if progress_callback:
            control.progress_callback = progress_callback

        # Get file info using capinfos (part of Wireshark)
        capinfos_path = shutil.which("capinfos")
        if not capinfos_path:
            # Try same directory as tshark
            tshark_dir = Path(diagnostics.tshark_path).parent
            candidate = tshark_dir / ("capinfos.exe" if sys.platform == "win32" else "capinfos")
            if candidate.exists():
                capinfos_path = str(candidate)

        if not capinfos_path:
            raise ValueError("capinfos nÃ£o encontrado; necessÃ¡rio para validaÃ§Ã£o de PCAP")

        control.progress("Validando arquivo PCAP...")
        output = self._run_tool([capinfos_path, "-M", "-S", str(file_path.resolve())], control, 60)
        info = self._parse_capinfos(output)

        capture_id = uuid4().hex
        timestamp = datetime.now(UTC).isoformat().replace(":", "-").replace(".", "-")

        # Copy file to captures directory
        dest_file = self.captures_dir / f"{capture_id}_{timestamp}{file_path.suffix}"
        shutil.copy2(file_path, dest_file)

        result = CaptureResult(
            id=capture_id,
            source=CaptureSource.IMPORTED,
            status=CaptureStatus.COMPLETED,
            created_at=datetime.now(UTC),
            started_at=datetime.fromisoformat(info.get("start_time", datetime.now(UTC).isoformat())),
            finished_at=datetime.fromisoformat(info.get("end_time", datetime.now(UTC).isoformat())),
            capture_filter=info.get("capture_filter"),
            display_filter="",
            limits=CaptureLimits(),
            file_path=str(dest_file),
            file_size=dest_file.stat().st_size,
            file_sha256=self._calculate_sha256(dest_file),
            packet_count=info.get("packet_count", 0),
            dropped_packets=info.get("dropped_packets", 0),
            dropped_by_interface=info.get("dropped_by_interface", 0),
            tshark_version=diagnostics.tshark_version,
            dumpcap_version=diagnostics.dumpcap_version,
            environment="docker" if diagnostics.is_docker else "native",
            is_docker=diagnostics.is_docker,
        )

        self._save_capture_metadata(result)
        return result

    def _parse_capinfos(self, output: str) -> dict:
        """Parse capinfos -M (machine readable) output."""
        info = {}
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                if key in {"number_of_packets", "packet_count"}:
                    info["packet_count"] = int(value) if value.isdigit() else 0
                elif key == "dropped_packets":
                    info["dropped_packets"] = int(value) if value.isdigit() else 0
                elif key == "capture_filter":
                    info["capture_filter"] = value
                elif key in {"start_time", "first_packet_time"}:
                    info["start_time"] = datetime.fromtimestamp(float(value), UTC).isoformat()
                elif key in {"end_time", "last_packet_time"}:
                    info["end_time"] = datetime.fromtimestamp(float(value), UTC).isoformat()
        return info

    # -------------------------------------------------------------------------
    # Analysis operations
    # -------------------------------------------------------------------------

    def _rows(self, capture_id, display_filter=None, control=None):
        result = self.get_capture(capture_id)
        if result.status not in {CaptureStatus.COMPLETED, CaptureStatus.PARTIAL, CaptureStatus.CANCELLED}:
            raise ValueError("Captura nÃ£o finalizada")
        path = self._capture_file(result)
        if not path.is_file():
            raise ValueError("Arquivo de captura nÃ£o encontrado")
        fingerprint = self._calculate_sha256(path)
        if result.file_sha256 and fingerprint != result.file_sha256:
            raise ValueError("Integridade da captura divergente")
        diag = self.discover_tools()
        if not diag.tshark_path:
            raise ValueError("tshark nÃ£o encontrado")
        expression = display_filter.expression if display_filter else ""
        key = hashlib.sha256(json.dumps([2, fingerprint, expression, diag.tshark_version]).encode()).hexdigest()
        folder = self._path(self.indexes_dir, self._id(capture_id))
        folder.mkdir(exist_ok=True)
        cache = self._path(folder, key + ".json")
        if cache.exists():
            try:
                return json.loads(cache.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                pass
        fields = ["frame.number", "frame.time_relative", "frame.time_epoch", "ip.src", "ip.dst",
                  "ipv6.src", "ipv6.dst", "eth.src", "eth.dst", "_ws.col.Protocol", "frame.len",
                  "_ws.col.Info", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
                  "dns.qry.name", "tcp.analysis.retransmission", "tcp.analysis.out_of_order",
                  "tcp.analysis.zero_window"]
        cmd = [diag.tshark_path, "-n", "-r", str(path), "-T", "fields",
               "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
        for field in fields:
            cmd.extend(["-e", field])
        if expression:
            cmd.extend(["-Y", expression])
        output = self._run_tool(cmd, control)
        rows = []
        for values in csv.reader(io.StringIO(output)):
            if len(values) != len(fields):
                raise ValueError("SaÃ­da inesperada do TShark")
            rows.append(dict(zip(fields, values)))
        if self._calculate_sha256(path) != fingerprint:
            raise ValueError("Captura alterada durante anÃ¡lise")
        atomic_write(cache, json.dumps(rows, ensure_ascii=False))
        return rows

    def analyze_capture(self, capture_id, display_filter=None, control=None, progress_callback=None):
        self._rows(capture_id, display_filter, control)
        return self.get_capture(capture_id)

    @staticmethod
    def _addresses(row):
        return (row["ip.src"] or row["ipv6.src"] or row["eth.src"],
                row["ip.dst"] or row["ipv6.dst"] or row["eth.dst"])

    def get_protocol_stats(self, capture_id, display_filter=None, control=None):
        rows = self._rows(capture_id, display_filter, control)
        groups = {}
        total_bytes = sum(int(r["frame.len"]) for r in rows)
        for row in rows:
            group = groups.setdefault(row["_ws.col.Protocol"], [0, 0])
            group[0] += 1
            group[1] += int(row["frame.len"])
        return ProtocolStats(capture_id=capture_id, total_packets=len(rows), total_bytes=total_bytes,
            by_protocol=[ProtocolHierarchyItem(protocol=name, packets=counts[0], bytes=counts[1],
                percentage_packets=100 * counts[0] / len(rows),
                percentage_bytes=100 * counts[1] / total_bytes if total_bytes else 0)
                for name, counts in sorted(groups.items())])

    def get_endpoints(self, capture_id, display_filter=None, control=None):
        endpoints = {}
        for row in self._rows(capture_id, display_filter, control):
            src, dst = self._addresses(row)
            for address, direction in [(src, "tx"), (dst, "rx")]:
                ep = endpoints.setdefault(address, EndpointStats(address=address,
                    type="IPv4" if row["ip.src"] else "IPv6" if row["ipv6.src"] else "Ethernet"))
                setattr(ep, "packets_" + direction, getattr(ep, "packets_" + direction) + 1)
                setattr(ep, "bytes_" + direction, getattr(ep, "bytes_" + direction) + int(row["frame.len"]))
        return sorted(endpoints.values(), key=lambda e: e.bytes_rx + e.bytes_tx, reverse=True)

    def get_conversations(self, capture_id, display_filter=None, control=None):
        conversations = {}
        for row in self._rows(capture_id, display_filter, control):
            src, dst = self._addresses(row)
            protocol = "TCP" if row["tcp.srcport"] else "UDP" if row["udp.srcport"] else row["_ws.col.Protocol"]
            if protocol in {"TCP", "UDP"}:
                src = f"[{src}]:{row[protocol.lower() + '.srcport']}"
                dst = f"[{dst}]:{row[protocol.lower() + '.dstport']}"
            a, b = sorted([src, dst])
            t = float(row["frame.time_relative"])
            conv = conversations.setdefault((protocol, a, b), ConversationStats(
                endpoint_a=a, endpoint_b=b, protocol=protocol, start_time=t, end_time=t))
            size = int(row["frame.len"])
            conv.packets += 1
            conv.bytes += size
            direction = "a_to_b" if src == a else "b_to_a"
            setattr(conv, "packets_" + direction, getattr(conv, "packets_" + direction) + 1)
            setattr(conv, "bytes_" + direction, getattr(conv, "bytes_" + direction) + size)
            conv.start_time = min(conv.start_time, t)
            conv.end_time = max(conv.end_time, t)
            conv.duration = conv.end_time - conv.start_time
        return sorted(conversations.values(), key=lambda c: c.bytes, reverse=True)

    def list_packets(
        self,
        capture_id: str,
        display_filter: Optional[DisplayFilter] = None,
        offset: int = 0,
        limit: int = 100,
        control=None,
    ) -> list[PacketSummary]:
        """List packets with pagination."""
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("PaginaÃ§Ã£o invÃ¡lida")
        packets = []
        for row in self._rows(capture_id, display_filter, control)[offset:offset + limit]:
            src, dst = self._addresses(row)
            packets.append(PacketSummary(number=int(row["frame.number"]),
                time=float(row["frame.time_relative"]),
                time_iso=datetime.fromtimestamp(float(row["frame.time_epoch"]), UTC).isoformat(),
                source=src, destination=dst, protocol=row["_ws.col.Protocol"],
                length=int(row["frame.len"]), info=row["_ws.col.Info"]))
        return packets

    def get_packet_detail(
        self,
        capture_id: str,
        packet_number: int,
        control=None,
    ) -> PacketDetail:
        """Get detailed packet information including protocol tree and hex dump."""
        result = self.get_capture(capture_id)
        capture_file = self._capture_file(result)
        if not capture_file.exists():
            raise ValueError("Arquivo de captura não encontrado")

        diagnostics = self.discover_tools()
        if not diagnostics.tshark_path:
            raise ValueError("tshark não encontrado")

        # Use TShark JSON output for structured packet detail (protocol tree)
        # and text output with -x for hex dump (since -T json -x doesn't include frame_raw)
        cmd_json = [
            diagnostics.tshark_path,
            "-n",
            "-r", str(capture_file),
            "-Y", f"frame.number == {packet_number}",
            "-T", "json",
        ]

        output = self._run_tool(cmd_json, control=control, timeout=30)
        if not output.strip():
            raise ValueError("Pacote não encontrado")

        try:
            packets = json.loads(output, object_pairs_hook=OrderedMultiDict)
        except json.JSONDecodeError as e:
            raise ValueError(f"Saída JSON inválida do TShark: {e}") from None

        if not packets or not packets[0].get("_source", {}).get("layers"):
            raise ValueError("Pacote não encontrado ou sem camadas")

        packet_data = packets[0]["_source"]["layers"]
        frame = packet_data.get("frame", {})
        eth = packet_data.get("eth", {})
        ip = packet_data.get("ip", {})
        ipv6 = packet_data.get("ipv6", {})
        tcp = packet_data.get("tcp", {})
        udp = packet_data.get("udp", {})

        # Extract frame metadata
        number = int(frame.get("frame.number", packet_number))
        time_rel = float(frame.get("frame.time_relative", 0.0))
        time_epoch_str = str(frame.get("frame.time_epoch", "0.0"))
        # TShark JSON may return epoch as float string or ISO timestamp
        try:
            time_epoch = float(time_epoch_str)
        except ValueError:
            # Parse ISO timestamp like '2023-11-14T22:13:20.000000000Z'
            time_epoch = datetime.fromisoformat(time_epoch_str.replace("Z", "+00:00")).timestamp()
        time_iso = datetime.fromtimestamp(time_epoch, UTC).isoformat()
        length = int(frame.get("frame.len") or frame.get("frame.length", 0))
        caplen = int(frame.get("frame.cap_len") or frame.get("frame.caplen") or length)

        # Generate info summary from protocol layers since frame.info may not be in JSON
        info_parts = []
        if tcp:
            sport = tcp.get("tcp.srcport", "")
            dport = tcp.get("tcp.dstport", "")
            if sport and dport:
                info_parts.append(f"TCP {sport} => {dport}")
        if udp:
            sport = udp.get("udp.srcport", "")
            dport = udp.get("udp.dstport", "")
            if sport and dport:
                info_parts.append(f"UDP {sport} => {dport}")
        # Handle IP arrays (for IP-in-IP scenarios) and single IP objects
        ip_layers = ip if isinstance(ip, list) else [ip] if ip else []
        for ip_layer in ip_layers:
            if isinstance(ip_layer, dict):
                info_parts.append(f"IP {ip_layer.get('ip.src', '')} => {ip_layer.get('ip.dst', '')}")
        if ipv6:
            info_parts.append(f"IPv6 {ipv6.get('ipv6.src', '')} => {ipv6.get('ipv6.dst', '')}")
        info = " / ".join(info_parts) if info_parts else ""

        # Determine source/destination addresses
        first_ip = ip[0] if isinstance(ip, list) and ip else (ip if isinstance(ip, dict) else {})
        src = first_ip.get("ip.src") or ipv6.get("ipv6.src") or eth.get("eth.src") or ""
        dst = first_ip.get("ip.dst") or ipv6.get("ipv6.dst") or eth.get("eth.dst") or ""

        # Determine protocol (highest layer)
        protocol = frame.get("frame.protocols", "").split(":")[-1] if frame.get("frame.protocols") else ""
        if not protocol:
            for proto in ["tcp", "udp", "icmp", "dns", "http", "tls", "ssh", "arp"]:
                if proto in packet_data:
                    protocol = proto.upper()
                    break
            if not protocol:
                protocol = "Unknown"
        else:
            protocol = protocol.upper()

        # Build protocol tree layers from JSON
        layers = self._build_protocol_tree(packet_data)

        # Extract hex dump using text output with -x
        hex_dump = ""
        hex_dump_error = None
        extracted_length = 0
        cmd_hex = [
            diagnostics.tshark_path,
            "-n",
            "-r", str(capture_file),
            "-Y", f"frame.number == {packet_number}",
            "-x",  # Hex dump
        ]
        try:
            hex_output = self._run_tool(cmd_hex, control=control, timeout=15)
            raw_bytes = self._extract_hex_dump_bytes(hex_output, caplen=caplen)
            hex_dump = self._format_hex_dump(raw_bytes, caplen=caplen, original_length=length)
            extracted_length = len(raw_bytes)
        except (Cancelled, BudgetExceeded):
            raise
        except Exception as e:
            hex_dump_error = f"Falha ao extrair hex dump: {e}"

        return PacketDetail(
            number=number,
            time=time_rel,
            time_iso=time_iso,
            source=src,
            destination=dst,
            protocol=protocol,
            length=length,
            info=info,
            layers=layers,
            hex_dump=hex_dump,
            original_length=length,
            captured_length=caplen,
            extracted_length=extracted_length,
            hex_dump_error=hex_dump_error,
        )

    def get_dns_summary(self, capture_id, display_filter=None, control=None):
        return {"queries": [{"packet": int(r["frame.number"]), "name": r["dns.qry.name"]}
                for r in self._rows(capture_id, display_filter, control) if r["dns.qry.name"]]}

    def get_tcp_summary(self, capture_id, display_filter=None, control=None):
        rows = self._rows(capture_id, display_filter, control)
        return {name: sum(bool(r[field]) for r in rows) for name, field in [
            ("retransmissions", "tcp.analysis.retransmission"),
            ("out_of_order", "tcp.analysis.out_of_order"), ("zero_window", "tcp.analysis.zero_window")]}

    def generate_report(self, capture_id: str, display_filter: Optional[DisplayFilter] = None):
        """Generate a complete capture analysis report."""
        from .models import CaptureReport

        result = self.get_capture(capture_id)

        protocol_stats = self.get_protocol_stats(capture_id, display_filter)
        endpoints = self.get_endpoints(capture_id, display_filter)
        conversations = self.get_conversations(capture_id, display_filter)
        dns_summary = self.get_dns_summary(capture_id, display_filter)
        tcp_summary = self.get_tcp_summary(capture_id, display_filter)

        # Build anomalies list
        anomalies = []
        if tcp_summary.get("retransmissions", 0) > 0:
            anomalies.append(f"{tcp_summary['retransmissions']} retransmissÃµes TCP detectadas")
        if tcp_summary.get("out_of_order", 0) > 0:
            anomalies.append(f"{tcp_summary['out_of_order']} pacotes TCP fora de ordem")
        if tcp_summary.get("zero_window", 0) > 0:
            anomalies.append(f"{tcp_summary['zero_window']} janelas TCP zero detectadas")
        if result.dropped_packets > 0:
            anomalies.append(f"{result.dropped_packets} pacotes perdidos pela captura")
        if result.dropped_by_interface > 0:
            anomalies.append(f"{result.dropped_by_interface} pacotes perdidos pela interface")

        limitations = [
            "Captura observa apenas trÃ¡fego visÃ­vel na interface selecionada",
            "TrÃ¡fego criptografado (TLS/SSL) nÃ£o pode ser inspecionado sem chaves",
            "EstatÃ­sticas baseadas em dissecaÃ§Ã£o do TShark; podem diferir de ferramentas especializadas",
            "Filtros de exibiÃ§Ã£o aplicados pÃ³s-captura nÃ£o afetam pacotes jÃ¡ perdidos",
        ]

        if display_filter and display_filter.expression:
            limitations.append(f"Resultados filtrados por: {display_filter.expression}")

        report = CaptureReport(
            capture_id=result.id,
            summary=result,
            protocol_stats=protocol_stats,
            endpoints=endpoints[:50],  # Top 50
            conversations=conversations[:50],  # Top 50
            dns_summary=dns_summary,
            tcp_summary=tcp_summary,
            anomalies=anomalies,
            limitations=limitations,
        )

        # Save report
        report_file = self._path(self.reports_dir, f"{self._id(capture_id)}.json")
        atomic_write(report_file, report.model_dump_json(indent=2))

        return report

    def prepare_ai_analysis_input(
        self,
        capture_id: str,
        display_filter: Optional[DisplayFilter] = None,
    ) -> AIAnalysisInput:
        """Prepare sanitized capture summary for AI analysis."""
        result = self.get_capture(capture_id)
        protocol_stats = self.get_protocol_stats(capture_id, display_filter)
        endpoints = self.get_endpoints(capture_id, display_filter)
        conversations = self.get_conversations(capture_id, display_filter)
        dns_summary = self.get_dns_summary(capture_id, display_filter)
        tcp_summary = self.get_tcp_summary(capture_id, display_filter)

        duration = 0.0
        if result.started_at and result.finished_at:
            duration = (result.finished_at - result.started_at).total_seconds()

        anomalies = []
        if tcp_summary.get("retransmissions", 0) > 0:
            anomalies.append(f"RetransmissÃµes TCP: {tcp_summary['retransmissions']}")
        if tcp_summary.get("out_of_order", 0) > 0:
            anomalies.append(f"Pacotes fora de ordem: {tcp_summary['out_of_order']}")

        return AIAnalysisInput(
            capture_id=result.id,
            capture_source=result.source,
            duration_seconds=duration,
            total_packets=result.packet_count,
            total_bytes=result.file_size,
            protocol_distribution=protocol_stats.by_protocol[:20],
            top_endpoints=endpoints[:20],
            top_conversations=conversations[:20],
            dns_queries=dns_summary.get("queries", [])[:50],
            tcp_indicators=tcp_summary,
            anomalies=anomalies,
            supporting_packet_numbers=[],  # Would need deeper analysis
            limitations=[
                "Resumo baseado em estatÃ­sticas agregadas, nÃ£o payload completo",
                "ConteÃºdo criptografado nÃ£o incluÃ­do",
                "Apenas metadados e headers visÃ­veis sÃ£o analisados",
            ],
        )

    # -------------------------------------------------------------------------
    # Wireshark integration
    # -------------------------------------------------------------------------

    def open_in_wireshark(self, capture_id: str) -> bool:
        """Open capture file in Wireshark desktop application."""
        result = self.get_capture(capture_id)
        capture_file = self._capture_file(result)
        if not capture_file.exists():
            raise ValueError("Arquivo de captura nÃ£o encontrado")

        diagnostics = self.discover_tools()
        if not diagnostics.wireshark_path:
            raise ValueError("Wireshark desktop nÃ£o encontrado no sistema")

        try:
            subprocess.Popen([diagnostics.wireshark_path, str(capture_file)])
            return True
        except Exception as e:
            raise ValueError(f"Falha ao abrir Wireshark: {e}")

    # -------------------------------------------------------------------------
    # Capture management
    # -------------------------------------------------------------------------

    def get_capture(self, capture_id: str) -> CaptureResult:
        """Get capture metadata by ID."""
        metadata_file = self._path(self.captures_dir, f"{self._id(capture_id)}.json")
        if not metadata_file.exists():
            raise ValueError("Captura nÃ£o encontrada")
        try:
            data = json.loads(metadata_file.read_text(encoding="utf-8"))
            result = CaptureResult.model_validate(data)
        except (ValueError, OSError):
            raise ValueError("Metadados de captura invÃ¡lidos") from None
        if result.id != capture_id:
            raise ValueError("ID divergente nos metadados")
        self._capture_file(result)
        return result

    def list_captures(self, limit: int = 50) -> list[CaptureResult]:
        """List recent captures."""
        captures = []
        for metadata_file in sorted(self.captures_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            if len(captures) >= limit:
                break
            try:
                captures.append(self.get_capture(metadata_file.stem))
            except Exception:
                pass
        return captures

    def stop_capture(self, capture_id: str) -> CaptureResult:
        """Stop a running capture (mark for cancellation)."""
        result = self.get_capture(capture_id)
        if result.status in {CaptureStatus.RUNNING, CaptureStatus.PENDING}:
            atomic_write(self._path(self.captures_dir, f"{capture_id}.stop"), "stop")
        # Only the owning process can confirm termination and write terminal state.
        return result

    def delete_capture(self, capture_id: str, keep_file: bool = False) -> bool:
        """Delete capture metadata and optionally the capture file."""
        result = self.get_capture(capture_id)
        if result.status in {CaptureStatus.RUNNING, CaptureStatus.PENDING}:
            raise ValueError("Pare a captura antes de remover")

        # Delete metadata
        metadata_file = self._path(self.captures_dir, f"{self._id(capture_id)}.json")
        if metadata_file.exists():
            metadata_file.unlink()

        # Delete index directory
        index_dir = self._path(self.indexes_dir, self._id(capture_id))
        if index_dir.exists():
            shutil.rmtree(index_dir)

        # Delete report
        report_file = self._path(self.reports_dir, f"{self._id(capture_id)}.json")
        if report_file.exists():
            report_file.unlink()

        # Optionally delete capture file
        if not keep_file:
            capture_file = self._capture_file(result)
            if capture_file.exists():
                capture_file.unlink()

        return True

    # -------------------------------------------------------------------------
    # Helper methods for protocol tree and hex dump parsing
    # -------------------------------------------------------------------------

    def _build_protocol_tree(self, packet_data: dict) -> list[dict]:
        """Build protocol layer tree from TShark JSON output, preserving exact encapsulation order."""
        layers = []
        frame = packet_data.get("frame", {})
        protocols_str = frame.get("frame.protocols", "") if isinstance(frame, dict) else ""
        protocol_order = [p.strip() for p in protocols_str.split(":") if p.strip()]

        protocol_to_layer = {
            "frame": "frame",
            "eth": "eth",
            "ethertype": "eth",
            "vlan": "vlan",
            "ip": "ip",
            "ipv6": "ipv6",
            "arp": "arp",
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "icmpv6": "icmpv6",
            "dns": "dns",
            "http": "http",
            "tls": "tls",
            "ssl": "tls",
            "ssh": "ssh",
            "dhcp": "dhcp",
            "data": "data",
        }

        # Pseudo-protocols / sub-dissectors that do not represent standalone layers
        pseudo_protocols = {"ethertype"}

        available_by_name: dict[str, deque[tuple[str, dict]]] = defaultdict(deque)
        metadata_keys = {"frame.protocols", "frame.raw", "frame.encap_type", "frame_raw", "frame.encoding"}

        items = packet_data._pairs if hasattr(packet_data, "_pairs") else packet_data.items()
        for key, value in items:
            if key in metadata_keys:
                continue
            key_lower = key.lower()
            if isinstance(value, dict):
                available_by_name[key_lower].append((key, value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        available_by_name[key_lower].append((key, item))

        # Root FRAME layer always comes first
        if available_by_name.get("frame"):
            orig_name, frame_dict = available_by_name["frame"].popleft()
            layers.append({"name": "FRAME", "fields": self._extract_layer_fields(orig_name, frame_dict)})

        # Traverse encapsulation sequence
        for proto in protocol_order:
            proto_lower = proto.lower()
            if proto_lower == "frame":
                continue

            # Pseudo-protocols: only consume if dedicated layer exists; do NOT duplicate eth
            if proto_lower in pseudo_protocols:
                if available_by_name.get(proto_lower):
                    orig_name, layer_dict = available_by_name[proto_lower].popleft()
                    layers.append({"name": proto.upper(), "fields": self._extract_layer_fields(orig_name, layer_dict)})
                continue

            # Direct match
            if available_by_name.get(proto_lower):
                orig_name, layer_dict = available_by_name[proto_lower].popleft()
                layers.append({"name": proto.upper(), "fields": self._extract_layer_fields(orig_name, layer_dict)})
                continue

            # Mapped alias
            mapped = protocol_to_layer.get(proto_lower)
            if mapped and mapped != proto_lower and available_by_name.get(mapped):
                orig_name, layer_dict = available_by_name[mapped].popleft()
                layers.append({"name": proto.upper(), "fields": self._extract_layer_fields(orig_name, layer_dict)})
                continue

            # Missing layer in data: do not invent absent layers

        # Append remaining unconsumed layers in packet_data order
        for name, queue in available_by_name.items():
            while queue:
                orig_name, layer_dict = queue.popleft()
                layers.append({"name": orig_name.upper(), "fields": self._extract_layer_fields(orig_name, layer_dict)})

        return layers

    def _extract_layer_fields(
        self, layer_name: str, layer_data: dict, max_fields: int = 200, max_depth: int = 5
    ) -> list[str]:
        """Extract formatted fields from a protocol layer."""
        fields = []
        metadata_keys = {"frame.protocols", "frame.raw", "frame.encap_type", "frame_raw", "frame.encoding"}
        items = layer_data._pairs if hasattr(layer_data, "_pairs") else layer_data.items()
        for key, value in items:
            if key in metadata_keys:
                continue
            field_name = key.replace(".", " ")
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        fields.extend(self._format_nested_fields(key, item, depth=1, max_depth=max_depth))
                    else:
                        fields.append(f"{field_name}: {item}")
            elif isinstance(value, dict):
                fields.extend(self._format_nested_fields(key, value, depth=1, max_depth=max_depth))
            else:
                fields.append(f"{field_name}: {value}")

            if len(fields) >= max_fields:
                fields = fields[:max_fields]
                fields.append("... [campos truncados]")
                break
        return fields

    def _format_nested_fields(
        self, prefix: str, data: dict, depth: int = 1, max_depth: int = 5
    ) -> list[str]:
        """Format nested dictionary fields for protocol tree."""
        if depth > max_depth:
            return ["  " * depth + f"{prefix.replace('.', ' ')}: ... [profundidade máxima atingida]"]
        fields = []
        items = data._pairs if hasattr(data, "_pairs") else data.items()
        for key, value in items:
            field_name = f"{prefix}.{key}".replace(".", " ")
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        fields.extend(
                            self._format_nested_fields(
                                f"{prefix}.{key}", item, depth=depth + 1, max_depth=max_depth
                            )
                        )
                    else:
                        fields.append("  " * depth + f"{field_name}: {item}")
            elif isinstance(value, dict):
                fields.append("  " * depth + f"{field_name}:")
                fields.extend(
                    self._format_nested_fields(
                        f"{prefix}.{key}", value, depth=depth + 1, max_depth=max_depth
                    )
                )
            else:
                fields.append("  " * depth + f"{field_name}: {value}")
        return fields

    def _extract_hex_dump_bytes(self, output: str, caplen: Optional[int] = None) -> bytes:
        """Extract and validate raw bytes from TShark text hex dump output (-x flag)."""
        if not output or not output.strip():
            raise ValueError("Saída de hex dump vazia")

        raw_bytes = bytearray()
        expected_offset = 0
        first_line = True
        hexdigits = set("0123456789abcdefABCDEF")

        for line_raw in output.splitlines():
            line = line_raw.rstrip("\r\n")
            if not line.strip():
                continue

            match = re.match(r"^([0-9a-fA-F]+)\s{2,}(.*)$", line)
            if not match:
                raise ValueError(f"Linha de hex dump inválida: {line}")

            offset_str, rest = match.group(1), match.group(2)
            try:
                offset = int(offset_str, 16)
            except ValueError:
                raise ValueError(f"Offset inválido na linha: {offset_str}") from None

            if first_line:
                if offset != 0:
                    raise ValueError(f"Offset inicial inválido: esperado 0, obtido {offset:#06x}")
                first_line = False
            else:
                if offset < expected_offset:
                    raise ValueError(
                        f"Offset repetido ou regressivo: {offset:#06x} < esperado {expected_offset:#06x}"
                    )
                elif offset > expected_offset:
                    raise ValueError(
                        f"Lacuna de offset detectada: esperado {expected_offset:#06x}, obtido {offset:#06x}"
                    )

            # Isolate hex bytes area from ASCII column (separated by at least 3 spaces)
            parts = re.split(r"\s{3,}", rest, maxsplit=1)
            hex_area = parts[0]

            tokens = hex_area.split()
            if not tokens:
                raise ValueError(f"Linha de hex dump sem bytes: {line}")

            if len(tokens) > 16:
                tokens = tokens[:16]

            line_bytes = bytearray()
            for token in tokens:
                if len(token) != 2 or not all(c in hexdigits for c in token):
                    raise ValueError(f"Token hexadecimal inválido na linha: {token}")
                line_bytes.append(int(token, 16))

            raw_bytes.extend(line_bytes)
            expected_offset = offset + len(line_bytes)

        if not raw_bytes:
            raise ValueError("Nenhum byte extraído do hex dump")

        if caplen is not None and len(raw_bytes) != caplen:
            raise ValueError(
                f"Quantidade de bytes extraídos ({len(raw_bytes)}) diverge do tamanho capturado ({caplen})"
            )

        return bytes(raw_bytes)

    def _format_hex_dump(
        self, data: bytes, caplen: Optional[int] = None, original_length: Optional[int] = None
    ) -> str:
        """Format raw bytes as consistent hex/ASCII dump."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_str:<47}  {ascii_str}")

        if original_length is not None and original_length > len(data):
            lines.append(f"... ({original_length - len(data)} bytes truncated)")
        elif caplen is not None and caplen > len(data):
            lines.append(f"... ({caplen - len(data)} bytes truncated)")
        return "\n".join(lines)

    def _parse_hex_dump_text(self, output: str, caplen: Optional[int] = None) -> str:
        """Parse and validate TShark text hex dump output into formatted hex/ASCII."""
        raw_bytes = self._extract_hex_dump_bytes(output, caplen=caplen)
        return self._format_hex_dump(raw_bytes, caplen=caplen)
