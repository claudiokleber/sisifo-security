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
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional
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
                            capture.error = "Executor interrompido; captura não repetida"
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
            raise ValueError("ID de captura inválido")
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
                        raise ValueError("Saída da ferramenta excedeu o limite")
                    if proc.poll() is not None:
                        break
                    control.cancelled.wait(0.05)
                if proc.returncode != 0:
                    raise ValueError(f"Ferramenta rejeitou arquivo/filtro ou falhou (código {proc.returncode})")
                stdout.seek(0)
                return stdout.read().decode("utf-8", errors="replace")
            except BudgetExceeded:
                if supplied_control:
                    raise
                raise ValueError("Ferramenta excedeu o limite de tempo") from None
            except OSError:
                raise ValueError("Não foi possível executar a ferramenta de rede") from None
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
            for line in output.splitlines():
                if "version" in line.lower():
                    return line.strip()
            return output.splitlines()[0].strip() if output.splitlines() else None
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
            return False, "dumpcap não encontrado"

        if is_docker:
            return False, "Captura nativa não disponível no Docker; use importação offline"

        if platform == "win32":
            # On Windows with Npcap, check if we can open an interface
            # This is a basic check; actual permission depends on Npcap service
            return True, "Windows: Npcap necessário; execute como administrador se falhar"
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
                return False, "Não foi possível verificar permissões de captura"

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
            return False, "dumpcap não encontrado; instale Wireshark/TShark"

        if not diagnostics.capture_permissions:
            return False, f"Sem permissão para captura: {diagnostics.permission_details}"

        if diagnostics.is_docker:
            return False, "Captura nativa não disponível no Docker; use importação offline"

        # Check interface exists
        interface_ids = [i.id for i in diagnostics.interfaces]
        if config.interface_id not in interface_ids:
            return False, f"Interface '{config.interface_id}' não encontrada"

        # Check storage
        max_size_mib = config.limits.max_file_size_mib
        if diagnostics.storage_available_mib < max_size_mib:
            return False, f"Espaço insuficiente: {diagnostics.storage_available_mib} MiB disponíveis, {max_size_mib} MiB necessários"

        # Check concurrent captures
        if diagnostics.active_captures >= config.limits.max_concurrent_captures:
            return False, f"Limite de capturas simultâneas atingido ({diagnostics.active_captures}/{config.limits.max_concurrent_captures})"

        return True, "Configuração válida"

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
            raise ValueError("Rotação e diretório personalizado ainda não suportados com segurança")

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
                    raise ValueError("Saída da captura excedeu o limite")
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
                result.error = f"Dumpcap saiu com código {ret}"

            # Parse dumpcap output for statistics
            self._parse_dumpcap_output(result, stdout, stderr)

            # Calculate file hash
            if output_file.exists():
                result.file_size = output_file.stat().st_size
                result.file_sha256 = self._calculate_sha256(output_file)

        except (Cancelled, KeyboardInterrupt):
            result.status = CaptureStatus.CANCELLED
            result.error = "Cancelado pelo usuário"
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
            raise ValueError("Arquivo não encontrado")

        if file_path.stat().st_size > 500 * 1024 * 1024:  # 500 MiB limit
            raise ValueError("Arquivo excede 500 MiB")

        # Validate file with capinfos
        diagnostics = self.discover_tools()
        if not diagnostics.tshark_path:
            raise ValueError("tshark não encontrado; necessário para validação")

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
            raise ValueError("capinfos não encontrado; necessário para validação de PCAP")

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
            raise ValueError("Captura não finalizada")
        path = self._capture_file(result)
        if not path.is_file():
            raise ValueError("Arquivo de captura não encontrado")
        fingerprint = self._calculate_sha256(path)
        if result.file_sha256 and fingerprint != result.file_sha256:
            raise ValueError("Integridade da captura divergente")
        diag = self.discover_tools()
        if not diag.tshark_path:
            raise ValueError("tshark não encontrado")
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
                raise ValueError("Saída inesperada do TShark")
            rows.append(dict(zip(fields, values)))
        if self._calculate_sha256(path) != fingerprint:
            raise ValueError("Captura alterada durante análise")
        atomic_write(cache, json.dumps(rows, ensure_ascii=False))
        return rows

    def analyze_capture(self, capture_id, display_filter=None, control=None, progress_callback=None):
        self._rows(capture_id, display_filter, control)
        return self.get_capture(capture_id)

    @staticmethod
    def _addresses(row):
        return (row["ip.src"] or row["ipv6.src"] or row["eth.src"],
                row["ip.dst"] or row["ipv6.dst"] or row["eth.dst"])

    def get_protocol_stats(self, capture_id, display_filter=None):
        rows = self._rows(capture_id, display_filter)
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

    def get_endpoints(self, capture_id, display_filter=None):
        endpoints = {}
        for row in self._rows(capture_id, display_filter):
            src, dst = self._addresses(row)
            for address, direction in [(src, "tx"), (dst, "rx")]:
                ep = endpoints.setdefault(address, EndpointStats(address=address,
                    type="IPv4" if row["ip.src"] else "IPv6" if row["ipv6.src"] else "Ethernet"))
                setattr(ep, "packets_" + direction, getattr(ep, "packets_" + direction) + 1)
                setattr(ep, "bytes_" + direction, getattr(ep, "bytes_" + direction) + int(row["frame.len"]))
        return sorted(endpoints.values(), key=lambda e: e.bytes_rx + e.bytes_tx, reverse=True)

    def get_conversations(self, capture_id, display_filter=None):
        conversations = {}
        for row in self._rows(capture_id, display_filter):
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
    ) -> list[PacketSummary]:
        """List packets with pagination."""
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("Paginação inválida")
        packets = []
        for row in self._rows(capture_id, display_filter)[offset:offset + limit]:
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
    ) -> PacketDetail:
        """Get detailed packet information including protocol tree and hex dump."""
        result = self.get_capture(capture_id)
        capture_file = self._capture_file(result)
        if not capture_file.exists():
            raise ValueError("Arquivo de captura não encontrado")

        diagnostics = self.discover_tools()
        if not diagnostics.tshark_path:
            raise ValueError("tshark não encontrado")

        # Get packet detail with protocol tree
        cmd = [
            diagnostics.tshark_path,
            "-r", str(capture_file),
            "-Y", f"frame.number == {packet_number}",
            "-V",  # Verbose protocol tree
            "-x",  # Hex dump
        ]

        cmd.insert(1, "-n")
        output = self._run_tool(cmd, timeout=30)
        if not output.strip():
            raise ValueError("Pacote não encontrado")

        # Parse the output
        lines = output.splitlines()
        summary_line = None
        layers = []
        hex_dump = ""
        in_hex = False

        current_layer = None
        for line in lines:
            if line.startswith("Frame "):
                summary_line = line
            elif line.startswith("    ") and not line.startswith("        ") and not in_hex:
                # New protocol layer
                if current_layer:
                    layers.append(current_layer)
                current_layer = {"name": line.strip(), "fields": []}
            elif line.startswith("        ") and current_layer and not in_hex:
                current_layer["fields"].append(line.strip())
            elif "Hex dump" in line or "Data" in line:
                in_hex = True
                hex_dump += line + "\n"
            elif in_hex:
                hex_dump += line + "\n"

        if current_layer:
            layers.append(current_layer)

        # Parse summary
        number = packet_number
        time_rel = 0.0
        time_iso = ""
        src = ""
        dst = ""
        protocol = ""
        length = 0
        info = ""

        if summary_line:
            # Frame 1: 123 bytes on wire...
            parts = summary_line.split()
            for i, part in enumerate(parts):
                if part.isdigit() and i == 1:
                    number = int(part)
                elif "bytes on wire" in summary_line:
                    try:
                        length = int(parts[parts.index("bytes") - 1])
                    except Exception:
                        pass

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
            hex_dump=hex_dump.strip(),
        )

    # -------------------------------------------------------------------------
    # Statistics and reports
    # -------------------------------------------------------------------------

    def get_dns_summary(self, capture_id, display_filter=None):
        return {"queries": [{"packet": int(r["frame.number"]), "name": r["dns.qry.name"]}
                for r in self._rows(capture_id, display_filter) if r["dns.qry.name"]]}

    def get_tcp_summary(self, capture_id, display_filter=None):
        rows = self._rows(capture_id, display_filter)
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
            anomalies.append(f"{tcp_summary['retransmissions']} retransmissões TCP detectadas")
        if tcp_summary.get("out_of_order", 0) > 0:
            anomalies.append(f"{tcp_summary['out_of_order']} pacotes TCP fora de ordem")
        if tcp_summary.get("zero_window", 0) > 0:
            anomalies.append(f"{tcp_summary['zero_window']} janelas TCP zero detectadas")
        if result.dropped_packets > 0:
            anomalies.append(f"{result.dropped_packets} pacotes perdidos pela captura")
        if result.dropped_by_interface > 0:
            anomalies.append(f"{result.dropped_by_interface} pacotes perdidos pela interface")

        limitations = [
            "Captura observa apenas tráfego visível na interface selecionada",
            "Tráfego criptografado (TLS/SSL) não pode ser inspecionado sem chaves",
            "Estatísticas baseadas em dissecação do TShark; podem diferir de ferramentas especializadas",
            "Filtros de exibição aplicados pós-captura não afetam pacotes já perdidos",
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
            anomalies.append(f"Retransmissões TCP: {tcp_summary['retransmissions']}")
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
                "Resumo baseado em estatísticas agregadas, não payload completo",
                "Conteúdo criptografado não incluído",
                "Apenas metadados e headers visíveis são analisados",
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
            raise ValueError("Arquivo de captura não encontrado")

        diagnostics = self.discover_tools()
        if not diagnostics.wireshark_path:
            raise ValueError("Wireshark desktop não encontrado no sistema")

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
            raise ValueError("Captura não encontrada")
        try:
            data = json.loads(metadata_file.read_text(encoding="utf-8"))
            result = CaptureResult.model_validate(data)
        except (ValueError, OSError):
            raise ValueError("Metadados de captura inválidos") from None
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