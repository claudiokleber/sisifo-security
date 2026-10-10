"""Network module CLI commands for Sísifo."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sisifo.core.session import data_root
from sisifo.modules.network import NetworkService
from sisifo.modules.network.models import (
    CaptureConfig,
    CaptureFilter,
    CaptureLimits,
    CaptureSource,
    CaptureStatus,
    DisplayFilter,
)

# Use ASCII-safe console on Windows to avoid encoding issues with special characters
console = Console(markup=False, legacy_windows=True, force_terminal=True, color_system=None)

app = typer.Typer(help="Monitoramento e análise de rede.", no_args_is_help=True)


def get_service() -> NetworkService:
    """Get network service instance."""
    return NetworkService(data_root() / "network")


@app.command()
def doctor():
    """Diagnóstico de dependências de rede (TShark, Dumpcap, Wireshark, Npcap)."""
    service = get_service()
    diag = service.discover_tools()

    console.print(f"Plataforma: {diag.platform}")
    console.print(f"Docker: {'sim' if diag.is_docker else 'não'}")
    console.print(f"Armazenamento: {diag.storage_path} ({diag.storage_available_mib} MiB livres)")
    console.print(f"Permissão de captura: {'sim' if diag.capture_permissions else 'não'} - {diag.permission_details}")
    console.print()

    if diag.dumpcap_path:
        console.print(f"dumpcap: {diag.dumpcap_path} ({diag.dumpcap_version or 'versão desconhecida'})")
    else:
        console.print("dumpcap: não encontrado")

    if diag.tshark_path:
        console.print(f"tshark: {diag.tshark_path} ({diag.tshark_version or 'versão desconhecida'})")
    else:
        console.print("tshark: não encontrado")

    if diag.wireshark_path:
        console.print(f"Wireshark: {diag.wireshark_path}")
    else:
        console.print("Wireshark: não encontrado")

    if diag.npcap_version:
        console.print(f"Npcap: {diag.npcap_version}")
    if diag.libpcap_version:
        console.print(f"libpcap: {diag.libpcap_version}")

    console.print()
    console.print(f"Interfaces descobertas: {len(diag.interfaces)}")
    for iface in diag.interfaces:
        loopback_str = " (loopback)" if iface.loopback else ""
        up_str = " UP" if iface.up else " DOWN"
        console.print(f"  {iface.id} - {iface.name}{loopback_str}{up_str}")

    console.print()
    console.print(f"Capturas ativas: {diag.active_captures}")
    console.print(f"Capturas recentes: {len(diag.recent_captures)}")

    if not diag.dumpcap_path or not diag.tshark_path:
        console.print("\n[red]Dependências ausentes: instale Wireshark/TShark para funcionalidade completa.[/red]")
        raise typer.Exit(1)


@app.command()
def interfaces():
    """Lista interfaces de rede disponíveis para captura."""
    service = get_service()
    diag = service.discover_tools()

    if not diag.interfaces:
        console.print("Nenhuma interface encontrada. Verifique se dumpcap está instalado e acessível.")
        raise typer.Exit(1)

    table = Table(title="Interfaces de Rede")
    table.add_column("ID", style="cyan")
    table.add_column("Nome", style="green")
    table.add_column("Descrição")
    table.add_column("Loopback", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Endereços")

    for iface in diag.interfaces:
        table.add_row(
            iface.id,
            iface.name,
            iface.description,
            "sim" if iface.loopback else "não",
            "UP" if iface.up else "DOWN",
            ", ".join(iface.addresses) if iface.addresses else "-",
        )

    console.print(table)


@app.command()
def import_pcap(
    file: Path = typer.Argument(..., help="Arquivo PCAP/PCAPNG para importar", exists=True, readable=True),
):
    """Importa e valida um arquivo PCAP/PCAPNG."""
    service = get_service()

    console.print(f"Importando {file}...")
    try:
        result = service.import_pcap(file)

        console.print("[green]Importação concluída:[/green]")
        console.print(f"  ID: {result.id}")
        console.print(f"  Origem: {result.source}")
        console.print(f"  Arquivo: {result.file_path}")
        console.print(f"  Tamanho: {result.file_size:,} bytes")
        console.print(f"  SHA-256: {result.file_sha256}")
        console.print(f"  Pacotes: {result.packet_count}")
        console.print(f"  Pacotes perdidos (captura): {result.dropped_packets}")
        console.print(f"  Pacotes perdidos (interface): {result.dropped_by_interface}")
        console.print(f"  TShark: {result.tshark_version}")
        console.print(f"  Dumpcap: {result.dumpcap_version}")

        if result.status != CaptureStatus.COMPLETED:
            console.print(f"[yellow]Status: {result.status}[/yellow]")
            if result.error:
                console.print(f"  Erro: {result.error}")

    except ValueError as e:
        console.print(f"[red]Erro na importação:[/red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Erro inesperado:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def list(
    limit: int = typer.Option(50, "--limit", "-n", help="Número máximo de capturas a listar"),
):
    """Lista capturas recentes."""
    service = get_service()
    captures = service.list_captures(limit=limit)

    if not captures:
        console.print("Nenhuma captura encontrada.")
        return

    table = Table(title=f"Capturas Recentes (últimas {len(captures)})")
    table.add_column("ID", style="cyan")
    table.add_column("Origem", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Interface")
    table.add_column("Pacotes", justify="right")
    table.add_column("Tamanho", justify="right")
    table.add_column("Criada em")

    for c in captures:
        source_str = "capturada" if c.source == CaptureSource.CAPTURED else "importada"
        table.add_row(
            c.id[:16] + "...",
            source_str,
            c.status.value,
            c.interface_name or c.interface_id or "-",
            str(c.packet_count),
            f"{c.file_size:,} bytes",
            c.created_at.isoformat() if c.created_at else "-",
        )

    console.print(table)


@app.command()
def show(capture_id: str = typer.Argument(..., help="ID da captura")):
    """Mostra metadados de uma captura."""
    service = get_service()

    try:
        result = service.get_capture(capture_id)
    except ValueError as e:
        console.print(f"[red]Erro:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"ID: {result.id}")
    console.print(f"Origem: {result.source}")
    console.print(f"Status: {result.status}")
    console.print(f"Interface: {result.interface_name or result.interface_id or '-'}")
    console.print(f"Filtro de captura (BPF): {result.capture_filter or '-'}")
    console.print(f"Filtro de exibição: {result.display_filter or '-'}")
    console.print(f"Arquivo: {result.file_path}")
    console.print(f"Tamanho: {result.file_size:,} bytes")
    console.print(f"SHA-256: {result.file_sha256 or '-'}")
    console.print(f"Pacotes: {result.packet_count}")
    console.print(f"Pacotes perdidos (captura): {result.dropped_packets}")
    console.print(f"Pacotes perdidos (interface): {result.dropped_by_interface}")
    console.print(f"TShark: {result.tshark_version or '-'}")
    console.print(f"Dumpcap: {result.dumpcap_version or '-'}")
    console.print(f"Ambiente: {result.environment}")
    console.print(f"Docker: {'sim' if result.is_docker else 'não'}")
    console.print(f"Criada em: {result.created_at.isoformat() if result.created_at else '-'}")
    console.print(f"Iniciada em: {result.started_at.isoformat() if result.started_at else '-'}")
    console.print(f"Finalizada em: {result.finished_at.isoformat() if result.finished_at else '-'}")
    if result.error:
        console.print(f"Erro: {result.error}")


@app.command()
def packets(
    capture_id: str = typer.Argument(..., help="ID da captura"),
    display_filter: Optional[str] = typer.Option(None, "--display-filter", "-Y", help="Filtro de exibição (sintaxe Wireshark)"),
    offset: int = typer.Option(0, "--offset", "-o", help="Deslocamento inicial"),
    limit: int = typer.Option(100, "--limit", "-n", help="Número máximo de pacotes"),
):
    """Lista pacotes de uma captura com paginação."""
    service = get_service()

    try:
        df = DisplayFilter(expression=display_filter) if display_filter else None
        packets = service.list_packets(capture_id, display_filter=df, offset=offset, limit=limit)
    except ValueError as e:
        console.print(f"[red]Erro:[/red] {e}")
        raise typer.Exit(1)

    if not packets:
        console.print("Nenhum pacote encontrado.")
        return

    # Use simple ASCII table to avoid encoding issues on Windows
    title = f"Pacotes ({len(packets)} exibidos, offset={offset})"
    print(title)
    # Header
    header = f"{'#':>4}  {'Tempo (s)':>12}  {'Origem':<20}  {'Destino':<20}  {'Protocolo':<10}  {'Tam.':>6}  {'Info'}"
    print(header)
    print("-" * len(header))
    for p in packets:
        info = p.info[:120] + ("..." if len(p.info) > 120 else "")
        row = f"{p.number:>4}  {p.time:>12.6f}  {p.source:<20}  {p.destination:<20}  {p.protocol:<10}  {p.length:>6}  {info}"
        print(row)
    return


@app.command()
def detail(
    capture_id: str = typer.Argument(..., help="ID da captura"),
    packet_number: int = typer.Argument(..., help="Número do pacote"),
):
    """Mostra detalhes completos de um pacote (árvore de protocolos + hex dump)."""
    service = get_service()

    try:
        detail = service.get_packet_detail(capture_id, packet_number)
    except ValueError as e:
        console.print(f"[red]Erro:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"Pacote #{detail.number}")
    console.print(f"Tempo: {detail.time:.6f}s ({detail.time_iso})")
    console.print(f"Origem: {detail.source}")
    console.print(f"Destino: {detail.destination}")
    console.print(f"Protocolo: {detail.protocol}")
    console.print(f"Tamanho: {detail.length} bytes")
    console.print(f"Info: {detail.info}")
    console.print()

    if detail.layers:
        console.print("--- Árvore de Protocolos ---")
        for layer in detail.layers:
            console.print(f"  {layer['name']}")
            for field in layer.get('fields', []):
                console.print(f"    {field}")

    if detail.hex_dump:
        console.print()
        console.print("--- Hex Dump ---")
        console.print(detail.hex_dump)


@app.command()
def stats(
    capture_id: str = typer.Argument(..., help="ID da captura"),
    display_filter: Optional[str] = typer.Option(None, "--display-filter", "-Y", help="Filtro de exibição (sintaxe Wireshark)"),
):
    """Mostra estatísticas de protocolos, endpoints e conversações."""
    service = get_service()

    try:
        df = DisplayFilter(expression=display_filter) if display_filter else None

        console.print("[bold]Hierarquia de Protocolos[/bold]")
        proto_stats = service.get_protocol_stats(capture_id, display_filter=df)
        print("Hierarquia de Protocolos")
        print("Protocolo                    Pacotes  % Pacotes  Bytes    % Bytes")
        print("-" * 65)
        for item in proto_stats.by_protocol:
            print(f"{item.protocol:<28} {item.packets:>8,}  {item.percentage_packets:>8.1f}%  {item.bytes:>8,}  {item.percentage_bytes:>7.1f}%")
        print(f"Total: {proto_stats.total_packets:,} pacotes, {proto_stats.total_bytes:,} bytes")
        print()

        endpoints = service.get_endpoints(capture_id, display_filter=df)[:20]
        print("Endpoints (Top 20)")
        print("Endereco                          Tipo      RX Pkts  TX Pkts  RX Bytes    TX Bytes")
        print("-" * 75)
        for ep in endpoints:
            print(f"{ep.address:<32} {ep.type:<8} {ep.packets_rx:>8,} {ep.packets_tx:>8,} {ep.bytes_rx:>10,} {ep.bytes_tx:>10,}")
        print()

        console.print("[bold]Conversações (Top 20)[/bold]")
        conversations = service.get_conversations(capture_id, display_filter=df)[:20]
        # Use simple print to avoid encoding issues
        print("A <=> B                                    Protocolo  Pacotes  Bytes      Duracao (s)")
        print("-" * 80)
        for conv in conversations:
            print(f"{conv.endpoint_a} <=> {conv.endpoint_b:<35} {conv.protocol:<10} {conv.packets:>8,}  {conv.bytes:>10,}  {conv.duration:.3f}")
        print()

        dns = service.get_dns_summary(capture_id, display_filter=df)
        console.print(f"[bold]DNS:[/bold] {len(dns.get('queries', []))} consultas")
        for q in dns.get('queries', [])[:10]:
            console.print(f"  {q}")

        tcp = service.get_tcp_summary(capture_id, display_filter=df)
        console.print()
        console.print("[bold]TCP:[/bold]")
        console.print(f"  Retransmissões: {tcp.get('retransmissions', 0)}")
        console.print(f"  Fora de ordem: {tcp.get('out_of_order', 0)}")
        console.print(f"  Janela zero: {tcp.get('zero_window', 0)}")

    except ValueError as e:
        console.print(f"[red]Erro:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def report(
    capture_id: str = typer.Argument(..., help="ID da captura"),
    display_filter: Optional[str] = typer.Option(None, "--display-filter", "-Y", help="Filtro de exibição (sintaxe Wireshark)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Arquivo de saída (JSON)"),
):
    """Gera relatório determinístico completo da captura."""
    service = get_service()

    try:
        df = DisplayFilter(expression=display_filter) if display_filter else None
        report_data = service.generate_report(capture_id, display_filter=df)
    except ValueError as e:
        console.print(f"[red]Erro:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"Relatório gerado para captura {report_data.capture_id}")
    console.print(f"Pacotes: {report_data.summary.packet_count}")
    console.print(f"Protocolos: {len(report_data.protocol_stats.by_protocol)}")
    console.print(f"Endpoints: {len(report_data.endpoints)}")
    console.print(f"Conversações: {len(report_data.conversations)}")
    console.print(f"Anomalias: {len(report_data.anomalies)}")
    for a in report_data.anomalies:
        console.print(f"  - {a}")
    console.print(f"Limitações: {len(report_data.limitations)}")
    for lim in report_data.limitations:
        console.print(f"  - {lim}")

    if output:
        output.write_text(report_data.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"\n[green]Relatório salvo em:[/green] {output}")


@app.command()
def open_wireshark(capture_id: str = typer.Argument(..., help="ID da captura")):
    """Abre a captura no Wireshark desktop (apenas ambiente local)."""
    service = get_service()

    try:
        service.open_in_wireshark(capture_id)
        console.print("[green]Wireshark iniciado com a captura.[/green]")
    except ValueError as e:
        console.print(f"[red]Erro:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def capture(
    interface: str = typer.Option(..., "--interface", "-i", help="ID da interface para capturar"),
    duration: int = typer.Option(60, "--duration", "-d", help="Duração máxima em segundos"),
    max_size_mib: int = typer.Option(100, "--max-size", help="Tamanho máximo do arquivo em MiB"),
    max_packets: int = typer.Option(100000, "--max-packets", help="Número máximo de pacotes"),
    capture_filter: Optional[str] = typer.Option(None, "--capture-filter", "-f", help="Filtro de captura (BPF)"),
    ring_buffer: bool = typer.Option(False, "--ring-buffer", help="Habilitar buffer circular"),
    ring_files: int = typer.Option(5, "--ring-files", help="Número de arquivos no buffer circular"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", help="Diretório de saída relativo ao data root"),
    no_confirm: bool = typer.Option(False, "--yes", "-y", help="Não pedir confirmação"),
):
    """Inicia captura de pacotes na interface especificada (usa Dumpcap)."""
    service = get_service()

    diag = service.discover_tools()
    if diag.is_docker:
        console.print("[red]Captura nativa não disponível no Docker. Use importação offline.[/red]")
        raise typer.Exit(1)

    if not diag.capture_permissions:
        console.print(f"[red]Sem permissão para captura:[/red] {diag.permission_details}")
        raise typer.Exit(1)

    # Validate interface
    iface_ids = [i.id for i in diag.interfaces]
    if interface not in iface_ids:
        console.print(f"[red]Interface '{interface}' não encontrada.[/red]")
        console.print("Use 'sisifo network interfaces' para listar interfaces disponíveis.")
        raise typer.Exit(1)

    iface_name = next((i.name for i in diag.interfaces if i.id == interface), interface)

    console.print("Configuração da captura:")
    console.print(f"  Interface: {iface_name} ({interface})")
    console.print(f"  Duração máxima: {duration}s")
    console.print(f"  Tamanho máximo: {max_size_mib} MiB")
    console.print(f"  Pacotes máximos: {max_packets:,}")
    console.print(f"  Filtro de captura (BPF): {capture_filter or '(nenhum)'}")
    console.print(f"  Buffer circular: {'sim' if ring_buffer else 'não'}" + (f" ({ring_files} arquivos)" if ring_buffer else ""))
    console.print()

    if not no_confirm:
        if not typer.confirm("Iniciar captura?"):
            console.print("Cancelado.")
            raise typer.Exit(0)

    config = CaptureConfig(
        interface_id=interface,
        capture_filter=CaptureFilter(expression=capture_filter or ""),
        limits=CaptureLimits(
            max_duration_seconds=duration,
            max_file_size_mib=max_size_mib,
            max_packets=max_packets,
        ),
        output_directory=output_dir,
        ring_buffer=ring_buffer,
        ring_buffer_files=ring_files,
    )

    console.print("[yellow]Capturando... Pressione Ctrl+C para parar.[/yellow]")
    try:
        result = service.start_capture(config)
        console.print("[green]Captura concluída:[/green]")
        console.print(f"  ID: {result.id}")
        console.print(f"  Status: {result.status}")
        console.print(f"  Arquivo: {result.file_path}")
        console.print(f"  Tamanho: {result.file_size:,} bytes")
        console.print(f"  SHA-256: {result.file_sha256 or '-'}")
        console.print(f"  Pacotes: {result.packet_count}")
        console.print(f"  Pacotes perdidos: {result.dropped_packets}")
        if result.error:
            console.print(f"  Erro: {result.error}")
    except (KeyboardInterrupt, typer.Abort):
        console.print("\n[yellow]Captura interrompida pelo usuário.[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"[red]Erro na captura:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def stop(capture_id: str = typer.Argument(..., help="ID da captura em andamento")):
    """Para uma captura em andamento."""
    service = get_service()

    try:
        result = service.stop_capture(capture_id)
        console.print(f"[green]Captura {capture_id} marcada para parada.[/green]")
        console.print(f"Status: {result.status}")
        if result.error:
            console.print(f"Erro: {result.error}")
    except ValueError as e:
        console.print(f"[red]Erro:[/red] {e}")
        raise typer.Exit(1)