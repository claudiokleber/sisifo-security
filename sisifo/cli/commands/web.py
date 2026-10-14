import socket
import threading
import webbrowser

import httpx
import typer
from rich.console import Console

console = Console(markup=False)

app = typer.Typer(help="Iniciar interface web local e abrir no navegador.", no_args_is_help=True)


def _run_server(sock: socket.socket, ready_event: threading.Event):
    import uvicorn

    from sisifo.web.server import app as web_app

    config = uvicorn.Config(web_app, log_level="info")
    server = uvicorn.Server(config)
    ready_event.set()
    server.run(sockets=[sock])


def existing_web(port: int) -> bool:
    """Recognize the local UI before opening it; never submit credentials."""
    try:
        with httpx.Client(trust_env=False, timeout=2) as client:
            base = f"http://127.0.0.1:{port}"
            health = client.get(f"{base}/health")
            schema = client.get(f"{base}/openapi.json")
            return (
                health.status_code == 200
                and health.json().get("status") == "ok"
                and schema.status_code == 200
                and schema.json().get("info", {}).get("title") == "Sísifo Web"
            )
    except (httpx.HTTPError, ValueError, AttributeError):
        return False


def start_web(port: int = 8000, no_browser: bool = False) -> None:
    """Programmatic entry point used by menu and CLI."""
    # Check optional web dependencies
    try:
        import fastapi  # noqa: F401
        import jinja2  # noqa: F401
        import uvicorn  # noqa: F401

        from sisifo.web.server import app as web_app
    except ImportError as e:
        console.print(f"Dependências web ausentes: {e}")
        console.print('Instale com: python -m pip install -e ".[dev,web]"')
        raise typer.Exit(1)

    import os

    import uvicorn

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    host = os.getenv("SISIFO_WEB_BIND", "127.0.0.1")
    if host not in {"127.0.0.1", "0.0.0.0"}:
        raise ValueError("Invalid bind address")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            console.print(f"Porta {port} indisponivel. Use --port para escolher outra.")
            raise typer.Exit(1) from None
        sock.listen(128)
        server = uvicorn.Server(uvicorn.Config(web_app, log_level="info"))
        done = threading.Event()

        def announce():
            while not done.wait(0.1):
                if server.started and existing_web(port):
                    url = f"http://127.0.0.1:{port}"
                    console.print(f"Servidor web: {url}")
                    if not no_browser:
                        try:
                            webbrowser.open(url)
                        except Exception:
                            console.print(f"Abra manualmente: {url}")
                    return

        worker = threading.Thread(target=announce, daemon=True)
        worker.start()
        try:
            server.run(sockets=[sock])
        finally:
            done.set()
            worker.join(timeout=5)


@app.callback(invoke_without_command=True)
def web(
    ctx: typer.Context,
    port: int = typer.Option(
        8000, "--port", "-p", help="Porta para o servidor web", min=1, max=65535
    ),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Não abrir navegador automaticamente"
    ),
):
    if ctx.invoked_subcommand is not None:
        return
    start_web(port=port, no_browser=no_browser)
