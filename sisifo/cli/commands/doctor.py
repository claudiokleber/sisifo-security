import docker
import typer
from rich.console import Console

from sisifo.core import session as store
from sisifo.core.modules import select_modules

console = Console(markup=False)

app = typer.Typer(
    help="Diagnóstico de dependências e imagens.", no_args_is_help=True, invoke_without_command=True
)


@app.callback(invoke_without_command=True)
def doctor(ctx: typer.Context):
    """Executa diagnóstico padrão (nmap, nikto)."""
    if ctx.invoked_subcommand is None:
        modules = "nmap,nikto"
        console.print(f"Dados: {store.data_root()}")
        client = None
        try:
            client = docker.from_env(timeout=10)
            client.ping()
            console.print("Docker: disponível")
            missing = False
            for m in select_modules(modules):
                try:
                    img = client.images.get(m.image)
                    console.print(f"{m.name}: {img.id}")
                except docker.errors.ImageNotFound:
                    console.print(f"{m.name}: imagem ausente ({m.image})")
                    missing = True
            if missing:
                raise typer.Exit(1)
        except docker.errors.DockerException as e:
            console.print(f"Docker indisponível: {e}")
            raise typer.Exit(1)
        finally:
            if client:
                client.close()


@app.command()
def check(
    modules: str = typer.Option("nmap,nikto", help="Módulos a verificar (nmap,nikto,metasploit)"),
):
    """Verifica Docker e imagens necessárias."""
    console.print(f"Dados: {store.data_root()}")
    client = None
    try:
        client = docker.from_env(timeout=10)
        client.ping()
        console.print("Docker: disponível")
        missing = False
        for m in select_modules(modules):
            try:
                img = client.images.get(m.image)
                console.print(f"{m.name}: {img.id}")
            except docker.errors.ImageNotFound:
                console.print(f"{m.name}: imagem ausente ({m.image})")
                missing = True
        if missing:
            raise typer.Exit(1)
    except docker.errors.DockerException as e:
        console.print(f"Docker indisponível: {e}")
        raise typer.Exit(1)
    finally:
        if client:
            client.close()
