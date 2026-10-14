"""Compatibility entry point for the shared connection wizard."""

import typer

app = typer.Typer(invoke_without_command=True)


@app.callback(invoke_without_command=True)
def setup(ctx: typer.Context = None):
    if ctx is None or ctx.invoked_subcommand is None:
        from sisifo.cli.main import setup as wizard

        wizard()


@app.command()
def configure():
    from sisifo.cli.commands.ai_console import configure as wizard

    wizard()


@app.command()
def status():
    from sisifo.cli.main import ai_status_cmd

    ai_status_cmd()
