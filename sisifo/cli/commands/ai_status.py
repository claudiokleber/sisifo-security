import typer

app = typer.Typer(invoke_without_command=True)


@app.callback(invoke_without_command=True)
def ai_status(ctx: typer.Context):
    from sisifo.cli.main import ai_status_cmd
    if ctx.invoked_subcommand is None:
        ai_status_cmd()
