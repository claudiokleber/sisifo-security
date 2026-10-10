"""Guided connection and conversational CLI, shared with the web service."""
import json

import typer

from sisifo.core.ai_connection import chat, connect, discover_models, public_status


def configure():
    from sisifo.core.config import save_config
    typer.echo("Conectar IA — use uma API compatível com /models e /chat/completions.")
    typer.echo("A chave identifica sua conta; o endereço identifica o serviço. Nem toda API usa este protocolo.")
    mode = typer.prompt("1) Conectar API  2) Trabalhar offline", default="1")
    if mode == "2":
        save_config("export", "")
        typer.echo("Modo offline ativado. Nenhuma consulta externa.")
        return
    if mode != "1":
        raise typer.BadParameter("Escolha 1 ou 2.")
    previous = public_status()
    endpoint = typer.prompt("Endereço base da API (normalmente termina em /v1)",
                            default=previous["endpoint"] or None)
    key = typer.prompt("Chave de API (vazio mantém a chave do mesmo endereço; local pode dispensar chave)",
                       hide_input=True, default="", show_default=False) or None
    typer.echo("O catálogo será consultado apenas no endereço informado.")
    models = []
    try:
        models = discover_models(endpoint, key)
        for index, model in enumerate(models, 1):
            typer.echo(f"{index}) {model}")
    except ValueError as error:
        typer.echo(str(error))
        typer.echo("Você pode informar o modelo manualmente; a conexão ainda precisa ser testada.")
    choice = typer.prompt("Número do modelo ou identificador", default=previous["model"] or None)
    if choice.isdigit() and 1 <= int(choice) <= len(models):
        choice = models[int(choice) - 1]
    if not typer.confirm("Testar o modelo com uma mensagem curta e salvar? A API pode cobrar pela consulta", default=True):
        return
    try:
        result = connect(endpoint, choice, key)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None
    typer.echo(f"Conexão testada. Modelo: {result['model']}. Chave protegida e não exibida.")


def converse(session_id=None):
    status = public_status()
    if not status["configured"]:
        raise typer.BadParameter("Conecte sua IA primeiro: sisifo setup")
    typer.echo(f"Assistente Sísifo | {status['model']} | {status['endpoint']}")
    typer.echo("Mensagens são enviadas a essa API. /sair encerra; /limpar inicia outra conversa.")
    typer.echo("O assistente explica verificações; não executa comandos. Histórico apenas nesta conversa.")
    if session_id:
        from sisifo.core.ai_analyzer import prepare_batches
        typer.echo(json.dumps(prepare_batches(session_id), ensure_ascii=False, indent=2))
        if not typer.confirm("Enviar esta prévia da sessão à API durante a conversa?", default=False):
            return
    history = []
    while True:
        try:
            message = typer.prompt("Você")
        except (EOFError, KeyboardInterrupt, typer.Abort):
            typer.echo("\nConversa encerrada.")
            return
        if message.strip() == "/sair":
            return
        if message.strip() == "/limpar":
            history = []
            typer.echo("Histórico limpo.")
            continue
        try:
            response = chat(history + [{"role": "user", "content": message}], session_id, bool(session_id))
        except ValueError as error:
            typer.echo(str(error))
            continue
        except KeyboardInterrupt:
            typer.echo("Consulta interrompida; a API pode já ter processado a mensagem.")
            continue
        history.extend([{"role": "user", "content": message}, {"role": "assistant", "content": response["content"]}])
        # Plain output: untrusted responses are never interpreted as Rich markup or commands.
        import re
        safe = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", response["content"])
        typer.echo("IA: " + safe)
