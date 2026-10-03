# Sísifo

Container-based security evidence collection and reviewable reporting, with optional AI-assisted analysis.

**Version:** 0.2.0 · **Python:** 3.11+ · **Recommended environment:** Docker Desktop with Linux containers.

[Original Portuguese documentation](README.pt-BR.md) (historical; some features described there have since changed).

## Features

- Nmap XML and Nikto JSON collection with persistent raw evidence, execution status, and errors.
- Markdown and JSON reports, Nmap XML import, and session comparison.
- Optional Ollama analysis with evidence references and coverage tracking.
- Explicit summary export to an existing Obsidian vault.
- An experimental Metasploit adapter restricted to `auxiliary/scanner/http/http_version`.

AI output proposes interpretations and defensive recommendations; it does not confirm vulnerabilities or execute actions. The current CLI, reports, and AI prompts primarily use Portuguese. A web interface is not available through the current CLI.

## Setup with Docker Desktop

Start Docker Desktop in Linux-container mode and wait for the engine to become available. From this project directory:

```powershell
docker compose build sisifo nmap metasploit
docker compose pull nikto
docker compose run --rm sisifo doctor
```

`doctor` checks every registered tool image, including the experimental Metasploit image. Default scans use Nmap; building the other images does not enable them automatically.

The `sisifo` service controls sibling containers through the Docker socket. This provides control over the host's Docker engine, so keep the service local. Tool containers do not receive the socket. Tools use bridge networking, and Nmap uses TCP connect scanning.

## Run the local lab

An optional Nginx test target is available only on the Docker network; it publishes no host ports.

```powershell
docker compose --profile lab up -d lab
docker compose run --rm sisifo scan lab --project lab-demo
docker compose run --rm sisifo scan http://lab --modules nikto --project web-demo
docker compose run --rm sisifo session list
docker compose --profile lab stop lab
```

Only scan systems you own or are authorized to assess. Inside a tool container, `localhost` refers to that container. For a service on the Windows host, use an appropriate reachable address such as `host.docker.internal`.

Nmap accepts an IP address, CIDR range, or hostname. Nikto accepts an HTTP/HTTPS origin with an optional port, without credentials or a resource path. To run both in one session:

```powershell
docker compose run --rm sisifo scan http://lab --modules nmap,nikto --project lab-demo
```

Nmap examines the hostname using its default port selection; Nikto examines the supplied web origin. Duplicate or unknown module names are rejected before session creation.

### Experimental Metasploit adapter

With the local lab running:

```powershell
docker compose run --rm sisifo scan http://lab --modules metasploit --project lab-demo
```

This adapter runs one fixed HTTP version scanner and records service observations. It is not a general exploit runner. Review its experimental status and validate it in your environment before relying on its output.

## Sessions and reports

Each scan prints a session ID. Replace `SESSION_ID`, `BEFORE_ID`, and `AFTER_ID` below with actual IDs:

```powershell
docker compose run --rm sisifo session show SESSION_ID
docker compose run --rm sisifo report SESSION_ID
docker compose run --rm sisifo analyze SESSION_ID
docker compose run --rm sisifo compare BEFORE_ID AFTER_ID
```

Reports are saved to `data/sessions/SESSION_ID/reports/report.md` and `report.json`. Raw output and errors are retained under `raw_output`; execution records include the actual container image ID.

With the default configuration and no `--model`, `analyze` exports `analysis/ai-input.json` without calling an AI service. A locally configured provider can change this behavior. Comparisons require compatible completed sessions, including project, target, tools, commands, and images. A finding that is no longer observed is not necessarily fixed.

## Optional local AI with Ollama

Choose a model that fits your available RAM/VRAM. Models are not downloaded automatically.

```powershell
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull MODEL_NAME
docker compose run --rm sisifo analyze SESSION_ID --model MODEL_NAME
```

Replace `MODEL_NAME` with the model you installed. Analysis output is saved under `analysis/ANALYSIS_ID/`, including a report, request/response artifacts, and coverage metadata. AI failures preserve the deterministic report. Evidence-reference validation does not guarantee correct interpretation; review the coverage and conclusions.

Compose defaults to `http://ollama:11434` and does not publish the Ollama port on the host. To use a host Ollama instance that accepts Docker connections, append `--endpoint http://host.docker.internal:11434`. An external endpoint receives analysis data; select it only when sharing that data is intended.

The source also contains NVIDIA provider/configuration helpers. The current CLI does not expose a `setup` command or provider selector, so that integration is not documented as a ready-to-use CLI workflow.

## Import existing Nmap evidence

Create `data/imports/` and place an XML file at `data/imports/example.xml`:

```powershell
docker compose run --rm sisifo import-nmap /data/imports/example.xml --target lab --project lab-demo
```

Importing does not execute a network scan or establish the source's authenticity. The original file and its hash are preserved. Version 0.1 sessions are not migrated automatically; retain them as historical archives.

## Export to Obsidian

Mount your vault only for the export operation. Replace `C:/path/to/your-vault` with an existing vault directory:

```powershell
docker compose run --rm -v "C:/path/to/your-vault:/vault" sisifo export-vault SESSION_ID /vault
```

The summary is written to `30-Projetos/sisifo/relatorios/SESSION_ID.md`. Repeating an unchanged export does not create duplicates; an existing note with different contents is not overwritten. Raw logs remain in the session data directory.

## Local development

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
```

On Linux/macOS, use `.venv/bin/python` in place of `.\.venv\Scripts\python.exe`. Tool execution still requires a reachable Docker engine and the corresponding images.

| Environment variable | Purpose |
| --- | --- |
| `SISIFO_DATA_DIR` | Session storage; defaults to `~/.sisifo` outside Compose and `/data` in Compose. |
| `SISIFO_TOOL_NETWORK` | Tool network; defaults to `bridge` outside Compose and `sisifo_default` in Compose. |
| `SISIFO_NMAP_IMAGE` | Override the Nmap image. |
| `SISIFO_NIKTO_IMAGE` | Override the Nikto image. |
| `SISIFO_METASPLOIT_IMAGE` | Override the experimental Metasploit image. |
| `SISIFO_OLLAMA_URL` | Ollama endpoint. |
| `SISIFO_CONFIG_DIR` | Local provider configuration directory; defaults to `.sisifo-config` under the working directory. |

To add a tool, implement target validation, an argument-list command builder, and a structured-output parser; register it in `sisifo/core/modules.py` and supply its container image. Include fixtures and success/failure tests. The central executor manages states, timeouts, logs, artifacts, and cleanup.

## Limitations

- This is not a complete security assessment. Observations and potential web issues require review.
- Artifacts are limited to 20 MiB. Docker log rotation can also limit capture; truncated structured output is treated as a parsing failure.
- There is no automatic scan recovery after abrupt process or host interruption. Review sessions left in `running` state.
- Sessions support a single writer. Do not edit session files during execution.
- Python container dependencies are pinned in `requirements-docker.lock`; image tags and OS packages can still change. Execution records capture image IDs.
- This documentation describes the current source; it does not certify Docker integrations or runtime compatibility. Run the checks above in your environment.

## License

Licensed under the GNU General Public License, version 3 only (GPL-3.0-only). See [LICENSE](LICENSE) for the full terms. External tools retain their own licenses.

## References

[Docker SDK](https://docker-py.readthedocs.io/en/stable/containers.html) · [Nmap XML](https://nmap.org/book/output-formats-xml-output.html) · [Nikto Docker](https://github.com/sullo/nikto/wiki/Docker) · [Ollama Chat API](https://docs.ollama.com/api/chat)
