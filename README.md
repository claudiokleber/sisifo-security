# Sísifo

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/sisifo-logo.svg">
  <img src="docs/brand/sisifo-logo-light.svg" alt="Sísifo — evidências, análise e investigação" width="720">
</picture>

Container-based security evidence collection and reviewable reporting, with optional AI-assisted analysis.

**Version:** 0.3.0 · **Python:** 3.11+ · **Recommended environment:** Docker Desktop with Linux containers.

[Documentação em português](README.pt-BR.md).

## Assisted agent and resumable AI

The [AI and agent guide (Portuguese)](docs/IA-E-AGENTE.md) documents bounded analysis, conservative budget reservations, validated batch reuse, persistent jobs and typed plans requiring explicit approval for external actions. The UI includes an offline data preview and local Nmap XML import. AI conclusions remain subject to human review.

After installation, open a new terminal and run `sisifo`, `sisifo setup`, `sisifo web` or `sisifo agent --help`. Installer wrappers manage their own virtual environment.

## Features

- Nmap XML and Nikto JSON collection with persistent raw evidence, execution status, and errors.
- Markdown and JSON reports, Nmap XML import, and session comparison.
- Optional NVIDIA or Ollama analysis with evidence references, structured context, bounded batches and coverage tracking.
- Explicit summary export to an existing Obsidian vault.
- An experimental Metasploit adapter restricted to `auxiliary/scanner/http/http_version`.
- **Local web interface** with authentication, CSRF protection, and secure session management.
- **OSINT connectors framework** with validation, rate limiting, and execution policies.
- **Multi-service credentials management** with separate files per service, never exposed in logs or responses.

AI output proposes interpretations and defensive recommendations; it does not confirm vulnerabilities or execute actions. The current CLI, reports, and AI prompts primarily use Portuguese.

## Setup with Docker Desktop

Start Docker Desktop in Linux-container mode and wait for the engine to become available. From this project directory:

```powershell
docker compose build sisifo nmap
docker compose pull nikto
docker compose run --rm sisifo doctor
```

`doctor` checks Nmap and Nikto by default. Use `doctor --modules metasploit` for the optional adapter; build it with `docker compose build metasploit`. Default scans use Nmap.

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

With the default configuration and no `--model`, `analyze` exports `analysis/ai-input.json` without calling an AI service. A locally configured provider can change this behavior. Comparisons require compatible completed sessions, including project, target, tools, commands, and images. A finding that is no longer observed is not necessarily fixed. Stable identities distinguish changed service attributes from new or missing services. Reports and AI reject missing evidence, hash mismatches and inconsistent counts; `session verify SESSION_ID` runs these checks explicitly. Legacy v2 sessions remain readable when their artifacts/counts are consistent, but absent historical hashes cannot be reconstructed as proof of prior integrity.

## Optional local AI with Ollama

Choose a model that fits your available RAM/VRAM. Models are not downloaded automatically.

```powershell
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull MODEL_NAME
docker compose run --rm sisifo analyze SESSION_ID --model MODEL_NAME
```

Replace `MODEL_NAME` with the model you installed. Analysis output is saved under `analysis/ANALYSIS_ID/`, including a report, request/response artifacts, and coverage metadata. AI failures preserve the deterministic report. Evidence-reference validation does not guarantee correct interpretation; review the coverage and conclusions.

Compose defaults to `http://ollama:11434` and does not publish the Ollama port on the host. To use a host Ollama instance that accepts Docker connections, append `--endpoint http://host.docker.internal:11434`. An external endpoint receives analysis data; select it only when sharing that data is intended.

### NVIDIA API and terminal installation

On Windows run `./install.ps1`; on Linux run `bash install.sh`. Both prepare the basic Docker images and run `sisifo setup`, which asks for the provider, model and a hidden API key. For manual setup:

```powershell
docker compose run --rm sisifo setup
docker compose run --rm sisifo ai-status
docker compose run --rm sisifo analyze SESSION_ID --provider nvidia
```

The default NVIDIA model is `nvidia/nemotron-3-super-120b-a12b`. The selected session evidence is sent to NVIDIA; the vault and API key are never included in prompts. Credentials are stored locally in `.sisifo-config/nvidia.key`, protected by filesystem permissions and excluded from Git, build contexts and package contents. This is a credential file, not an encrypted vault: exclude it from shared backups. Compose mounts the configuration only into the app, never into tool containers. `NVIDIA_API_KEY` may also be supplied to a native process. Never pass the key as a command-line argument.

After selecting NVIDIA in setup, plain `analyze SESSION_ID` uses it. Use `--provider export` to export all batches without network requests; explicit `--model` changes only the model and retains the configured provider. Up to 20 evidence items per batch, 24,000 evidence characters, and 50 batches per invocation are processed by default. `--max-batches` controls the call budget (1–100); omissions or failed later batches produce a partial result and CLI failure status. Valid batches, input, usage, coverage and errors remain available. Truncated fields are listed explicitly. Evidence IDs and complete declared batch coverage are checked; this does not guarantee semantic accuracy.

HTTP authentication errors, retired models, rate limits, invalid JSON, unknown references and truncated generations are reported without logging credentials. NVIDIA keys are sent only to the official HTTPS endpoint and redirects are refused. `install.ps1 -SkipSetup` / `install.sh --skip-setup` skips the interactive step for automated builds.

## Import existing Nmap evidence

Create `data/imports/` and place an XML file at `data/imports/example.xml`:

```powershell
docker compose run --rm sisifo import-nmap /data/imports/example.xml --target lab --project lab-demo
```

Importing does not execute a network scan or establish the source's authenticity. The original file and its hash are preserved. Original observation timestamps are separate from import timestamps. Imported comparisons require matching declared arguments, scanner versions and scaninfo; missing coverage or external input files prevent strict comparison. These declarations are not proof of authenticity. Version 0.1 sessions are not migrated automatically; retain them as historical archives.

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
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
```

On Linux/macOS, use `.venv/bin/python` in place of `.\.venv\Scripts\python.exe`. Tool execution still requires a reachable Docker engine and the corresponding images.

| Environment variable | Purpose |
| --- | --- |
| `SISIFO_DATA_DIR` | Session storage; installer wrappers use the repository `data` directory; standalone fallback is `~/.sisifo`; Compose uses `/data`. |
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
- Use `session recover SESSION_ID` to mark an orphaned run as interrupted. Recovery requires Docker and refuses an active writer or container; it never restarts tools. Stopped containers and raw data are preserved. Interrupted writes may still require manual evidence review.
- Sessions support a single writer. Do not edit session files during execution.
- Python container dependencies are pinned in `requirements-docker.lock`; base/tool images are pinned by digest. Alpine package downloads can still change; execution records capture the actual image ID. Update pins deliberately and rebuild/retest.
- This documentation describes the current source; it does not certify Docker integrations or runtime compatibility. Run the checks above in your environment.

## Web interface (v0.3+)

Start the local web UI and open it in your default browser:

```powershell
sisifo web
```

Options:

- `--port <N>` – choose the listening port (default 8000).
- `--no-browser` – start the server without opening the browser.

The server binds to `127.0.0.1` only. In Docker, the port is published on the host loopback; the container listens on its internal interface but the browser on the host opens `http://127.0.0.1:<port>`. Press **Ctrl+C** to stop the server cleanly.

### Web interface features

The web UI provides a complete dark-themed Portuguese interface with:

**Visão geral (Overview)**
- Recent sessions with status and tools used
- Available modules and their status
- Integration status (AI provider, OSINT connectors)

**Sessões (Sessions)**
- List all sessions with filtering by ID, project, target, status
- Session details: runs, tools, commands, errors, timestamps
- Direct links to reports and evidence downloads

**Relatórios (Reports)**
- View Markdown/JSON reports in browser
- Download reports as files
- Verify integrity of findings and artifacts
- Compare two compatible sessions

**Nova Execução (New Scan)**
- Form with target validation (IP, CIDR, hostname, URL)
- Multi-module selection (Nmap, Nikto, Metasploit)
- Project name and timeout configuration
- Background job execution with progress tracking

**Análise por IA (AI Analysis)**
- Select session, provider (NVIDIA/Ollama/Export), model, batch limit
- Shows what data is sent and to which destination
- Progress tracking with partial results
- Export offline analysis bundles

**OSINT (Integrations)**
- Catalog of available connectors with capabilities and status
- Query form with connector, type (domain/IP/URL/hash), and query validation
- Background execution with rate limiting and retry policies
- Results with provenance, timestamps, warnings, limitations

**Configurações (Configuration)**
- AI provider and model configuration
- Web interface password management
- OSINT connector credentials (per-service files)
- Status indicators for all configured services

### Security features

- **Session authentication** with secure, HttpOnly, SameSite=Strict cookies
- **CSRF protection** via double-submit cookie pattern with HMAC-signed tokens
- **Host/Origin validation** including DNS rebinding protection
- **Path confinement** for file downloads (prevents directory traversal)
- **No unrestricted CORS** — API only accessible from same origin
- **Input validation** on all endpoints (Pydantic models)
- **Secrets never exposed** — credentials not in logs, responses, URLs, or localStorage
- **Password configuration** via `sisifo setup-web` (stored in `.sisifo-config/web.json` with restricted permissions)

### Docker web profile

```powershell
docker compose --profile web up -d web
# Access at http://127.0.0.1:8000
```

The `web` service runs the same `sisifo` image with the `web` command, publishing port 8000 on `127.0.0.1` only.

### Interactive menu

```powershell
sisifo menu
```

Presents a terminal menu with:

1. **Usar pelo terminal** – shows a reminder to use the CLI directly.
2. **Abrir interface web local** – runs `sisifo web`.
3. **Configurar IA (NVIDIA/Ollama)** – runs `sisifo setup`.
4. **Configurar senha da interface web** – runs `sisifo setup-web`.
5. **Sair** – exits the menu.

Non‑interactive scripts continue to work unchanged; the menu is only invoked when you call `sisifo menu`.

## OSINT connectors (extensibility)

The `sisifo.osint` package defines a contract for external intelligence services (Shodan, Censys, VirusTotal, urlscan.io, …). Each connector declares:

- ID, name, description, version
- Supported query types (domain, IP, URL, hash)
- Required credential fields
- Allowed network destinations
- Capabilities, limits, implementation status

Results are normalised to a common schema preserving provenance, timestamps, evidence, reference URLs, warnings and limitations. A reference **dummy** connector is included for testing; it performs no network requests.

### Execution layer

The `OsintExecutor` enforces declared rules at runtime:

- **Configuration validation** before any request
- **Query type enforcement** — unsupported types rejected
- **Query format validation** (domain, IP, URL, hash syntax)
- **Destination allowlist** — only declared hosts reachable
- **Timeout and response size limits**
- **Retry policy** with exponential backoff (429, 5xx)
- **HTTP error handling** (401, 403, 429, 5xx) with structured codes
- **Redirect control** (disabled by default)
- **JSON response validation**
- **Rate limiting** (connector-declared limits)
- **Provenance tracking** — source, timestamps, original data preserved

### Adding a connector

1. Create a class inheriting from `sisifo.osint.BaseConnector`.
2. Fill the `meta` attribute (`ConnectorMeta`).
3. Implement `validate_config`, `diagnose`, `query`, `normalize`.
4. Implement `validate_query` for query format validation.
5. Register it in `sisifo.osint.registry._registry`.
6. Declare `allowed_destinations`, `limits` (timeouts, retries, max_response_size, rate_per_minute).

The web UI lists available connectors, shows their configuration status, and lets the user run queries with explicit confirmation before any external request.

### Connector configuration

Each connector stores credentials in a separate file: `.sisifo-config/osint_<connector_id>.json`

```json
{
  "api_key": "your-api-key",
  "secret": "another-field-if-needed"
}
```

Files are created with restricted permissions (0o600 on Unix, ACL on Windows). The web UI shows only "configurado"/"não configurado" — never the secret values.

## Credentials management (multi‑service)

The configuration directory (`.sisifo-config/`) stores **separate** files per service:

- `config.json` — non-secret settings (provider, model, version)
- `nvidia.key` — NVIDIA API key (legacy, still supported)
- `web.json` — web interface password
- `osint_<connector_id>.json` — OSINT connector credentials

After saving, the web UI never returns the full secret; it only reports "configurada". Secrets are never written to:

- localStorage / URLs / logs / prompts / reports / Git / Docker images
- tool containers (the Docker socket is not passed to them)

Removal requires explicit confirmation. Environment variables (`NVIDIA_API_KEY`, `SISIFO_WEB_PASSWORD`, `SISIFO_<SERVICE>_KEY`, etc.) and local files take precedence, documented in the config schema.

Migration from v1 config is automatic and reversible — the old format is detected and upgraded on load.

## License

[Docker SDK](https://docker-py.readthedocs.io/en/stable/containers.html) · [Nmap XML](https://nmap.org/book/output-formats-xml-output.html) · [Nikto Docker](https://github.com/sullo/nikto/wiki/Docker) · [Ollama Chat API](https://docs.ollama.com/api/chat) · [NVIDIA API](https://docs.api.nvidia.com/nim/reference/llm-apis)


## Instalação nativa independente

Execute `install.ps1` (Windows) ou `bash install.sh` (Linux) e abra um novo terminal: `sisifo`. Docker não é requisito para o menu/web. Atualização validada antes da ativação, reparo e rollback: veja [Instalação nativa](docs/INSTALACAO-NATIVA.md). `--with-docker` prepara containers opcionalmente.


## IA conversacional e conexão por API

Use `sisifo setup` para informar o endereço da API e a chave, buscar modelos e
testar a conexão. Depois, `sisifo chat` abre a conversa no terminal;
`sisifo chat --session ID` inclui evidências com prévia e confirmação.
Na web, use **Configurações → Conexão com a IA** e **Análise IA**.
O novo assistente substitui a escolha obrigatória entre marcas. Configurações
anteriores continuam compatíveis. APIs precisam implementar o protocolo suportado;
a chave sozinha não identifica todos os serviços.
Veja [uso, compatibilidade e limites](docs/IA-CONVERSACIONAL.md).


## Terminal OSINT e ajuda

Após instalar ou atualizar, use `sisifo help` e `sisifo osint terminal`.
O terminal guia a consulta e permite selecionar resultados para interpretação pela IA,
com prévia sanitizada e confirmação separada. A aba OSINT oferece o mesmo fluxo.
Use `sisifo osint config hibp` para configurar a chave e `sisifo osint --help` para opções.
[Contrato, rotas e limitações](docs/OSINT-INTEGRACOES.md).

## Estado da validação — 2026-10-12

Artefatos locais registram **286 testes convencionais e 11 E2E aprovados**.
Os E2E usam Chromium com HTTP externo simulado; não homologam HIBP/IA reais.
A [CI do commit 11adfe59](https://github.com/claudiokleber/sisifo-security/actions/runs/38088423076) passou nos jobs unitários,
rede e instalação nativa, mas **não contém browser-e2e nem valida as alterações locais posteriores**.
As execuções E2E anteriores sem artefatos permanecem classificadas como relatadas.
Consulte [evidências, comandos e pendências](docs/OSINT-VALIDACAO.md).
