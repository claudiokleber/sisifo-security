# Sísifo 0.3.0

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/sisifo-logo.svg">
  <img src="docs/brand/sisifo-logo-light.svg" alt="Sísifo — evidências, análise e investigação" width="720">
</picture>

Ferramentas em containers → evidências persistentes → relatório revisável → IA opcional → interface web funcional → OSINT extensível.

Implementado: CLI, Nmap XML, Nikto JSON, estados e erros de execução, relatório Markdown/JSON, importação Nmap, comparação de sessões, integração Ollama/NVIDIA, **interface web com autenticação e CSRF**, **framework OSINT com validação e políticas de execução**, **gestão multi-serviço de credenciais**. A IA sugere medidas e hipóteses; não confirma vulnerabilidades automaticamente nem executa ações. Metasploit possui adaptador experimental restrito a identificação HTTP.

## IA, agente e execução persistente

Consulte [o guia de IA e agente](docs/IA-E-AGENTE.md) para limites, retomada, aprovação de planos e validação. A interface permite revisar os dados offline antes da análise, importar XML Nmap, acompanhar e cancelar jobs. Resultados da IA permanecem pendentes de revisão humana.

Após instalar, abra um novo terminal e use `sisifo`, `sisifo setup`, `sisifo web` e `sisifo agent --help`. A venv é interna ao instalador; não precisa ser ativada para esses comandos.

## Instalação e IA NVIDIA

No PowerShell, dentro da pasta do projeto: `./install.ps1`. No Linux: `bash install.sh`.
O instalador prepara as imagens básicas e solicita provedor, modelo e chave de API com entrada oculta.
Para configurar novamente: `docker compose run --rm sisifo setup`.

```powershell
docker compose run --rm sisifo ai-status
docker compose run --rm sisifo analyze ID --provider nvidia
docker compose run --rm sisifo analyze ID --provider export
```

O modelo padrão NVIDIA é `nvidia/nemotron-3-super-120b-a12b`. A chave fica em `.sisifo-config/nvidia.key`, com permissões locais restritas, fora do Git e das imagens. É um arquivo de credencial, não um cofre criptografado; não inclua essa pasta em backups compartilhados. Somente o container do aplicativo recebe essa pasta. `NVIDIA_API_KEY` também é aceita no uso nativo. A chave não entra em argumentos, prompts ou relatórios.

**Após configurar NVIDIA, `analyze ID` envia as evidências dessa sessão à API oficial.** O vault não é enviado. `--provider export` nunca chama a API. `--model` altera apenas o modelo e mantém o provedor configurado.

A análise usa lotes de até 20 evidências/24 mil caracteres, com até 50 lotes por execução. `--max-batches` aceita 1–100 e limita o número de lotes consultados. Os campos truncados e itens omitidos são registrados; limite atingido ou falha após um lote válido gera resultado parcial. Respostas já validadas são preservadas. Todos os IDs citados e a cobertura declarada de cada lote são verificados. Validação estrutural não garante interpretação correta.

`session verify ID` confere arquivos, hashes, contagens e referências. Comparações importadas exigem args, versão e scaninfo equivalentes; cobertura ausente ou dependente de arquivos externos é recusada. Mudanças de versão/banner aparecem em `changed`. Horário original da observação é separado da importação. Sessões antigas v2 continuam legíveis, mas hashes históricos ausentes não são inventados.

O Metasploit é opcional: `docker compose build metasploit`; diagnóstico com `docker compose run --rm sisifo doctor --modules metasploit`. O diagnóstico padrão exige apenas Nmap/Nikto.

## Início com Docker Desktop (Linux containers)

Abra um terminal na pasta deste projeto. Inicie o Docker Desktop e aguarde o engine ficar disponível.

```powershell
docker compose build sisifo nmap
docker compose pull nikto
docker compose run --rm sisifo doctor
```

O serviço `sisifo` controla containers irmãos pelo socket Docker. Esse acesso permite administrar o Docker do computador: mantenha este serviço local e não exponha sua API. Os containers das ferramentas não recebem o socket. As ferramentas usam a rede bridge, com Nmap TCP connect, sem exigir host networking.

## Experimento local

Um servidor Nginx opcional serve de alvo de teste; ele não publica portas no computador.

```powershell
docker compose --profile lab up -d lab
docker compose run --rm sisifo scan lab --project laboratorio
docker compose run --rm sisifo scan http://lab --modules nikto --project laboratorio-web
docker compose run --rm sisifo session list
docker compose --profile lab stop lab
```

Cada scan imprime um ID. Os relatórios ficam em `data/sessions/ID/reports/report.md` e `report.json`. Saídas originais e erros ficam em `raw_output`; a imagem efetivamente usada é identificada por seu ID no registro da execução. Alvos reais devem pertencer ao seu ambiente autorizado. No Docker, `localhost` aponta para o container da ferramenta; para um serviço no Windows, use o endereço apropriado, como `host.docker.internal`.

Nmap aceita IP, CIDR ou hostname. Nikto aceita uma origem HTTP/HTTPS (host e porta, sem credenciais/caminho). Para rodar ambos na mesma sessão, use `scan http://lab --modules nmap,nikto`: Nmap avalia o host (portas padrão), Nikto avalia a origem web informada. `--modules` aceita módulos registrados; nomes repetidos ou desconhecidos são recusados antes de criar a sessão.

```powershell
docker compose run --rm sisifo report ID
docker compose run --rm sisifo analyze ID
docker compose run --rm sisifo compare ID_ANTERIOR ID_ATUAL
```

Sem provedor configurado, `analyze` apenas exporta `analysis/ai-input.json`, legível por outra IA, sem enviar dados. A comparação requer projeto, alvo, ferramentas, comandos e imagem equivalentes, com ambas as sessões concluídas. "Não observado novamente" não significa "corrigido".

## IA local opcional

Ollama é um perfil opcional do Compose. Escolha um modelo compatível com sua memória RAM/VRAM; o projeto não baixa modelos automaticamente.

```powershell
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull NOME_DO_MODELO
docker compose run --rm sisifo analyze ID --model NOME_DO_MODELO
```

Substitua os nomes em maiúsculas. A resposta fica em `analysis/ID_DA_ANALISE/report.md`, acompanhada dos dados enviados, modelo, prompt, cobertura e resposta original. Erros de IA preservam o relatório determinístico. Referências inexistentes são rejeitadas; validar referências e estrutura não garante que a interpretação seja correta. Os primeiros lotes respeitam limites explícitos e registram omissões; revise a cobertura antes de usar as conclusões.

Para um Ollama já rodando no computador, passe `--endpoint http://host.docker.internal:11434`, caso o serviço aceite conexões do Docker. Por padrão, Compose usa `http://ollama:11434`. O perfil Ollama não publica portas no host. Não use um endpoint externo sem decidir que os dados podem ser enviados a ele.

## Importar evidências sem varrer rede

Coloque o XML em `data/imports/example.xml`:

```powershell
docker compose run --rm sisifo import-nmap /data/imports/example.xml --target lab --project laboratorio
```

Importações não provam que a origem seja autêntica. O arquivo original e seu hash são preservados. Sessões da versão 0.1 não são migradas automaticamente: preserve-as como arquivo histórico; o formato 0.2 usa UUID e uma pasta de dados externa ao pacote.

## Desenvolvimento local

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
```

Os wrappers dos instaladores usam `data` e `.sisifo-config` do projeto, compartilhados com Compose; variáveis `SISIFO_DATA_DIR` e `SISIFO_CONFIG_DIR` têm precedência. Fora de uma instalação vinculada ao repositório, o padrão de dados é `~/.sisifo`. `SISIFO_TOOL_NETWORK` escolhe a rede das ferramentas, padrão bridge. Para usar os mesmos dados do Compose, configure `SISIFO_DATA_DIR` para a pasta `data` do projeto. Configurações de imagens: `SISIFO_NMAP_IMAGE`, `SISIFO_NIKTO_IMAGE`. Provedor: `SISIFO_OLLAMA_URL`.

## Adicionar ferramentas

Crie adaptador com validação de alvo, comando em lista e parser de um formato estruturado. Registre em `core/modules.py` e inclua a imagem no preparo do ambiente. O executor central cuida de estados, timeout, logs, saída e limpeza. Forneça fixtures e testes de sucesso/falha. Um adaptador Metasploit deverá definir explicitamente quais módulos e resultados normalizar; não haverá seleção automática de exploits pela IA.

## Interface web (v0.3+)

Inicie a interface web local e abra no navegador padrão:

```powershell
sisifo web
```

Opções:

- `--port <N>` – porta de escuta (padrão 8000).
- `--no-browser` – inicia o servidor sem abrir o navegador.

O servidor escuta apenas em `127.0.0.1`. No Docker a porta é publicada no loopback do host; o navegador do host abre `http://127.0.0.1:<porta>`. Pressione **Ctrl+C** para encerrar limpos.

### Funcionalidades da interface web

A UI web oferece tema escuro em português com:

**Visão geral**
- Sessões recentes com status e ferramentas
- Módulos disponíveis e seu estado
- Status das integrações (provedor IA, conectores OSINT)

**Sessões**
- Lista com filtros por ID, projeto, alvo, status
- Detalhes: execuções, ferramentas, comandos, erros, timestamps
- Links diretos para relatórios e download de evidências

**Relatórios**
- Visualização Markdown/JSON no navegador
- Download dos relatórios como arquivos
- Verificação de integridade de achados e artefatos
- Comparação de duas sessões compatíveis

**Nova Execução**
- Formulário com validação de alvo (IP, CIDR, hostname, URL)
- Seleção múltipla de módulos (Nmap, Nikto, Metasploit)
- Nome do projeto e timeout configuráveis
- Execução em background com acompanhamento de progresso

**Análise por IA**
- Seleção de sessão, provedor (NVIDIA/Ollama/Export), modelo, limite de lotes
- Indicação do que é enviado e para qual destino
- Acompanhamento de progresso com resultados parciais
- Exportação de pacotes offline

**OSINT (Integrações)**
- Catálogo de conectores com capacidades e status
- Formulário de consulta com conector, tipo (domínio/IP/URL/hash) e validação
- Execução em background com rate limiting e retentativas
- Resultados com proveniência, timestamps, avisos, limitações

**Configurações**
- Configuração de provedor e modelo de IA
- Gerenciamento de senha da interface web
- Credenciais de conectores OSINT (arquivos por serviço)
- Indicadores de status para todos os serviços configurados

### Segurança da interface

- **Autenticação de sessão** com cookies HttpOnly, SameSite=Strict
- **Proteção CSRF** via double-submit cookie com tokens HMAC
- **Validação Host/Origin** incluindo proteção contra DNS rebinding
- **Confinamento de caminhos** para downloads (previne directory traversal)
- **Sem CORS irrestrito** — API acessível apenas da mesma origem
- **Validação de entrada** em todos os endpoints (modelos Pydantic)
- **Segredos nunca expostos** — credenciais não em logs, respostas, URLs, localStorage
- **Senha da web** via `sisifo setup-web` (armazenada em `.sisifo-config/web.json` com permissões restritas)

### Perfil Docker web

```powershell
docker compose --profile web up -d web
# Acesso em http://127.0.0.1:8000
```

O serviço `web` roda a mesma imagem `sisifo` com o comando `web`, publicando a porta 8000 apenas em `127.0.0.1`.

### Menu interativo

```powershell
sisifo menu
```

Apresenta menu no terminal:

1. **Usar pelo terminal** – lembrete para usar a CLI diretamente.
2. **Abrir interface web local** – executa `sisifo web`.
3. **Configurar IA (NVIDIA/Ollama)** – executa `sisifo setup`.
4. **Configurar senha da interface web** – executa `sisifo setup-web`.
5. **Sair** – fecha o menu.

Scripts não interativos continuam funcionando; o menu só aparece quando você chama `sisifo menu`.

## Conectores OSINT (extensibilidade)

Novo pacote `sisifo.osint` define contrato para serviços de inteligência externa (Shodan, Censys, VirusTotal, urlscan.io, …). Cada conector declara:

- ID, nome, descrição, versão
- Tipos de consulta suportados (domínio, IP, URL, hash)
- Campos de credencial necessários
- Destinos de rede permitidos
- Capacidades, limites, estado de implementação

Resultados são normalizados a esquema comum preservando proveniência, timestamps, evidência, URL de referência, avisos e limitações. Inclui conector **dummy** de referência para testes, sem requisições de rede.

### Camada de execução

O `OsintExecutor` aplica as regras declaradas em tempo de execução:

- **Validação de configuração** antes de qualquer requisição
- **Enforcement de tipo de consulta** — tipos não suportados recusados
- **Validação de formato de consulta** (domínio, IP, URL, hash)
- **Allowlist de destinos** — apenas hosts declarados alcançáveis
- **Limites de timeout e tamanho de resposta**
- **Política de retentativa** com backoff exponencial (429, 5xx)
- **Tratamento de erros HTTP** (401, 403, 429, 5xx) com códigos estruturados
- **Controle de redirecionamento** (desabilitado por padrão)
- **Validação de resposta JSON**
- **Rate limiting** (limites declarados pelo conector)
- **Rastreamento de proveniência** — fonte, timestamps, dados originais preservados

### Adicionando um conector

1. Crie classe herdando de `sisifo.osint.BaseConnector`.
2. Preencha atributo `meta` (`ConnectorMeta`).
3. Implemente `validate_config`, `diagnose`, `query`, `normalize`.
4. Implemente `validate_query` para validação de formato.
5. Registre em `sisifo.osint.registry._registry`.
6. Declare `allowed_destinations`, `limits` (timeouts, retries, max_response_size, rate_per_minute).

A interface web lista conectores disponíveis, exibe estado de configuração e permite executar consultas com confirmação explícita antes de qualquer requisição externa.

### Configuração de conectores

Cada conector armazena credenciais em arquivo separado: `.sisifo-config/osint_<connector_id>.json`

```json
{
  "api_key": "sua-api-key",
  "secret": "outro-campo-se-necessario"
}
```

Arquivos são criados com permissões restritas (0o600 no Unix, ACL no Windows). A UI web mostra apenas "configurado"/"não configurado" — nunca os valores dos segredos.

## Gestão de credenciais (multi‑serviço)

O diretório de configuração (`.sisifo-config/`) armazena **arquivos separados por serviço**:

- `config.json` — configurações não secretas (provider, model, version)
- `nvidia.key` — chave NVIDIA (legado, ainda suportado)
- `web.json` — senha da interface web
- `osint_<connector_id>.json` — credenciais dos conectores OSINT

Após salvar, a UI web nunca devolve o segredo completo; apenas indica "configurada". Segredos nunca são gravados em:

- localStorage / URLs / logs / prompts / relatórios / Git / imagens Docker
- containers das ferramentas (socket Docker não é passado a eles)

Remoção exige confirmação explícita. Variáveis de ambiente (`NVIDIA_API_KEY`, `SISIFO_WEB_PASSWORD`, `SISIFO_<SERVICO>_KEY`, etc.) e arquivos locais têm precedência documentada no esquema de configuração.

Migração da config v1 é automática e reversível — o formato antigo é detectado e atualizado no carregamento.

## Exportar para Obsidian

Monte o vault somente no comando de exportação (PowerShell):

```powershell
docker compose run --rm -v "D:/Projeto_Odisseia/Odisseia:/vault" sisifo export-vault ID /vault
```

O resumo é salvo em `30-Projetos/sisifo/relatorios/ID.md`. Repetir a mesma exportação não duplica a nota; se você tiver alterado seu conteúdo, o comando recusa sobrescrevê-la. Logs brutos permanecem na pasta de dados.

## Licença

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
