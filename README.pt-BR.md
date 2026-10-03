# Sísifo 0.2

Ferramentas em containers → evidências persistentes → relatório revisável → IA opcional.

Implementado: CLI, Nmap XML, Nikto JSON, estados e erros de execução, relatório Markdown/JSON, importação Nmap, comparação de sessões e integração Ollama. A IA sugere medidas e hipóteses; não confirma vulnerabilidades automaticamente nem executa ações. Metasploit e interface web ainda não fazem parte desta versão.

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

Sem `--model`, `analyze` apenas exporta `analysis/ai-input.json`, legível por outra IA, sem enviar dados. A comparação requer projeto, alvo, ferramentas, comandos e imagem equivalentes, com ambas as sessões concluídas. “Não observado novamente” não significa “corrigido”.

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
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
```

No uso fora do Docker, os dados ficam em `~/.sisifo`; `SISIFO_DATA_DIR` substitui essa pasta. `SISIFO_TOOL_NETWORK` escolhe a rede das ferramentas, padrão bridge. Para usar os mesmos dados do Compose, configure `SISIFO_DATA_DIR` para a pasta `data` do projeto. Configurações de imagens: `SISIFO_NMAP_IMAGE`, `SISIFO_NIKTO_IMAGE`. Provedor: `SISIFO_OLLAMA_URL`.

## Adicionar ferramentas

Crie adaptador com validação de alvo, comando em lista e parser de um formato estruturado. Registre em `core/modules.py` e inclua a imagem no preparo do ambiente. O executor central cuida de estados, timeout, logs, saída e limpeza. Forneça fixtures e testes de sucesso/falha. Um adaptador Metasploit deverá definir explicitamente quais módulos e resultados normalizar; não haverá seleção automática de exploits pela IA.

## Limitações e próximos passos

- Não é uma avaliação completa de segurança. Nmap observa serviços; Nikto sinaliza possíveis problemas web.
- Limite de artefato: 20 MiB. Rotação dos logs Docker também limita a captura; saída estruturada truncada é tratada como falha de parsing.
- Sem retomada automática de scan após interrupção abrupta do processo/host; revise sessões que permanecerem running.
- Sessões têm um único escritor. Não edite arquivos durante uma execução; não há suporte a múltiplos escritores na mesma sessão.
- As dependências Python do container estão fixadas em `requirements-docker.lock`, com versões verificadas. Tags de imagens e pacotes do sistema ainda podem mudar; os IDs das imagens são registrados por execução. Fixe digests e atualize o lock deliberadamente ao preparar uma distribuição reproduzível.
- Interface web e módulo Metasploit são trabalho futuro. A exportação ao Obsidian é explícita, pelo comando export-vault.
- Licenciado sob a GNU General Public License, somente versão 3 (GPL-3.0-only). Veja os termos completos em [LICENSE](LICENSE). As ferramentas externas mantêm suas próprias licenças.

Fontes: [Docker SDK](https://docker-py.readthedocs.io/en/stable/containers.html), [Nmap XML](https://nmap.org/book/output-formats-xml-output.html), [Nikto Docker](https://github.com/sullo/nikto/wiki/Docker), [Ollama Chat API](https://docs.ollama.com/api/chat).

## Exportar resumo ao Obsidian

Monte o vault somente no comando de exportação (PowerShell):

```powershell
docker compose run --rm -v "D:/Projeto_Odisseia/Odisseia:/vault" sisifo export-vault ID /vault
```

O resumo é salvo em `30-Projetos/sisifo/relatorios/ID.md`. Repetir a mesma exportação não duplica a nota; se você tiver alterado seu conteúdo, o comando recusa sobrescrevê-la. Logs brutos permanecem na pasta de dados.
