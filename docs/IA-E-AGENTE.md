# IA e agente assistido — revisão de 2026-10-05

## Uso instalado

No Windows, execute `./install.ps1 --update --skip-setup --skip-docker` no repositório para atualizar o comando local preservando credenciais. Abra um novo terminal. No Linux/macOS, use `bash install.sh --update --skip-setup --skip-docker`. O instalador usa o código local; não executa `git pull` nem descarta alterações.

```text
sisifo
sisifo setup
sisifo ai-status
sisifo doctor
sisifo web
```

Os wrappers mantêm uma venv interna e apontam dados/configuração para `data` e `.sisifo-config` do repositório, compatíveis com Compose. As variáveis `SISIFO_DATA_DIR` e `SISIFO_CONFIG_DIR` substituem esses caminhos. A atualização não precisa solicitar novamente a chave já configurada. `setup` pergunta antes de substituir uma chave existente.

Para atualizar a interface executada por Docker:

```text
docker compose build sisifo
docker compose --profile web up -d web
```

Uma instância já iniciada precisa ser reiniciada para carregar código novo. A publicação Compose continua restrita a `127.0.0.1:8000`. Porta ocupada por outro serviço produz orientação para `--port`; o programa não encerra processos alheios.

## Revisar antes de enviar

```text
sisifo analyze ID_DA_SESSAO --provider export
sisifo analyze ID_DA_SESSAO --provider nvidia --max-seconds 600 --token-budget 250000
sisifo analyze ID_DA_SESSAO --provider nvidia --resume ID_DA_ANALISE --token-budget 500000
```

A interface web oferece “Revisar dados (offline)”, tempo máximo, orçamento e ID de retomada. A aba Nova Execução também importa XML Nmap local, limitado a 20 MB. A prévia inclui escopo, horários, resultados dos módulos e cobertura. O mascaramento heurístico reconhece padrões de segredos e campos sensíveis, mas não garante remover todos os dados confidenciais. Os arquivos originais de evidência são preservados.

`--model` mantém o provedor configurado. NVIDIA aceita apenas o endpoint oficial; o navegador só pode selecionar o endpoint Ollama configurado no servidor. Ollama pode executar localmente; um endpoint remoto também recebe dados.

O orçamento é uma reserva conservadora baseada em bytes UTF-8, saída máxima e tentativas possíveis, não uma previsão monetária nem a contagem exata de tokens faturados. O consumo informado pelo provedor é registrado quando disponível. Retomadas mantêm as reservas anteriores; aumente o limite explicitamente quando necessário.

Cada análise tem ID, entrada, metadados, respostas por lote, hashes, resultados validados, consolidação e relatório. A retomada exige a mesma entrada, provedor, modelo, endpoint e versão de prompt. Lotes íntegros concluídos são reutilizados. Arquivos ausentes ou alterados interrompem a retomada para evitar repetir chamadas cobradas silenciosamente.

Observação, hipótese, evidência ausente e citações são campos separados. IDs e citações literais são verificados contra a entrada. Isso não comprova a interpretação factual. Recomendações duplicadas são agrupadas; avaliações diferentes sobre a mesma evidência são sinalizadas para revisão. Nenhuma recomendação é marcada automaticamente como aprovada por uma pessoa.

## Planos do agente

```text
sisifo agent plan ID_DA_SESSAO
sisifo agent show ID_DO_PLANO
sisifo agent run ID_DO_PLANO
```

O plano de revisão padrão verifica a sessão, gera relatório e prepara exportação offline. Para incluir uma consulta de IA, crie o plano com `--provider nvidia` ou `--provider ollama`. A execução apresenta o plano e pede autorização antes das ações externas. Para automação previamente revisada, `--approve HASH_EXATO` vincula a autorização ao conteúdo do plano.

`sisifo agent import-plan arquivo.json` valida planos tipados com escopo explícito. Ferramentas disponíveis: `verify_session`, `build_report`, `analyze_session`, `scan` e `osint`. Não existe ferramenta de shell livre; respostas do modelo nunca são executadas como comandos. Há limites de passos, tempo, tokens e alvos/sessões permitidos.

Este é um agente assistido com planejamento por template e planos JSON, não um planejador autônomo por linguagem natural. O estado de cada passo é persistido antes da execução. Um passo interrompido de resultado incerto não é repetido automaticamente: revise o resultado antes de criar outro plano. Planos concluídos retornam o resultado salvo.

## Jobs e cancelamento

Jobs web possuem ID, histórico persistente, progresso, resultados parciais, idempotência e fila limitada. `SISIFO_MAX_JOBS` controla de 1 a 8 workers (padrão 2). Cada diretório de dados admite um gerenciador ativo; não use múltiplos workers Uvicorn para o mesmo diretório.

Após reiniciar, jobs em andamento são marcados como interrompidos; a aplicação não repete operações externas. O botão Cancelar solicita cancelamento cooperativo. Consultas HTTP já iniciadas podem aguardar seu timeout; cancelamento não desfaz efeitos externos nem custos já incorridos. A sessão web expira em uma hora, alinhada ao token CSRF.

## Limites que permanecem

- Apenas o conector OSINT dummy está incluído. Conectores reais devem usar o transporte central e respeitar configuração, allowlist HTTPS, rate limiting, tamanho, timeout e retries. O rate limiting atual é por processo.
- Credenciais usam arquivos com permissões restritas; não há cofre criptografado em repouso.
- Progresso usa polling; não há WebSocket nem suporte multiusuário.
- Testes da IA usam respostas simuladas; não comprovam qualidade de um modelo real nem disponibilidade de uma conta NVIDIA/Ollama.
- Testes de API e domínio são automatizados; a jornada completa no navegador ainda não tem suíte E2E automatizada.

## Validação executada

Em 2026-10-05: 146 testes passaram no Windows/Python 3.14 e no Linux/Python 3.12 em Docker. Ruff e a verificação sintática de JavaScript passaram. Build de wheel/sdist e imagem Docker concluíram. Atualização Windows e ciclo instalar/atualizar/desinstalar Linux foram verificados. Há um aviso de depreciação Starlette/httpx no cliente de testes; nenhuma falha de teste.

Na interface real em Docker, login e renderização do painel OSINT foram observados. A ferramenta de navegador bloqueou ao manipular a confirmação JavaScript da consulta; a consulta completa foi validada pela API/testes, sem alegação de E2E completo no navegador. Não foram realizadas consultas pagas à IA nem varreduras externas durante essa validação.

O fluxo HTTP real passou tanto no servidor nativo iniciado pelo wrapper Windows quanto no container: login, configuração fictícia do dummy, importação XML, prévia mascarada, job de exportação offline, consulta dummy e histórico de jobs. Ctrl+C concluiu o shutdown do servidor nativo. As instâncias descartáveis foram encerradas; a instância preexistente na porta 8000 não foi reiniciada.
