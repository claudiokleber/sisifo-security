# Validação OSINT e IA

## Testes reproduzíveis

Em um ambiente virtual de desenvolvimento:

```powershell
python -m pip install -e ".[dev,web]"
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m playwright install chromium
python -m pytest -m e2e tests/test_e2e_osint.py -q
```

No Linux de CI, use `python -m playwright install --with-deps chromium`.
A suíte padrão exclui explicitamente a marca `e2e`; isso não significa que os
testes de navegador passaram. O job `browser-e2e` os executa separadamente e
falha se Chromium estiver ausente. Para executar ambas: `python -m pytest -m ""`.

O servidor de teste reserva uma porta aleatória com o mesmo socket entregue ao
Uvicorn. A prontidão verifica HTTP 200, token exclusivo e PID. Configuração,
senha e dados são temporários. Não use credenciais reais nesse ambiente.

Somente o transporte HTTP externo é substituído. Rotas, propostas, executor,
normalização, jobs, cancelamento e interpretação permanecem reais. O endpoint
de diagnóstico existe apenas no script em `tests/support/`, nunca no produto.

Cobertura: configuração inicial, teclado/tela estreita, entrada inválida,
recusa de confirmação, sucesso, vazio, autenticação, rate limit, timeout,
cancelamento, renderização de conteúdo hostil, envio separado à IA,
IA desconectada e repetição da mesma aprovação sem duplicar execução.

Defina `SISIFO_E2E_ARTIFACTS` para guardar screenshots, traces e log do servidor
nas falhas. A CI usa `artifacts/e2e` e retenção de sete dias. Os artefatos contêm
somente dados sintéticos, mas podem incluir os tokens da sessão descartável;
nunca reutilize o roteiro contra dados reais.

## Resultados de execução (2026-10-12)

### Suíte E2E (Chromium + HTTP simulado)
- **1ª execução**: 11/11 aprovados em 69,09s — relatada anteriormente, sem artefato independente
- **2ª execução**: 11/11 aprovados em 63,12s — relatada anteriormente, sem artefato independente
- **3ª execução anterior**: 11/11 em 62,80s — apenas relatada, sem artefato independente.
- **Nova execução de consolidação (2026-10-12 17:00)**: 11/11; console relatado de 62,02s, duração interna JUnit de 61,683s. Artefato `artifacts/validation/e2e.xml` inspecionado, sem falhas, erros ou skips.
- Os artefatos disponíveis comprovam uma execução E2E e uma convencional, não três execuções consecutivas. Os testes não foram reexecutados durante esta atualização documental.

Cenários cobertos e confirmados:
- Primeiro acesso sem configuração → botão desabilitado, configuração habilita
- Configuração sintética e atualização imediata da interface
- Uso básico por teclado e tela estreita (390×844)
- Entrada inválida sem transmissão (validação HTML5)
- Confirmação recusada sem execução (dialog.dismiss)
- Resultado positivo (Test Breach) e vazio com ressalva ("não garante")
- Credencial recusada (401), rate limit (429) e timeout (ReadTimeout)
- Cancelamento propagado até o transporte (contador `cancelled` incrementado)
- Conteúdo malicioso exibido como texto, sem execução (XSS payload renderizado, sem `<img>`, `window.__xss` undefined)
- Seleção de evidências, prévia e autorização separada para IA
- Ausência de transmissão à IA antes da autorização (contador `ai` == 0 até clique em "Autorizar")
- Orientação quando a IA não está configurada ("A IA ainda não está configurada")
- Repetição da mesma aprovação sem duplicar job ou consulta externa (mesmo `job_id`, `hibp` == 1)

### Suíte convencional
- 286 testes aprovados, 11 deselected (marca e2e) — **registrado na consolidação anterior** com artefato JUnit (`artifacts/validation/unit.xml`, timestamp 2026-10-12T17:00:10.697660-03:00)
- 1 aviso Starlette/httpx (TestClient deprecated httpx fallback) — registrado, não silenciado

### Qualidade de código
- `ruff check sisifo tests`: **All checks passed** — registrado na consolidação anterior
- `ruff format --check sisifo tests`: **89 files already formatted** — registrado na consolidação anterior
- `ruff format --check .`: **101 files already formatted** — relatado anteriormente (escopo mais amplo, inclui arquivos de configuração raiz)
- Sintaxe JavaScript (`sisifo/web/static/app.js`, `login.js`): **válida** — registrado na consolidação anterior (`node --check`)

### Isolamento e limpeza
- Cada teste usa `tmp_path` dedicado; dados, configuração e porta são temporários
- Prontidão confirmada por HTTP 200 + token exclusivo + PID correspondente
- Servidores e navegadores encerrados mesmo após falha (fixture `web_server` e `page` com `finally`)
- Nenhum processo descartável (`osint_server.py`, Uvicorn nas portas de teste) permaneceu ativo após as execuções
- Portas 63497 e 53959 (das execuções anteriores manuais) já estavam livres antes da execução
- Verificação pós-execução: nenhum processo `osint_server.py` ou `uvicorn` em portas de teste ativo

### Verificação de CI remota (GitHub Actions)

Consultada em 2026-10-12 pela API pública do GitHub, sem necessidade de instalar `gh`.
[Execução checks 38088423076](https://github.com/claudiokleber/sisifo-security/actions/runs/38088423076): **success**, branch
`melhorias/osint-experiencia`, SHA `11adfe59c6b166ed936fcf27b17bf0e746da93a4`.

Jobs aprovados: seis combinações unitárias (Ubuntu/Windows × Python 3.11/3.12/3.14),
network-integration e duas instalações nativas (Ubuntu/Windows).
**Essa execução não contém browser-e2e.** O job existe no workflow local posterior.
O resultado remoto valida o commit publicado, não o checkout com alterações locais.

Próxima ação: revisar e versionar as alterações, publicar somente mediante autorização
 e acompanhar uma nova execução que inclua browser-e2e. A homologação HIBP/IA real
permanece independente. O diagnóstico anterior de bloqueio por ausência de `gh`
foi superado pela consulta à API pública.

### Classificação das evidências

| Resultado | Classificação | Evidência |
|-----------|---------------|-----------|
| Unit tests 286 passed (2026-10-12 17:00) | **Registrado na consolidação anterior** | `artifacts/validation/unit.xml` (JUnit XML) |
| E2E tests 11/11 passed (2026-10-12 17:00) | **Registrado na consolidação anterior** | `artifacts/validation/e2e.xml` (JUnit XML) |
| E2E 1ª execução 69,09s | Relatado anteriormente, sem evidência independente | — |
| E2E 2ª execução 63,12s | Relatado anteriormente, sem evidência independente | — |
| E2E 3ª execução 62,80s | Relatado anteriormente, sem evidência independente | — |
| Ruff check passed | **Registrado na consolidação anterior** | Saída de console |
| Ruff format --check 89 files | **Registrado na consolidação anterior** | Saída de console |
| Ruff format --check 101 files | Relatado anteriormente | Escopo `.` vs `sisifo tests` |
| JS syntax valid | **Registrado na consolidação anterior** | `node --check` saída vazia |
| Nenhum processo remanescente | **Registrado na consolidação anterior** | `Get-CimInstance` + `netstat` |

### Identidade do código testado
- Commit base: `11adfe59c6b166ed936fcf27b17bf0e746da93a4` (HEAD)
- Arquivos de teste executados: `tests/test_e2e_osint.py` (untracked), `tests/conftest.py` (modificado), `tests/support/osint_server.py` (untracked)
- Código de produto: múltiplos arquivos modificados não commitados (ver `git status`)
- O commit base possui CI aprovada, mas o conteúdo local modificado não está identificado por esse SHA.
- Não foi produzido manifesto de hashes durante a execução; não é possível vincular retroativamente o JUnit a um snapshot exato. Na próxima validação, registrar commit e manifesto do conteúdo testado.
- `artifacts/validation/` não está ignorado pelo Git no estado revisado. Manter esses XML fora do commit; não usar `git add .` sem revisar. Nenhum artefato foi apagado nesta atualização.

### Comandos de validação com artefatos
```powershell
python -m pytest -q --junitxml=artifacts/validation/unit.xml
python -m pytest -m e2e tests/test_e2e_osint.py -q --junitxml=artifacts/validation/e2e.xml
```
- Ambiente: Windows 10/11, Python 3.14.7, venv em `.venv`
- Chromium: instalado via `playwright install chromium`
- Transporte HTTP externo: simulado via `httpx.MockTransport` (sem rede real)
- Dados: 100% sintéticos, credenciais fixas de teste

## Limpeza de scripts

`test_hibp_integration.py` era um diagnóstico avulso: chamava `test()` inexistente,
usava mock síncrono para uma operação assíncrona e não fazia assertions.
Os testes em `tests/test_hibp.py` já verificam consulta, normalização e erros.
Sua exclusão não representa remoção de cobertura válida da suíte em `tests/`.
Os cinco scripts `fix_*` removidos aplicavam substituições pontuais de imports
ou variáveis, já incorporadas ao código; não fazem parte da instalação/CI.

## Aviso de dependência

Na máquina revisada em 2026-10-11: FastAPI 0.142.2, Starlette 1.7.0 e httpx 0.28.1.
O TestClient de Starlette tenta importar httpx2 e emite aviso ao usar o fallback
httpx. O aviso não foi suprimido. A migração de dependências requer validação
da matriz Python; não foi feita uma atualização ampla para ocultar o aviso.

## Homologação externa — pendente

Os testes sintéticos não comprovam autenticação, assinatura, disponibilidade
ou respostas atuais de HIBP e de um provedor de IA real.

1. Obtenha autorização para o e-mail consultado, destino e eventual cobrança.
2. Configure a chave por entrada oculta: `sisifo osint config hibp`.
3. Abra `sisifo osint terminal` e revise o destino antes de confirmar.
4. Repita na web com `sisifo web`; compare evidências e referências.
5. Configure IA por `sisifo setup`, sem colocar a chave no chat ou nos logs.
6. Selecione evidências, confira a prévia sanitizada e autorize esse segundo envio.
7. Registre status, limites observados e referências, sem e-mail ou credenciais.

Uma chave de formato válido não comprova acesso ao serviço. Resultado vazio
não comprova ausência de exposição. Não provoque rate limiting em produção:
valide falhas artificialmente no ambiente de teste. Use dados oficiais de teste
quando disponíveis, após conferir a documentação vigente do provedor.
