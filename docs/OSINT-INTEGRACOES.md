# Integrações OSINT

## HIBP e terminal OSINT — atualização de 2026-10-10

```console
sisifo help
sisifo osint terminal
sisifo osint list
sisifo osint config hibp
sisifo osint query hibp email usuario@exemplo.com
sisifo osint --help
```

O comando instalado dispensa ativar o ambiente virtual. `sisifo osint` continua como atalho compatível para o terminal interativo. `/ajuda`, `/voltar`, `/limpar` e `/sair` orientam a navegação na seleção de conector/consulta. O menu principal reutiliza o mesmo terminal.

### Contrato do conector

O conector `hibp` consulta e-mails em `/breachedaccount/{email}`, com segmento URL codificado e `truncateResponse=false`. A chave é configurada com entrada oculta; validar seu formato não comprova assinatura ou autenticação. Consultas a contas exigem a assinatura apropriada. Não há promessa de gratuidade. Fonte: [documentação oficial HIBP](https://haveibeenpwned.com/API/v3), consultada em 2026-10-09.

O limite de 30 requisições/minuto é local; cada tentativa HTTP é contabilizada uma vez. 401/403/429 mantêm códigos internos específicos. Somente 404 no breachedaccount é convertido em resultado vazio; isso não comprova ausência de exposição. Respostas malformadas não são descartadas silenciosamente. Cancelamento e limite total de tempo preservam suas exceções e interrompem tarefas HTTP/backoff. Retentativas são limitadas.

### Web e confirmação

- `GET /api/osint/connectors`: catálogo e configuração.
- `POST /api/osint/proposals`: valida conector, tipo e consulta; retorna prévia com identificador.
- `POST /api/osint/query`: aceita apenas `proposal_id` e `confirmed: true`.
- `POST /api/osint/ai/preview`: recebe `job_id` e índices (base zero) dos resultados selecionados.
- `POST /api/osint/ai/interpret`: executa a prévia aprovada usando `proposal_id` e `confirmed: true`.

As propostas ficam no servidor, vinculadas à sessão e ao conteúdo, por cinco minutos. Repetir a aprovação retorna o mesmo job. Reiniciar o servidor invalida propostas pendentes. Autenticação e CSRF são obrigatórios. Integrações externas que usavam o corpo antigo de `/api/osint/query` precisam adotar a etapa de proposta.

### Interpretação pela IA

No terminal, após uma consulta com resultados, selecione números separados por vírgulas. Na web, selecione os resultados e use “Preparar prévia para IA”. A seleção permite até 20 itens e 7.000 caracteres. A prévia minimiza campos, omite a consulta/e-mail e aplica sanitização. Referências `resultado-N` permitem relacionar a interpretação às evidências locais. A IA não executa consultas adicionais.

O envio ao HIBP e o envio à IA têm confirmações separadas. A proposta em linguagem natural na web também solicita autorização antes de enviar o objetivo à IA; recusar mantém a análise local. Sem IA configurada, as consultas OSINT permanecem disponíveis. O texto da IA é apresentado como texto, não HTML executável. Mudanças na conexão de IA invalidam a autorização daquela prévia.

### Verificação e limites

Instale dependências de desenvolvimento com `pip install -e ".[dev,web]"`. O extra `dev` inclui `pytest-asyncio`. Execute `pytest -q`, `ruff check .` e `node --check sisifo/web/static/app.js`.

Os testes de transporte usam HTTP simulado e credenciais sintéticas; não validam uma assinatura real. Os testes JavaScript exercitam os contratos de proposta/renderização com DOM simulado, não substituem E2E em navegador. A aplicação web permanece single-user. Métodos auxiliares de catálogo HIBP continuam internos. Outros provedores abaixo não estão implementados por esta atualização.

---

## 2. DeHashed

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 3. BreachDirectory

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 4. LeakPeek

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 5. Shodan

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 6. Censys

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 7. FOFA

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 8. SecurityTrails

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 9. CNPJÁ (Pública e Comercial)

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 10. OpenCorporates

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 11. Numverify

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 12. Twilio

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 13. IPinfo

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 14. Ipstack

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Em pesquisa - aguardando documentação oficial acessível*

---

## 15. OSINT UI API

**Data da consulta:** 
**URL oficial da documentação:** 
**Versão da API:** 

*Serviço não identificado de forma inequívoca. Solicitar endereço oficial.*

---

## Matriz de Capacidades (Resumo)

| Serviço | Query Types | Auth | Free Tier | Rate Limit | Status |
|---------|-------------|------|-----------|------------|--------|
| HIBP | email | API Key (32 hex) | Sim | ~40/min (local: 30/min) | ✅ Implementado |
| DeHashed | email, domain, phone, ip | API Key | Limitado | ? | 🔍 Pesquisando |
| BreachDirectory | email, domain | API Key | ? | ? | 🔍 Pesquisando |
| LeakPeek | email, domain | API Key | ? | ? | 🔍 Pesquisando |
| Shodan | ip, domain, org | API Key | Limitado | ? | 🔍 Pesquisando |
| Censys | ip, domain, cert | API Key + Secret | Limitado | ? | 🔍 Pesquisando |
| FOFA | ip, domain, title | API Key | Limitado | ? | 🔍 Pesquisando |
| SecurityTrails | domain, ip | API Key | Limitado | ? | 🔍 Pesquisando |
| CNPJÁ Pública | cnpj | Nenhum/Open | Sim | ? | 🔍 Pesquisando |
| CNPJÁ Comercial | cnpj | API Key | Não | ? | 🔍 Pesquisando |
| OpenCorporates | company, officer | API Key | Sim (limitado) | ? | 🔍 Pesquisando |
| Numverify | phone | API Key | Sim (limitado) | ? | 🔍 Pesquisando |
| Twilio | phone | Account SID + Token | Não (trial) | ? | 🔍 Pesquisando |
| IPinfo | ip | API Key | Sim (limitado) | ? | 🔍 Pesquisando |
| Ipstack | ip | API Key | Sim (limitado) | ? | 🔍 Pesquisando |
| OSINT UI API | ? | ? | ? | ? | ❓ Não identificado |

* = requer plano pago

---

## Próximos Passos

1. ✅ HIBP documentado e implementado (com correções: EMAIL type, hex key, cancellation, typed errors)
2. 🔍 Pesquisar documentação oficial dos demais serviços
3. Validar fluxo completo HIBP: CLI → Web → IA (concluído)
4. Implementar fluxo interativo OSINT (CLI interativo + Web "Investigar com OSINT")
5. Iterar para próximo serviço (DeHashed ou Shodan)

### Correções complementares — 2026-10-10

A integração genérica `osint_hibp.query` fica bloqueada pelo executor compartilhado:
use a rota OSINT com proposta e confirmação; `approval_ref` arbitrário não desbloqueia a operação.
O catálogo HIBP reavalia a configuração em cada leitura, inclusive após salvar/remover credenciais.
A interpretação propaga o Control do job até o transporte assíncrono da IA, cancelável enquanto aguarda resposta.
`Retry-After` aceita segundos e data HTTP; se exceder o orçamento, a consulta encerra com o prazo informado,
sem repetir antes do permitido. Chamadas OSINT sem orçamento explícito usam 60 segundos.
Cada conector declara `ai_evidence_fields`; fontes desconhecidas ou evidência exportável vazia são rejeitadas.

## Experiência guiada OSINT — 2026-10-10

- Web com três passos, configuração direta dos serviços, seleção automática do tipo de consulta e instruções quando nenhuma integração está configurada.
- Resultados, estados e erros em português; detalhes técnicos recolhidos, consultas mais recentes primeiro e feedback imediato de execução/cancelamento.
- IA opcional: seleção dos resultados, prévia sanitizada e confirmação separada; orientação explícita quando a conexão não está configurada.
- Terminal aceita escolha numérica do serviço, confirmações s/n (sim/não) e 0 para voltar. Entrada: `sisifo osint terminal`.
- Corrigida falha HIBP encontrada no navegador: BreachDate sem AddedDate não pode preencher um timestamp que exige fuso horário. A data permanece na evidência, sem inventar horário.

### Validação e limites

286 testes passaram, 4 avisos conhecidos (1 Starlette/httpx e 3 serializações de enum Pydantic). Ruff e sintaxe JavaScript aprovados. Navegador real contra FastAPI local, com HIBP e IA simulados: configuração, recusa/aceite de envio, resultado positivo, resultado vazio, credencial recusada, cancelamento, IA não configurada, descoberta de modelo e interpretação autorizada. Sem erros no console observado.

Esses testes não homologam HIBP/IA em produção. Não foram utilizadas credenciais reais, serviços pagos, novo teste Linux ou rebuild Docker. O roteiro de navegador foi manual, não uma suíte E2E automatizada permanente. Nenhum commit/push nesta tarefa.
