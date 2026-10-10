# Infraestrutura de integrações

O catálogo é criado por `create_catalog()` na inicialização da web e por invocação
na CLI. `sisifo integration list --json` e `sisifo integration show <id>` consultam
esse registro. Na web, `/api/integration/catalog` expõe os mesmos metadados.
Os estados refletem a configuração na criação do catálogo; após configurar uma
credencial com a web aberta, reinicie o servidor para atualizar esses estados.

`POST /api/integration/execute` exige sessão e CSRF, recebe `integration_id`,
`capability`, `inputs`, `options` e uma `idempotency_key` opcional; retorna 202
com `job_id`. Consulte `/api/integration/jobs/{id}` ou a lista em
`/api/integration/jobs`. O cancelamento usa POST no sufixo `/{id}/cancel`.
Não há executor web paralelo: todos usam o JobManager do lifespan da aplicação.

## Capacidades verificadas

- `network_analysis/analyze`: capture_id obrigatório e display_filter opcional;
  options aceita offset e limit. O capture_id referencia uma captura já importada.
  Usa o NetworkService e TShark offline.
- `network_analysis/packet_detail`: capture_id e packet_number obrigatórios.
- `osint_dummy/query`: query e query_type (domain ou ip). Resultado explicitamente
  simulado, via executor OSINT existente. Requer a configuração osint_dummy.

Handlers são registrados como funções reais, com modelos Pydantic estritos para
inputs e options. Credenciais são escolhidas no registro confiável, resolvidas no
worker e não aceitas como referências arbitrárias do cliente. O carregamento usa
`load_service_config`; esta camada não adiciona novas regras de variáveis de ambiente.
Resultados e progresso passam por sanitização, inclusive dos valores resolvidos.
Os registros de jobs armazenam hashes da requisição, não seu conteúdo original.
A sanitização é uma mitigação, não uma garantia geral de remoção de dados sensíveis
presentes em pacotes. As capturas originais continuam no armazenamento de rede.

## Autorização e limites

A classificação mínima vem da política registrada. Capacidades ativas, intrusivas
ou que exijam aprovação ficam bloqueadas enquanto não houver autoridade de
aprovação implementada. Uma approval_ref arbitrária não desbloqueia a execução.

O servidor limita duração, concorrência por integração e tamanho do resultado e
do progresso persistidos. Cada job executa um handler sequencial, sem retries
nem fan-out. Pedidos de retries, concorrência interna maior que 1 ou limites de
memória/taxa por requisição são rejeitados, pois esses controles não existem.
O timeout inclui espera na fila. Cancelamento/deadline são cooperativos; chamadas
TShark recebem Control e encerram o subprocesso. Um handler futuro que ignore
Control pode atrasar o encerramento: threads Python não são terminadas à força.
O limite de resultado não equivale a um limite da memória usada pelo handler.

A idempotência é atômica no JobManager e persiste com o job: mesma chave e conteúdo
normalizado retornam o mesmo ID; conteúdo diferente retorna conflito; chave nova
permite nova execução. Sem chave, trabalhos idênticos em andamento são reutilizados.
Os vínculos são mantidos enquanto o arquivo do job existir. Após reinício, trabalhos
antes ativos ficam interrupted e não são reexecutados automaticamente.

CLI e servidor são processos distintos. A fila possui um único dono por diretório;
esta etapa não implementa um cliente CLI remoto para execução de integrações.
O campo evidence_root é reservado; este adaptador não cria um novo repositório de
artefatos nem promete referências de evidência que não foram produzidas.

## Validação

`python -m pytest tests/test_integration.py -q` verifica contratos, idempotência
concorrente e após reinício, autorização bloqueada, limites, cancelamento, segredos
sintéticos, CLI e API. Os testes HTTP usam TestClient, não um navegador real.
Dois testes executam handlers registrados contra TShark real com PCAP sintético;
quando TShark está ausente, são marcados como skip. Nenhum teste usa capturas reais,
credenciais reais ou serviços externos. Docker não é validado por esses testes.
