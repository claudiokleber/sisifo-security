# Conexão e conversa com a IA

## Começar pelo terminal

Execute `sisifo setup`, escolha conectar API e informe:

1. O endereço base fornecido pelo serviço (normalmente termina em `/v1`).
2. A chave de API, com entrada oculta.
3. Um modelo da lista retornada pelo serviço, ou seu identificador manual.

O botão/etapa **Testar conexão e salvar** envia uma mensagem curta ao modelo.
Só salva depois de obter uma resposta textual completa. Essa chamada pode consumir
créditos. Consultar `/models` pode funcionar sem autenticação em alguns serviços;
por isso a lista, sozinha, não comprova que a chave permite gerar respostas.

Use `sisifo chat` para conversar. `/limpar` reinicia o histórico e `/sair` encerra.
` sisifo chat --session ID ` inclui as evidências de uma sessão após mostrar uma
prévia e solicitar confirmação. O menu de IA também oferece conversa, conexão e
análise estruturada. `sisifo ai-status` mostra apenas a configuração local,
sem fazer chamadas e sem afirmar que a API está disponível naquele momento.

## Interface web

Em **Configurações → Conexão com a IA**, informe endereço e chave, clique em
**Buscar modelos**, selecione/informe o modelo e use **Testar conexão e salvar**.
A chave fica vazia na tela depois de salva e não retorna nas respostas de status.

Na aba **Análise IA**, escreva sua pergunta. Para incluir evidências, expanda
**Adicionar contexto**, informe a sessão, revise o contexto e autorize o envio.
A análise estruturada em lotes continua disponível em uma seção separada.
O histórico da conversa fica apenas na memória da página/terminal: não é salvo
como relatório e se perde ao fechar ou recarregar. Cada nova pergunta reenvia o
histórico atual e, quando autorizado, o contexto da sessão; há custo proporcional
no serviço escolhido. A IA conversa e recomenda; não executa ferramentas.

## Compatibilidade e limites

Esta versão suporta o protocolo com `GET /models` (lista `data[].id`) e
`POST /chat/completions` (messages, model, max_tokens e resposta choices).
Uma chave sozinha não identifica necessariamente o serviço. APIs com protocolo
diferente precisam de um adaptador; nenhuma chave arbitrária é considerada válida.
A descoberta usa a lista retornada pela API, sem inventar modelos nem garantir
acesso a todos os itens. Se o catálogo não existir, use o identificador manual.
Modelos de imagem, embeddings ou respostas não textuais podem aparecer no catálogo,
mas só modelos que passam no teste de conversa são salvos. O relatório estruturado
exige também suporte a JSON (`response_format`) e ao schema do Sísifo.

Configurações antigas continuam legíveis. Os nomes antigos deixam de ser opções
obrigatórias nos formulários; os identificadores internos são preservados para
compatibilidade com análises e planos existentes. Para servidor local, use sua API
compatível (por exemplo, a URL local com `/v1`). HTTP só é aceito em loopback;
serviços externos precisam de HTTPS. Redirecionamentos não são seguidos.

A credencial nova fica em `ai_connection.json` no diretório de configuração,
protegido pelas permissões do sistema, sem criptografia adicional em repouso.
`SISIFO_AI_API_KEY` substitui a chave salva para a conexão configurada. Ao mudar
endereço, informe explicitamente outra chave: a anterior não é reaproveitada no
novo destino. O modo offline desativa consultas sem apagar a credencial guardada.

Limites: 40 mensagens, 8000 caracteres por mensagem, 32000 no histórico e 24000
no contexto de sessão; respostas HTTP até 2 MB. Sessões maiores devem usar análise
em lotes. A conversa não usa streaming nem retries automáticos. Timeouts interrompem
a espera local, mas não garantem que o serviço externo não tenha processado/cobrado
a solicitação. O mascaramento automático de dados sensíveis é heurístico; revise
a prévia. Mensagens e resultados nunca devem incluir chaves voluntariamente.

## Verificação desta entrega

Testes automatizados usam chaves fictícias e transporte HTTP simulado; cobrem
descoberta, autenticação rejeitada, redirecionamentos, troca de destino, preservação
da configuração após falha, CLI, API web, CSRF, histórico e validação de mensagens.
O fluxo de configuração e conversa também foi exercitado no navegador com servidor
local simulando a API. Não houve consulta a modelos comerciais nem uso de chave real.
