# Rede: correções e validação

O serviço de rede usa TShark para análise offline e Dumpcap para captura nativa.

- A parada grava uma solicitação consumida pelo processo proprietário. O status permanece `running` até o encerramento efetivo; o arquivo parcial recebe tamanho, hash e horário de término. Um lock de processo limita a captura a um executor por diretório de dados. Registros abandonados tornam-se `interrupted` quando não há proprietário ativo.
- IDs devem conter 32 caracteres hexadecimais. Metadados e arquivos referenciados são confinados ao armazenamento de capturas. Divergência de hash impede análise.
- Cache v2 separado por hash do arquivo, filtro de exibição e versão do TShark. Cache textual antigo não é reutilizado.
- Estatísticas derivam de campos estruturados, com resolução de nomes desativada (`-n`). A distribuição usa o protocolo de nível mais alto por pacote, não a hierarquia completa de camadas; evita contar o mesmo pacote várias vezes no total.
- Falha de processo ou filtro inválido gera erro, nunca sucesso vazio. Saída de análise limitada a 32 MiB, stderr a 1 MiB e tempo por processo. O índice limitado ainda é carregado em memória; arquivos cuja dissecação exceda esse limite exigem filtros mais restritos.
- Rotação e diretório personalizado são recusados explicitamente nesta versão: o modelo de evidência atual representa um arquivo único e não deve alegar suporte correto a múltiplos arquivos.

## Testes

`python -m pytest tests/test_network.py -q`

Fixtures `network-synthetic.pcap` e `.pcapng` possuem dois pacotes Ethernet/IPv4 sintéticos: UDP e TCP, endereços de documentação. O gerador reproduzível está em `tests/fixtures/generate_network.py`. Nenhum tráfego real foi coletado.

Os testes de integração chamam TShark e capinfos reais quando instalados. Sem TShark, dois casos são pulados explicitamente. `SISIFO_REQUIRE_TSHARK=1` transforma ausência em falha. O job `network-integration` da CI instala TShark no Ubuntu e exige a integração real. A configuração de CI não significa que essa execução remota já ocorreu.

Os testes locais de parada usam um processo Python controlado que aguarda; não abrem interfaces de captura. Captura real com Npcap/Dumpcap ainda exige validação específica no ambiente do usuário.
