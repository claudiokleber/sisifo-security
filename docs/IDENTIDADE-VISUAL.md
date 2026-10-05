# Identidade visual

Especificação atualizada, paleta, inventário e decisões: [Guia da marca](brand/README.md). A integração atual usa somente biblioteca padrão no módulo de terminal, tema automático e botões neutros; os detalhes abaixo registram a primeira integração.

Recursos fornecidos pelo usuário em `Downloads/files`, integrados em 2026-10-05.

- `sisifo-logo.svg`: tela de login e READMEs.
- `sisifo-icon.svg`: cabeçalho e favicon.
- `sisifo-icon-512.png`: ícone de atalho em dispositivos Apple.
- Logos PNG, variantes claras SVG/PNG e `sisifo-mark.svg`: incluídos no pacote em `sisifo/web/static/branding`, disponíveis para fundos claros, materiais e integrações futuras.
- `sisifo/branding.py`: arte de terminal adaptada do arquivo fornecido. Renderizada pelo Rich no menu, com versão compacta, `NO_COLOR`, `SISIFO_ASCII=1` e saída sem ANSI quando redirecionada. Não altera a codificação global de stdout e não inicia animações em threads.

As imagens originais foram copiadas sem alterações; metadados foram preservados. SVGs foram inspecionados e não contêm scripts, eventos executáveis ou referências externas. A web usa recursos locais, sem CDN. O vermelho principal dos botões é mais escuro que o acento do logo para manter legibilidade do texto branco.

Após atualização do código, reinicie o servidor nativo. Para Docker, execute `docker compose build sisifo` e `docker compose --profile web up -d web`. Uma atualização completa do navegador pode ser necessária para substituir o CSS em cache.
