# Identidade visual do Sísifo

Originais fornecidos pelo usuário em `C:\Users\ck\Downloads\files` (a pasta `brand-src/` citada na tarefa não estava presente). As cópias de runtime ficam em `sisifo/web/static/branding/`; esta pasta serve à documentação versionada. Não há fontes ou imagens carregadas de CDNs.

| Arquivo | Uso |
|---|---|
| `sisifo-logo.svg` | Logo completa em fundo preto: README, login e visão geral no tema escuro |
| `sisifo-logo-light.svg` | Logo completa em fundo branco: mesmas superfícies no tema claro |
| `sisifo-logo.png` | Logo PNG original e fonte da imagem social |
| `sisifo-logo-light.png` | Alternativa PNG para fundo claro |
| `sisifo-icon.svg` | Favicon principal, fundo preto |
| `sisifo-icon-light.svg` | Favicon claro e cabeçalho claro |
| `sisifo-icon-512.png` | Fonte dos ícones raster derivados |
| `sisifo-mark.svg` | Símbolo branco transparente: cabeçalho, carregamento e estados vazios escuros |
| `favicon.ico` | Compatibilidade: imagens de 16, 32 e 48 px |
| `apple-touch-icon.png` | Atalho Apple, 180 × 180 px |
| `og-image.png` | Open Graph/Twitter, 1200 × 630 px, logo centralizada em preto |

O módulo `sisifo/branding.py` adapta o `branding.py` fornecido: banner, painel, menu/prompt, seção, mensagens, spinner e progresso. Usa somente biblioteca padrão, consulta capacidades na hora da saída, lê a versão do pacote e não altera stdout ao importar. Demonstração: `python -m sisifo.branding`.

## Paleta e uso

- Preto `#000000`; branco `#FFFFFF`.
- Cinza do cubo `#8E8E8E`; cinza do slogan `#6B6B6B`.
- Vermelho `#FF2A2A`: face do cubo, cursor, foco e indicação de erro; não usar como fundo de áreas ou botões.
- Não recolorir nem distorcer os arquivos originais. Manter espaço livre equivalente à largura dos colchetes ao redor da logo. Ícone: mínimo 16 px.
- O símbolo transparente tem traços brancos: nunca usar em fundo claro. Usar o ícone `-light` nesses casos.
- Logos seguem `prefers-color-scheme`, pois não existe seletor manual de tema. O movimento é desativado por `prefers-reduced-motion`.
- Texto comum usa branco/preto e cinzas com contraste AA. Em tema claro, erros têm texto preto com marcador vermelho para evitar texto vermelho pequeno sobre branco. O conteúdo textual não depende apenas de cor para indicar estado.

## Decisões de integração

Não existe manifesto/PWA, por isso não foi criado um manifesto nem um ícone PWA adicional de 192 px. O ícone original de 512 px permanece disponível. Os metadados sociais têm URL absoluta calculada pelo servidor; serviços externos não conseguem acessar uma aplicação restrita a localhost.

Os derivados raster foram gerados com ferramentas locais de desenvolvimento, sem adicionar dependências ao projeto. Originais e metadados foram preservados. O spinner só atua em saída interativa e não escreve ANSI em stdout redirecionado, relatórios ou evidências. Falhas não emitem mensagem de sucesso no spinner.
