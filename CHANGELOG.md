# Changelog

## Não lançado

- Nova identidade visual: branding da CLI, painel e progresso compatíveis com TTY/ASCII/NO_COLOR; logos e ícones locais, tema automático claro/escuro, metadados sociais e respeito a movimento reduzido na web.

## 0.2.1 — 2026-10-03

- Imported session comparisons now require explicit compatible coverage. Service attribute changes have a stable identity and a separate `changed` result.
- Reports and AI validate evidence presence, counts, references and hashes. Original observation and import timestamps are separate; unsupported schema versions are rejected.
- Running tools are persisted before launch, including image ID, network and container ID. Exclusive writer locks and explicit orphan recovery preserve interrupted work without restarting scans.
- Markdown output renders untrusted tool/model content as literal text.
- Metasploit HTTP identification is an optional experimental adapter with DNS resolution recorded and parser validation. Basic diagnostics no longer require it.
- NVIDIA API integration, hidden-key terminal setup, Windows/Linux Docker installers and local credential isolation. Ollama and offline export remain supported.
- AI analysis processes bounded batches with structured evidence, validates declared batch coverage and references, saves partial results and reports truncation/omissions. HTTP retries and response sizes are bounded; credentials cannot follow redirects or reach a custom NVIDIA endpoint.
- Base/tool images pinned by digest, local Git baseline and Windows/Linux CI configuration. Installation documentation updated in English and Portuguese.

AI output still requires human review. Hashes stored beside artifacts detect inconsistency, not authenticity. Runtime compatibility is limited to the environments actually tested; CI configuration alone is not an executed CI run.
