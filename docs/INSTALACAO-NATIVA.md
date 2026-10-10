# Instalação nativa e recuperação

Instale Python 3.11 ou superior. No Linux, instale também o suporte `venv` da distribuição. Docker e TShark são opcionais para iniciar o menu e a web; ferramentas específicas continuam exigindo suas dependências.

Windows, na pasta do código:

```powershell
.\install.ps1
sisifo
```

Linux:

```sh
bash install.sh
# Abra um novo terminal
sisifo
```

O instalador PowerShell atualiza o PATH do processo em que foi executado e o PATH do usuário. Outros terminais já abertos precisam ser reabertos. Um instalador Bash não consegue alterar o ambiente do shell pai: abra outro terminal. Nenhum instalador deve prometer que todos os terminais existentes recebem o PATH imediatamente.

O pacote é instalado normalmente (não editável), com web incluída, em um ambiente privado por versão. O launcher usa diretamente esse Python; não é necessário ativar `.venv` nem permanecer na pasta do código. Configuração é explícita: `sisifo setup` e `sisifo setup-web`.

## Atualizar, reparar e recuperar

- Windows: `./install.ps1 --update`; Linux: `bash install.sh --update`.
- Use o código local atualizado. O instalador não faz git pull/reset.
- Nova versão é instalada e passa por smoke de CLI/web antes de substituir o launcher. Falha de pip/venv/smoke preserva a versão ativa.
- `sisifo repair` recria launcher e PATH. `sisifo repair --rollback` seleciona o ambiente anterior disponível.
- Se o próprio comando não abrir: execute `./install.ps1 --repair` ou `bash install.sh --repair`. Python privado ausente exige reinstalação completa; repair não baixa dependências silenciosamente.
- `--rollback` também funciona nos instaladores. Versões antigas e tentativas interrompidas permanecem para recuperação; limpeza automática não implementada.
- `--uninstall` remove os launchers, preservando ambientes, manifest, dados e credenciais. O diretório no PATH permanece disponível para reparo.

Windows: `%APPDATA%\sisifo\bin`; Linux: `${XDG_DATA_HOME:-$HOME/.local/share}/sisifo/bin`. `SISIFO_INSTALL_DIR` permite raiz alternativa, especialmente para testes.

Instalações novas usam os padrões de dados/configuração do aplicativo. Se houver dados ou configuração legados na pasta do código na primeira instalação, seus caminhos são preservados no manifest para não abandonar sessões/credenciais. Não remova essa pasta de dados sem migração explícita. `SISIFO_DATA_DIR` e `SISIFO_CONFIG_DIR` têm precedência. O manifest guarda caminhos, nunca chaves.

## Docker opcional

Por padrão não há build/pull de Docker durante instalação. `--with-docker` solicita preparo das imagens no repositório; `--skip-docker` continua aceito. Falha nessa etapa não desfaz a instalação nativa. `sisifo doctor` informa quando Docker não está disponível; os comandos de scan continuam exigindo as ferramentas correspondentes.

Não existe garantia de nunca quebrar: remoção manual de runtime, PATH sobrescrito ou dependências do sistema podem exigir repair/reinstalação. O objetivo é detectar e recuperar, preservar dados e testar antes de ativar.
