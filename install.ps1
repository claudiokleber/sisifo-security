<#
.SYNOPSIS
    Instala o Sísifo no perfil do usuário (sem admin).
.DESCRIPTION
    Cria um ambiente virtual isolado em $env:APPDATA\sisifo\venv,
    instala o pacote em modo editável, cria um wrapper `sisifo.bat`
    em $env:APPDATA\sisifo\bin e adiciona esse diretório ao PATH do usuário.
    Também prepara as imagens Docker necessárias e executa o diagnóstico.
.PARAMETER SkipSetup
    Pula a configuração interativa (IA e senha web).
.PARAMETER Uninstall
    Remove a instalação do usuário (mantém dados e credenciais).
.PARAMETER Update
    Atualiza a instalação existente para a versão atual do repositório.
.PARAMETER SkipDocker
    Pula build/pull de imagens Docker e diagnóstico.
#>
param(
    [switch]$SkipSetup,
    [switch]$SkipDocker,
    [switch]$Uninstall,
    [switch]$Update
)

$ErrorActionPreference = 'Stop'
foreach ($argument in $args) {
    switch -Exact ($argument) {
        '--update' { $Update = $true }
        '--uninstall' { $Uninstall = $true }
        '--skip-setup' { $SkipSetup = $true }
        '--skip-docker' { $SkipDocker = $true }
        default { throw "Unknown argument: $argument" }
    }
}
$scriptRoot = $PSScriptRoot
Push-Location $scriptRoot

try {
    $appData = $env:APPDATA
    if (-not $appData) { throw 'Variável APPDATA não definida.' }
    $installDir = Join-Path $appData 'sisifo'
    $venvDir = Join-Path $installDir 'venv'
    $binDir = Join-Path $installDir 'bin'
    $wrapper = Join-Path $binDir 'sisifo.bat'
    $pythonExe = Join-Path $venvDir 'Scripts\python.exe'
    $pipExe = Join-Path $venvDir 'Scripts\pip.exe'

    function Ensure-PathInUserPath($path) {
        $userPath = [Environment]::GetEnvironmentVariable('Path','User')
        if (-not $userPath) { $userPath = '' }
        $entries = $userPath -split ';' | Where-Object { $_ }
        $normalized = $path.TrimEnd('\')
        if ($entries -contains $normalized) {
            if (($env:Path -split ';') -notcontains $normalized) { $env:Path = $normalized + ';' + $env:Path }
            return
        }
        $newPath = ($entries + @($normalized)) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        $env:Path = $normalized + ';' + $env:Path
        Write-Host "Adicionado ao PATH do usuário: $path"
        Write-Host 'Abra um novo terminal para que a alteração tenha efeito.'
    }

    function Remove-PathFromUserPath($path) {
        $userPath = [Environment]::GetEnvironmentVariable('Path','User')
        if (-not $userPath) { return }
        $entries = $userPath -split ';' | Where-Object { $_ }
        $normalized = $path.TrimEnd('\')
        $filtered = $entries | Where-Object { $_ -ne $normalized }
        if ($filtered.Count -eq $entries.Count) { return }
        $newPath = $filtered -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "Removido do PATH do usuário: $path"
    }

    # Detect conflicting sisifo executable in PATH (outside our binDir)
    $existing = Get-Command sisifo -ErrorAction SilentlyContinue
    if ($existing -and $existing.Source -ne 'Application') {
        Write-Warning "Outro executável 'sisifo' encontrado em $($existing.Path). A instalação continuará, mas o wrapper terá prioridade se seu diretório estiver antes no PATH."
    }

    if ($Uninstall -and $Update) { throw 'Choose either Update or Uninstall.' }
    if ($Update) { Write-Host 'Updating from current local source; no git pull or reset.' }
    if ($Uninstall) {
        Write-Host 'Removendo instalação do usuário...'
        Remove-PathFromUserPath $binDir
        foreach ($target in @($venvDir, $binDir)) {
            $resolved = [IO.Path]::GetFullPath($target)
            $expected = [IO.Path]::GetFullPath($installDir).TrimEnd('\') + '\'
            if (-not $resolved.StartsWith($expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe removal path.' }
            if (Test-Path -LiteralPath $resolved) {
                if ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove linked directory.' }
                Remove-Item -LiteralPath $resolved -Recurse -Force
            }
        }
        Write-Host 'Instalação removida. Dados em .sisifo-config e volumes Docker preservados.'
        return
    }

    # Criar diretórios
    New-Item -ItemType Directory -Force -Path $venvDir | Out-Null
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null

    # Criar/atualizar venv
    if (-not (Test-Path $pythonExe)) {
        Write-Host 'Criando ambiente virtual...'
        & python -m venv $venvDir
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar venv.' }
    } else {
        Write-Host 'Ambiente virtual já existe.'
    }

    # Atualizar pip/setuptools
    & $pythonExe -m pip install --upgrade pip setuptools wheel
    if ($LASTEXITCODE -ne 0) { throw "Failed to update packaging tools." }

    # Instalar pacote em modo editável (inclui dependências web)
    Write-Host 'Instalando Sísifo (modo editável)...'
    & $pythonExe -m pip install -e "${scriptRoot}[dev,web]"
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao instalar pacote.' }

    # Criar wrapper sisifo.bat (propaga args e exit code)
    $wrapperContent = @"
@echo off
setlocal
if not defined SISIFO_CONFIG_DIR set "SISIFO_CONFIG_DIR=$scriptRoot\.sisifo-config"
if not defined SISIFO_DATA_DIR set "SISIFO_DATA_DIR=$scriptRoot\data"
"$pythonExe" -m sisifo.cli.main %*
exit /b %errorlevel%
"@
    [IO.File]::WriteAllText($wrapper, $wrapperContent, [System.Text.UTF8Encoding]::new($false))

    # Adicionar binDir ao PATH do usuário
    Ensure-PathInUserPath $binDir

    if (-not $SkipDocker) {
        # Preparar imagens Docker
        Write-Host 'Construindo/obtendo imagens Docker...'
        docker compose build sisifo nmap
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao construir imagens.' }
        docker compose pull nikto
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao obter Nikto.' }

        # Diagnóstico
        Write-Host 'Executando diagnóstico...'
        docker compose run --rm sisifo doctor
        if ($LASTEXITCODE -ne 0) { throw 'Diagnóstico falhou.' }
    }

    if (-not $SkipSetup) {
        Write-Host 'Iniciando configuração interativa...'
        & $wrapper setup
        if ($LASTEXITCODE -ne 0) { throw 'Configuração não concluída.' }
        & $wrapper setup-web
        if ($LASTEXITCODE -ne 0) { throw 'Configuração da senha web não concluída.' }
    }

    Write-Host ''
    Write-Host '✅ Instalação concluída.'
    Write-Host "Comando disponível: sisifo (abra um novo terminal)."
    Write-Host "Dados: $scriptRoot\data (ou SISIFO_DATA_DIR)"
    Write-Host "Config: $scriptRoot\.sisifo-config (ou SISIFO_CONFIG_DIR)"
}
finally {
    Pop-Location
}