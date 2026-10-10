# Instalação por usuário, sem Docker por padrão. Python 3.11+ necessário.
param([switch]$SkipSetup, [switch]$SkipDocker, [switch]$WithDocker,
      [switch]$Update, [switch]$Uninstall, [switch]$Repair, [switch]$Rollback)
$ErrorActionPreference = 'Stop'
foreach ($argument in $args) {
    switch -Exact ($argument) {
        '--update' { $Update = $true }
        '--uninstall' { $Uninstall = $true }
        '--repair' { $Repair = $true }
        '--rollback' { $Rollback = $true }
        '--skip-setup' { $SkipSetup = $true }
        '--skip-docker' { $SkipDocker = $true }
        '--with-docker' { $WithDocker = $true }
        default { throw "Unknown argument: $argument" }
    }
}
$pythonCommand = $null
foreach ($candidate in @('python', 'python3', 'py')) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        & $candidate -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) { $pythonCommand = $candidate; break }
    }
}
if (-not $pythonCommand) { throw 'Instale Python 3.11 ou superior e execute este instalador novamente.' }
$installArguments = @((Join-Path $PSScriptRoot 'sisifo\installation.py'), '--source', $PSScriptRoot)
if ($Update) { $installArguments += '--update' }
if ($Uninstall) { $installArguments += '--uninstall' }
if ($Repair) { $installArguments += '--repair' }
if ($Rollback) { $installArguments += '--rollback' }
& $pythonCommand @installArguments
if ($LASTEXITCODE -ne 0) { throw 'Instalação não concluída; a versão anterior não foi removida.' }
$installRoot = if ($env:SISIFO_INSTALL_DIR) { $env:SISIFO_INSTALL_DIR } else { Join-Path $env:APPDATA 'sisifo' }
$binDir = Join-Path $installRoot 'bin'
$env:Path = $binDir + ';' + $env:Path
if ($WithDocker -and -not $SkipDocker -and -not $Uninstall) {
    Push-Location $PSScriptRoot
    try {
        docker compose build sisifo nmap
        if ($LASTEXITCODE -ne 0) { throw 'Docker indisponível ou build falhou. A instalação nativa continua utilizável.' }
        docker compose pull nikto
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao obter Nikto. A instalação nativa continua utilizável.' }
    } finally { Pop-Location }
}
Write-Host 'Use sisifo para abrir o menu; sisifo setup para configurar; sisifo web para a interface local.'
