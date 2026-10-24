# Start the private fake-tool MVP with the pinned 7B GPU model.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo
$inference = Join-Path $repo 'artifacts/local-inference'
$runtime = Join-Path $inference 'runtime/llama-server.exe'
$model = Join-Path $inference 'qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf'
if (!(Test-Path $runtime) -or !(Test-Path $model)) {
    throw 'First run: uv run python -m training.acquire_gguf'
}
foreach ($port in @(8081, 8000)) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        throw "Port $port is already in use. Reuse the running service or stop it first."
    }
}
$keyPath = Join-Path $inference 'local-api.key'
if (!(Test-Path $keyPath)) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    [IO.File]::WriteAllText($keyPath, [Convert]::ToBase64String($bytes))
}
$env:MECHA_LOCAL_KEY = [IO.File]::ReadAllText($keyPath).Trim()
$modelProcess = Start-Process -FilePath $runtime -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
    -ArgumentList @('-m', "`"$model`"", '--alias', 'Qwen2.5-7B-Instruct', '--host', '127.0.0.1',
        '--port', '8081', '-ngl', '99', '-c', '4096', '-np', '1', '-t', '6', '--no-ui',
        '--api-key-file', "`"$keyPath`"", '--cors-origins', 'http://127.0.0.1:8000',
        '--no-cors-credentials', '--timeout', '120') `
    -RedirectStandardOutput (Join-Path $inference 'server.stdout.log') `
    -RedirectStandardError (Join-Path $inference 'server.stderr.log')
$ready = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    if ($modelProcess.HasExited) { throw 'Model server exited. Inspect artifacts/local-inference/server.stderr.log.' }
    try {
        $health = Invoke-RestMethod 'http://127.0.0.1:8081/health' -TimeoutSec 2
        if ($health.status -eq 'ok') { $ready = $true; break }
    } catch { Start-Sleep -Seconds 1 }
}
if (!$ready) { Stop-Process -Id $modelProcess.Id; throw 'Model startup timed out.' }
$uv = Join-Path $repo '.venv/Scripts/uv.exe'
if (!(Test-Path $uv)) { $uv = (Get-Command uv -ErrorAction Stop).Source }
$gateway = Start-Process -FilePath $uv -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
    -ArgumentList @('run', '--no-sync', '--env-file', '.env.mvp.example', 'python', '-m',
        'uvicorn', 'packages.gateway.app:app', '--host', '127.0.0.1', '--port', '8000', '--workers', '1') `
    -RedirectStandardOutput (Join-Path $inference 'gateway.stdout.log') `
    -RedirectStandardError (Join-Path $inference 'gateway.stderr.log')
@{ model_pid = $modelProcess.Id; gateway_launcher_pid = $gateway.Id } |
    ConvertTo-Json | Set-Content (Join-Path $inference 'processes.json')
Write-Output 'Model ready. Console starting at http://127.0.0.1:8000; demo key: fake-local-demo-key'
