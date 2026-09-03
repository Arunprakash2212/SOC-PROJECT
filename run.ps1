# SOC-PROJECT launcher. Usage: .\run.ps1 [stage] [flags]
#   no arguments -> full pipeline, then the dashboard on port 8080
#   test         -> unit tests ; anything else is forwarded to the CLI.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) {
  Write-Host '[!] Python is not on PATH. Install it, or run: py -3 -m pip install -r requirements.txt' -ForegroundColor Red
  exit 1
}
if (-not $Rest) {
  & $py soc.py run
  Write-Host ''
  Write-Host '[.] opening the dashboard on http://localhost:8080 - press Ctrl-C to stop' -ForegroundColor Cyan
  & $py soc.py serve --port 8080
  exit $LASTEXITCODE
}
if ($Rest[0] -eq 'test') { & $py -m unittest discover -s tests -v; exit $LASTEXITCODE }
& $py soc.py @Rest
exit $LASTEXITCODE
