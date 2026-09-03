@echo off
rem SOC-PROJECT launcher. Avoids typing the entry-point filename, which chat
rem clients tend to rewrite into a link. Usage:
rem   run.cmd            full pipeline, then the dashboard on port 8080
rem   run.cmd serve      dashboard only
rem   run.cmd test       unit tests
rem   run.cmd stats      detection coverage and idle rules
rem any other arguments are forwarded to the CLI unchanged
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo [!] Python is not on PATH. Install it, or use: py -3 -m pip install -r requirements.txt
  exit /b 1
)
if "%~1"=="" (
  python soc.py run
  echo.
  echo [.] opening the dashboard on http://localhost:8080 - press Ctrl-C to stop
  python soc.py serve --port 8080
  exit /b %errorlevel%
)
if /i "%~1"=="test" (
  python -m unittest discover -s tests -v
  exit /b %errorlevel%
)
python soc.py %*
