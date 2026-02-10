@echo off
REM ============================================
REM ATS-Toolkit v2.0 - Launcher
REM Requires: Python 3.11+, Virtual Environment
REM ============================================

REM --- Request Admin Privileges ---
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList '%~dp0'"
    exit /b
)

REM --- Navigate to project root ---
cd /d "%~dp0"

title ATS-Toolkit v2.0

REM --- Check if venv exists and dependencies are installed ---
if not exist .venv\Scripts\activate.bat (
    echo [!] Virtual environment not found.
    echo [!] Running install.bat first...
    echo.
    call "%~dp0install.bat"
    if not exist .venv\Scripts\activate.bat (
        echo [ERROR] Installation failed. Please check errors above.
        pause
        exit /b 1
    )
)

REM --- Activate venv ---
call .venv\Scripts\activate.bat

REM --- Quick dependency check ---
python -c "import structlog; import fastapi; import textual" >nul 2>&1
if errorlevel 1 (
    echo [!] Dependencies missing. Running install.bat...
    echo.
    call "%~dp0install.bat"
    call .venv\Scripts\activate.bat
)

REM --- Ensure .env exists ---
if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
    )
)

:MENU
cls
echo.
echo  ================================================================
echo  #                                                              #
echo  #              ATS-TOOLKIT v2.0 - Cybersecurity                #
echo  #              Modular Security Framework                      #
echo  #                                                              #
echo  ================================================================
echo.
echo   [1]  TUI Interface        (Terminal UI - Textual)
echo   [2]  Web Interface         (Streamlit - Port 8501)
echo   [3]  API Server            (FastAPI  - Port 8000)
echo   [4]  API + Web UI          (Both servers)
echo   [5]  CLI - List Modules
echo   [6]  CLI - Run Module
echo   [7]  Settings              (Edit .env)
echo   [8]  Reinstall / Update
echo   [0]  Quit
echo.
echo  ================================================================
echo.

set /p CHOICE="  Select an option [0-8]: "

if "%CHOICE%"=="1" goto TUI
if "%CHOICE%"=="2" goto WEB
if "%CHOICE%"=="3" goto API
if "%CHOICE%"=="4" goto BOTH
if "%CHOICE%"=="5" goto LIST
if "%CHOICE%"=="6" goto RUN
if "%CHOICE%"=="7" goto SETTINGS
if "%CHOICE%"=="8" goto REINSTALL
if "%CHOICE%"=="0" goto QUIT

echo  [!] Invalid option. Try again.
timeout /t 2 >nul
goto MENU

:TUI
cls
echo.
echo  Starting TUI Interface...
echo  (Press Ctrl+Q to quit)
echo.
python main.py --tui
if errorlevel 1 (
    echo.
    echo  [!] TUI failed to start. Check errors above.
    pause
)
goto MENU

:WEB
cls
echo.
echo  Starting Streamlit Web Interface...
echo  URL: http://localhost:8501
echo  (Press Ctrl+C to stop)
echo.
start "" http://localhost:8501
python main.py --web
goto MENU

:API
cls
echo.
echo  Starting FastAPI Server...
echo  API:     http://localhost:8000
echo  Docs:    http://localhost:8000/docs
echo  (Press Ctrl+C to stop)
echo.
start "" http://localhost:8000/docs
python main.py --api --host 0.0.0.0 --port 8000
goto MENU

:BOTH
cls
echo.
echo  Starting API + Web UI...
echo  API:     http://localhost:8000
echo  Web UI:  http://localhost:8501
echo.
start "ATS-API" cmd /k "cd /d "%~dp0" && .venv\Scripts\activate && python main.py --api --host 0.0.0.0 --port 8000"
timeout /t 3 >nul
start "" http://localhost:8501
start "" http://localhost:8000/docs
python main.py --web
goto MENU

:LIST
cls
echo.
echo  Available Modules:
echo  ==================
echo.
python main.py list
echo.
pause
goto MENU

:RUN
cls
echo.
echo  Run a Module
echo  ============
echo.
python main.py list 2>nul
echo.
set /p MODULE_NAME="  Module name: "
if "%MODULE_NAME%"=="" goto MENU
set /p MODULE_CONFIG="  Config (key=value key=value): "
echo.
if "%MODULE_CONFIG%"=="" (
    python main.py run %MODULE_NAME%
) else (
    python main.py run %MODULE_NAME% --config %MODULE_CONFIG%
)
echo.
pause
goto MENU

:SETTINGS
cls
echo.
echo  Opening .env configuration...
echo.
if exist .env (
    notepad .env
) else (
    echo  [!] No .env file found.
    if exist .env.example (
        copy .env.example .env >nul
        echo  [INFO] Created .env from template. Opening...
        notepad .env
    )
)
goto MENU

:REINSTALL
cls
echo.
echo  Reinstalling / Updating...
echo.
call "%~dp0install.bat"
echo.
echo  Done!
pause
goto MENU

:QUIT
cls
echo.
echo  ATS-Toolkit stopped. Goodbye!
echo.
deactivate >nul 2>&1
exit /b 0
