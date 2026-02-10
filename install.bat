@echo off
REM ATS-Toolkit Windows Installation Script

REM --- Request Admin Privileges ---
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList '%~dp0'"
    exit /b
)

REM --- Navigate to project root ---
cd /d "%~dp0"

echo ========================================
echo  ATS-Toolkit v2.0 Installation
echo ========================================
echo.
echo [INFO] Working directory: %cd%
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.11+
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [INFO] Python version: %PYVER%
echo.

REM ============================================
REM Create virtual environment
REM ============================================
echo [1/5] Creating virtual environment...
if not exist .venv (
    python -m venv .venv
    echo [INFO] Virtual environment created in .venv
) else (
    echo [INFO] Virtual environment already exists
)

REM Activate venv
call .venv\Scripts\activate.bat
echo [INFO] Virtual environment activated
echo.

REM ============================================
REM Install dependencies
REM ============================================
echo [2/5] Installing dependencies...

REM Upgrade pip first
python -m pip install --upgrade pip --quiet

REM Check if Poetry is available globally or install in venv
poetry --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing Poetry in virtual environment...
    pip install poetry --quiet
)

REM Install project dependencies with Poetry
poetry install --no-interaction 2>nul
if errorlevel 1 (
    echo [INFO] Poetry install failed, falling back to pip...
    pip install fastapi uvicorn[standard] pydantic python-dotenv aiohttp httpx dnspython structlog pyyaml pandas sqlalchemy cryptography textual rich streamlit redis --quiet
    echo [INFO] Dependencies installed via pip
)
echo.

REM ============================================
REM Create configuration
REM ============================================
echo [3/5] Creating configuration...
if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo [INFO] Created .env from template
    ) else (
        echo [WARN] No .env.example found, creating minimal .env
        (
            echo ATS_ENV=production
            echo ATS_LOG_LEVEL=INFO
            echo ATS_THREADS=50
            echo ATS_TIMEOUT=60
        ) > .env
    )
) else (
    echo [INFO] .env already exists
)
echo.

REM ============================================
REM Create directories
REM ============================================
echo [4/5] Creating directories...
if not exist logs mkdir logs
if not exist config mkdir config
if not exist data mkdir data
echo [INFO] Directories ready
echo.

REM ============================================
REM Verify installation
REM ============================================
echo [5/5] Verifying installation...
python -c "import sys; sys.path.insert(0,'.'); from src.core.base_module import AtsModule; print('[OK] Core engine')" 2>nul
if errorlevel 1 (
    echo [WARN] Core import check failed - dependencies may still be installing
)

python -c "import structlog; print('[OK] structlog')" 2>nul
python -c "import fastapi; print('[OK] FastAPI')" 2>nul
python -c "import textual; print('[OK] Textual')" 2>nul
python -c "import aiohttp; print('[OK] aiohttp')" 2>nul

echo.
echo ========================================
echo  Installation Complete!
echo ========================================
echo.
echo To activate the virtual environment:
echo   .venv\Scripts\activate
echo.
echo Usage (with venv activated):
echo   python main.py --help     Show help
echo   python main.py --api      Start API server
echo   python main.py --tui      Start TUI interface
echo   python main.py --web      Start Streamlit Web UI
echo   python main.py list       List all modules
echo.
pause
