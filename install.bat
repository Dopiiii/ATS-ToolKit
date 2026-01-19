@echo off
REM ATS-Toolkit Windows Installation Script
REM Requires Python 3.11+ and Poetry

echo.
echo ========================================
echo  ATS-Toolkit v2.0 Installation
echo ========================================
echo.

REM Check Python version
python --version 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.11+
    pause
    exit /b 1
)

REM Check Poetry
poetry --version 2>nul
if errorlevel 1 (
    echo [INFO] Poetry not found. Installing...
    pip install poetry
)

echo.
echo [1/4] Installing dependencies...
poetry install

echo.
echo [2/4] Creating configuration...
if not exist .env (
    copy .env.example .env
    echo [INFO] Created .env from template
) else (
    echo [INFO] .env already exists
)

echo.
echo [3/4] Creating directories...
if not exist logs mkdir logs
if not exist config mkdir config

echo.
echo [4/4] Verifying installation...
python -c "from src.core import AtsModule; print('Core OK')"
if errorlevel 1 (
    echo [ERROR] Installation verification failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo  Installation Complete!
echo ========================================
echo.
echo Usage:
echo   python main.py --api     Start API server
echo   python main.py --tui     Start TUI (Phase 1)
echo   python main.py list      List modules
echo.
pause
