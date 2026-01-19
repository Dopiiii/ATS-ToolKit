@echo off
REM ATS-Toolkit Windows Installation Script
echo ========================================
echo  ATS-Toolkit v2.0 Installation
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.11+
    pause
    exit /b 1
)

echo [INFO] Python found
echo.

REM Check Poetry
poetry --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Poetry not found. Installing...
    pip install poetry
)

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
python -c "from src.core import base_module; print('Core OK')"

echo.
echo ========================================
echo  Installation Complete!
echo ========================================
echo.
echo Usage:
echo   python main.py --api     Start API server
echo   python main.py --tui     Start TUI
echo   python main.py list      List modules
echo.
pause
