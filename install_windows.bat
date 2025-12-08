@echo off
REM React2Shell Vulnerability Checker - Windows Installation Script

echo Installing React2Shell Vulnerability Checker for Windows...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed. Please install Python 3 from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if pip is installed
pip --version >nul 2>&1
if errorlevel 1 (
    echo pip is not installed. Please ensure Python was installed with pip.
    pause
    exit /b 1
)

REM Install dependencies
echo Installing required dependencies...
pip install -r requirements.txt

echo Installation completed!
echo.
echo To run the checker, use:
echo   python react2shell_checker_windows.py --path C:\path\to\your\project
echo   python react2shell_checker_windows.py --url https://your-site.example

pause