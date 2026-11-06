@echo off
rem Сборка SMBCheck.exe (окно) и SMBCheck-cli.exe (для Планировщика заданий)
chcp 65001 >nul
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo Python не найден. Установите Python 3.11+ с python.org, отметив "Add python.exe to PATH".
  pause
  exit /b 1
)

python -m pip install --upgrade pip pyinstaller pytest certifi || goto :err
python -m pytest -q || goto :err

python -m PyInstaller --noconfirm --clean --onefile --windowed --collect-data certifi --name SMBCheck app.py || goto :err
python -m PyInstaller --noconfirm --onefile --console --collect-data certifi --name SMBCheck-cli app.py || goto :err

echo.
echo Готово: dist\SMBCheck.exe и dist\SMBCheck-cli.exe
explorer dist
exit /b 0

:err
echo.
echo Сборка не удалась, смотрите сообщения выше.
pause
exit /b 1
