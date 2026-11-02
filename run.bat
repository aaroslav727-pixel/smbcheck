@echo off
rem Запуск без сборки .exe (нужен установленный Python 3.11+)
cd /d "%~dp0"
start "" pythonw app.py
