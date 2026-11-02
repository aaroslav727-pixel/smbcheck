"""Точка входа: двойной клик (или SMBCheck.exe) открывает окно; с аргументами — командная строка."""
import sys

from smbcheck.cli import main

if __name__ == "__main__":
    sys.exit(main())
