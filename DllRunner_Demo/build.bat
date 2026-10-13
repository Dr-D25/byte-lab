@echo off
setlocal

cl /nologo /LD /MT /O2 /W3 mydll.c ^
   /link /DEF:mydll.def /OUT:mydll.dll

if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === Exports ===
dumpbin /exports mydll.dll | findstr /R "^ *[0-9]"
echo.
echo BUILD OK: mydll.dll