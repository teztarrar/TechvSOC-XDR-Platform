@echo off
setlocal

set CC=cl.exe
set RC=rc.exe
set OUT=EventForwardingAggregator.exe
set RCFILE=resource.rc
set ICO=app.ico
set RES=resource.res

REM All source files
set SRCS=event_forwarder.c http_client.c json_builder.c metrics.c log_reader.c

REM Libraries
set LIBS=wevtapi.lib ws2_32.lib winhttp.lib iphlpapi.lib comctl32.lib user32.lib gdi32.lib advapi32.lib shell32.lib

echo ========================================
echo  TechvSOC XDR Native Agent - Build v2
echo  TechvSOC XDR Platform
echo ========================================
echo.

where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: cl.exe not found.
    echo Run from Visual Studio Developer Command Prompt:
    echo   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    echo.
    pause
    exit /b 1
)

set HAS_RES=0
if exist "%ICO%" (
    echo [INFO] Compiling resource file...
    rc.exe /fo "%RES%" "%RCFILE%"
    if %ERRORLEVEL% EQU 0 ( set HAS_RES=1 ) else ( echo [WARN] Resource compile failed. )
) else (
    echo [INFO] No icon found - using default shield icon.
)

echo.
echo Compiling %OUT% ...
echo Sources: %SRCS%
echo.

if "%HAS_RES%"=="1" (
    cl.exe /W4 /O2 /D "NDEBUG" /D "_WINDOWS" /D "UNICODE" /D "_UNICODE" ^
        /Fe:%OUT% %SRCS% %RES% %LIBS% /link /SUBSYSTEM:WINDOWS
) else (
    cl.exe /W4 /O2 /D "NDEBUG" /D "_WINDOWS" /D "UNICODE" /D "_UNICODE" ^
        /Fe:%OUT% %SRCS% %LIBS% /link /SUBSYSTEM:WINDOWS
)

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo  Build successful: %OUT%
    echo ========================================
    echo.
    echo Before first run:
    echo   1. Edit event_forwarder.ini
    echo   2. Set [backend] url and token
    echo   3. Copy event_forwarder.ini to same directory as %OUT%
    echo.
) else (
    echo.
    echo Build FAILED. Check errors above.
)

pause
endlocal
